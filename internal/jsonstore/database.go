package jsonstore

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// Database contains the mechanics shared by MilterGuard's small,
// complete-file JSON stores. Domain-specific code supplies record identity,
// expiry, eviction and ordering policies.
type Database[K comparable, V any] struct {
	Mu              sync.RWMutex
	name            string
	path            string
	version         int
	maxEntries      int
	readLimit       int64
	Records         map[K]V
	key             func(V) K
	expired         func(V, time.Time) bool
	Maintain        func(V, time.Time) (V, bool, bool)
	evictLess       func(V, V) bool
	sortLess        func(V, V) bool
	PrepareForWrite func(V) V
	AfterWrite      func(map[K]V)
	OnEvict         func(K, V)
	CloneValue      func(V) V
	Now             func() time.Time
	log             *slog.Logger
	DeferWrites     bool
	Dirty           bool
	reads           uint64
	writes          uint64
	expiredRemoved  uint64
}

type jsonDatabaseFile[V any] struct {
	Version int `json:"version"`
	Entries []V `json:"entries"`
}

type Stats struct {
	Name           string
	Reads          uint64
	Writes         uint64
	ExpiredRemoved uint64
	Flushed        bool
}

func New[K comparable, V any](name, path string, version, maxEntries int, readLimit int64, key func(V) K, expired func(V, time.Time) bool, evictLess, sortLess func(V, V) bool, log *slog.Logger) *Database[K, V] {
	return &Database[K, V]{name: name, path: path, version: version, maxEntries: maxEntries, readLimit: readLimit, Records: make(map[K]V), key: key, expired: expired, evictLess: evictLess, sortLess: sortLess, Now: time.Now, log: log}
}

func (d *Database[K, V]) Load(acceptedVersion func(int) bool, normalize func(V) (V, bool, bool)) (bool, error) {
	d.Mu.Lock()
	defer d.Mu.Unlock()
	var file jsonDatabaseFile[V]
	if err := readFile(d.path, d.readLimit, &file); err != nil {
		return false, err
	}
	if !acceptedVersion(file.Version) {
		return false, fmt.Errorf("unsupported %s version %d", d.name, file.Version)
	}
	changed := file.Version != d.version
	now := d.Now().UTC()
	for _, value := range file.Entries {
		value, keep, modified := normalize(value)
		changed = changed || modified
		if !keep || d.isExpired(value, now) {
			changed = true
			d.expiredRemoved++
			continue
		}
		d.Records[d.key(value)] = value
	}
	for len(d.Records) > d.maxEntries {
		d.EvictOneLocked()
		changed = true
	}
	if changed {
		d.Dirty = true
	}
	return changed, nil
}

func (d *Database[K, V]) Get(key K) (V, bool) {
	d.Mu.Lock()
	defer d.Mu.Unlock()
	value, ok := d.Records[key]
	if !ok {
		var zero V
		return zero, false
	}
	if d.isExpired(value, d.Now().UTC()) {
		delete(d.Records, key)
		d.Dirty = true
		d.expiredRemoved++
		var zero V
		return zero, false
	}
	d.reads++
	return value, true
}

func (d *Database[K, V]) Put(value V) error {
	key := d.key(value)
	return d.Update(func(records map[K]V) (uint64, uint64, bool) {
		records[key] = value
		return 0, 1, true
	})
}

func (d *Database[K, V]) Delete(key K) (bool, error) {
	deleted := false
	err := d.Update(func(records map[K]V) (uint64, uint64, bool) {
		if _, found := records[key]; !found {
			return 0, 0, false
		}
		delete(records, key)
		deleted = true
		return 0, 1, true
	})
	return deleted, err
}

func (d *Database[K, V]) View(fn func(V) bool) []V {
	d.Mu.Lock()
	defer d.Mu.Unlock()
	now := d.Now().UTC()
	result := make([]V, 0)
	for key, value := range d.Records {
		if d.isExpired(value, now) {
			delete(d.Records, key)
			d.Dirty = true
			d.expiredRemoved++
			continue
		}
		if fn(value) {
			result = append(result, value)
			d.reads++
		}
	}
	return result
}

// update provides one atomic transaction for feature operations that need to
// read and modify several related records.
func (d *Database[K, V]) Update(fn func(map[K]V) (reads, writes uint64, changed bool)) error {
	d.Mu.Lock()
	defer d.Mu.Unlock()
	backup := make(map[K]V, len(d.Records))
	for key, value := range d.Records {
		if d.CloneValue != nil {
			value = d.CloneValue(value)
		}
		backup[key] = value
	}
	reads, writes, changed := fn(d.Records)
	d.reads += reads
	if !changed {
		return nil
	}
	d.writes += writes
	d.Dirty = true
	if len(d.Records) >= d.maxEntries {
		d.RemoveExpiredLocked(d.Now().UTC())
	}
	for len(d.Records) > d.maxEntries {
		d.EvictOneLocked()
	}
	if !d.DeferWrites {
		if _, err := d.FlushLocked("write"); err != nil {
			d.ReplaceLocked(backup)
			return err
		}
	}
	return nil
}

func (d *Database[K, V]) ReplaceLocked(values map[K]V) {
	clear(d.Records)
	for key, value := range values {
		d.Records[key] = value
	}
}

func (d *Database[K, V]) RemoveExpiredLocked(now time.Time) uint64 {
	var removed uint64
	for key, value := range d.Records {
		if d.Maintain != nil {
			updated, keep, changed := d.Maintain(value, now)
			if !keep {
				delete(d.Records, key)
				removed++
				continue
			}
			d.Records[key] = updated
			value = updated
			if changed {
				d.Dirty = true
			}
		}
		if d.isExpired(value, now) {
			delete(d.Records, key)
			removed++
		}
	}
	if removed > 0 {
		d.Dirty = true
		d.expiredRemoved += removed
	}
	return removed
}

func (d *Database[K, V]) MarkWritesLocked(count uint64) {
	d.writes += count
	d.Dirty = true
}

func (d *Database[K, V]) ChangedLocked(writes uint64) error {
	d.MarkWritesLocked(writes)
	if d.DeferWrites {
		return nil
	}
	_, err := d.FlushLocked("write")
	return err
}

func (d *Database[K, V]) MarkReadsLocked(count uint64) { d.reads += count }

func (d *Database[K, V]) isExpired(value V, now time.Time) bool {
	return d.expired != nil && d.expired(value, now)
}

func (d *Database[K, V]) EvictOneLocked() {
	var victim K
	var selected V
	found := false
	for key, value := range d.Records {
		if !found || (d.evictLess != nil && d.evictLess(value, selected)) {
			victim, selected, found = key, value, true
		}
	}
	if found {
		delete(d.Records, victim)
		d.writes++
		if d.OnEvict != nil {
			d.OnEvict(victim, selected)
		}
	}
}

func (d *Database[K, V]) Flush() (Stats, error) {
	d.Mu.Lock()
	defer d.Mu.Unlock()
	return d.FlushLocked("")
}

func (d *Database[K, V]) FlushLocked(trigger string) (Stats, error) {
	d.RemoveExpiredLocked(d.Now().UTC())
	stats := Stats{Name: d.name, Reads: d.reads, Writes: d.writes, ExpiredRemoved: d.expiredRemoved}
	if d.Dirty {
		if err := d.writeLocked(); err != nil {
			return stats, err
		}
		if d.AfterWrite != nil {
			d.AfterWrite(d.Records)
		}
		d.Dirty = false
		stats.Flushed = true
	}
	d.reads, d.writes, d.expiredRemoved = 0, 0, 0
	if trigger != "" && d.log != nil {
		flushed := "no"
		if stats.Flushed {
			flushed = "yes"
		}
		d.log.Debug("JSON stores flushed", "trigger", trigger, "summary", fmt.Sprintf("%s: r %d, w %d, e %d, f %s", stats.Name, stats.Reads, stats.Writes, stats.ExpiredRemoved, flushed))
	}
	return stats, nil
}

func (d *Database[K, V]) writeLocked() error {
	if d.path == "" {
		return nil
	}
	values := make([]V, 0, len(d.Records))
	for _, value := range d.Records {
		if d.PrepareForWrite != nil {
			value = d.PrepareForWrite(value)
		}
		values = append(values, value)
	}
	if d.sortLess != nil {
		sort.Slice(values, func(i, j int) bool { return d.sortLess(values[i], values[j]) })
	}
	return writeFile(d.path, jsonDatabaseFile[V]{Version: d.version, Entries: values}, 0750, 0640)
}

func (d *Database[K, V]) SetDeferred(deferred bool) {
	d.Mu.Lock()
	d.DeferWrites = deferred
	d.Mu.Unlock()
}
func (d *Database[K, V]) Size() int { d.Mu.Lock(); defer d.Mu.Unlock(); return len(d.Records) }

type managedDatabase interface {
	Flush() (Stats, error)
	SetDeferred(bool)
}

type Manager struct {
	log    *slog.Logger
	stores []managedDatabase
}

func NewManager(log *slog.Logger) *Manager { return &Manager{log: log} }

func (m *Manager) Add(stores ...managedDatabase) {
	m.stores = append(m.stores, stores...)
}
func (m *Manager) SetDeferred(value bool) {
	for _, store := range m.stores {
		store.SetDeferred(value)
	}
}

func (m *Manager) Flush(trigger string) {
	parts := make([]string, 0, len(m.stores))
	for _, store := range m.stores {
		stats, err := store.Flush()
		flushed := "no"
		if stats.Flushed {
			flushed = "yes"
		}
		parts = append(parts, fmt.Sprintf("%s: r %d, w %d, e %d, f %s", stats.Name, stats.Reads, stats.Writes, stats.ExpiredRemoved, flushed))
		if err != nil && m.log != nil {
			m.log.Error("cannot flush JSON store", "store", stats.Name, "trigger", trigger, "error", err)
		}
	}
	if m.log != nil {
		m.log.Debug("JSON stores flushed", "trigger", trigger, "summary", strings.Join(parts, ", "))
	}
}
