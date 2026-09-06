package milter

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/jsonfile"
)

// jsonDatabase contains the mechanics shared by MilterGuard's small,
// complete-file JSON stores. Domain-specific code supplies record identity,
// expiry, eviction and ordering policies.
type jsonDatabase[K comparable, V any] struct {
	mu              sync.RWMutex
	name            string
	path            string
	version         int
	maxEntries      int
	readLimit       int64
	records         map[K]V
	key             func(V) K
	expired         func(V, time.Time) bool
	maintain        func(V, time.Time) (V, bool, bool)
	evictLess       func(V, V) bool
	sortLess        func(V, V) bool
	prepareForWrite func(V) V
	afterWrite      func(map[K]V)
	onEvict         func(K, V)
	cloneValue      func(V) V
	now             func() time.Time
	log             *slog.Logger
	deferWrites     bool
	dirty           bool
	reads           uint64
	writes          uint64
	expiredRemoved  uint64
}

type jsonDatabaseFile[V any] struct {
	Version int `json:"version"`
	Entries []V `json:"entries"`
}

type jsonDatabaseStats struct {
	Name           string
	Reads          uint64
	Writes         uint64
	ExpiredRemoved uint64
	Flushed        bool
}

func newJSONDatabase[K comparable, V any](name, path string, version, maxEntries int, readLimit int64, key func(V) K, expired func(V, time.Time) bool, evictLess, sortLess func(V, V) bool, log *slog.Logger) *jsonDatabase[K, V] {
	return &jsonDatabase[K, V]{name: name, path: path, version: version, maxEntries: maxEntries, readLimit: readLimit, records: make(map[K]V), key: key, expired: expired, evictLess: evictLess, sortLess: sortLess, now: time.Now, log: log}
}

func (d *jsonDatabase[K, V]) load(acceptedVersion func(int) bool, normalize func(V) (V, bool, bool)) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var file jsonDatabaseFile[V]
	if err := jsonfile.Read(d.path, d.readLimit, &file); err != nil {
		return false, err
	}
	if !acceptedVersion(file.Version) {
		return false, fmt.Errorf("unsupported %s version %d", d.name, file.Version)
	}
	changed := file.Version != d.version
	now := d.now().UTC()
	for _, value := range file.Entries {
		value, keep, modified := normalize(value)
		changed = changed || modified
		if !keep || d.isExpired(value, now) {
			changed = true
			d.expiredRemoved++
			continue
		}
		d.records[d.key(value)] = value
	}
	for len(d.records) > d.maxEntries {
		d.evictOneLocked()
		changed = true
	}
	if changed {
		d.dirty = true
	}
	return changed, nil
}

func (d *jsonDatabase[K, V]) get(key K) (V, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	value, ok := d.records[key]
	if !ok {
		var zero V
		return zero, false
	}
	if d.isExpired(value, d.now().UTC()) {
		delete(d.records, key)
		d.dirty = true
		d.expiredRemoved++
		var zero V
		return zero, false
	}
	d.reads++
	return value, true
}

func (d *jsonDatabase[K, V]) put(value V) error {
	key := d.key(value)
	return d.update(func(records map[K]V) (uint64, uint64, bool) {
		records[key] = value
		return 0, 1, true
	})
}

func (d *jsonDatabase[K, V]) delete(key K) (bool, error) {
	deleted := false
	err := d.update(func(records map[K]V) (uint64, uint64, bool) {
		if _, found := records[key]; !found {
			return 0, 0, false
		}
		delete(records, key)
		deleted = true
		return 0, 1, true
	})
	return deleted, err
}

func (d *jsonDatabase[K, V]) view(fn func(V) bool) []V {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now().UTC()
	result := make([]V, 0)
	for key, value := range d.records {
		if d.isExpired(value, now) {
			delete(d.records, key)
			d.dirty = true
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
func (d *jsonDatabase[K, V]) update(fn func(map[K]V) (reads, writes uint64, changed bool)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	backup := make(map[K]V, len(d.records))
	for key, value := range d.records {
		if d.cloneValue != nil {
			value = d.cloneValue(value)
		}
		backup[key] = value
	}
	reads, writes, changed := fn(d.records)
	d.reads += reads
	if !changed {
		return nil
	}
	d.writes += writes
	d.dirty = true
	if len(d.records) >= d.maxEntries {
		d.removeExpiredLocked(d.now().UTC())
	}
	for len(d.records) > d.maxEntries {
		d.evictOneLocked()
	}
	if !d.deferWrites {
		if _, err := d.flushLocked("write"); err != nil {
			d.replaceLocked(backup)
			return err
		}
	}
	return nil
}

func (d *jsonDatabase[K, V]) replaceLocked(values map[K]V) {
	clear(d.records)
	for key, value := range values {
		d.records[key] = value
	}
}

func (d *jsonDatabase[K, V]) removeExpiredLocked(now time.Time) uint64 {
	var removed uint64
	for key, value := range d.records {
		if d.maintain != nil {
			updated, keep, changed := d.maintain(value, now)
			if !keep {
				delete(d.records, key)
				removed++
				continue
			}
			d.records[key] = updated
			value = updated
			if changed {
				d.dirty = true
			}
		}
		if d.isExpired(value, now) {
			delete(d.records, key)
			removed++
		}
	}
	if removed > 0 {
		d.dirty = true
		d.expiredRemoved += removed
	}
	return removed
}

func (d *jsonDatabase[K, V]) markWritesLocked(count uint64) {
	d.writes += count
	d.dirty = true
}

func (d *jsonDatabase[K, V]) changedLocked(writes uint64) error {
	d.markWritesLocked(writes)
	if d.deferWrites {
		return nil
	}
	_, err := d.flushLocked("write")
	return err
}

func (d *jsonDatabase[K, V]) markReadsLocked(count uint64) { d.reads += count }

func (d *jsonDatabase[K, V]) isExpired(value V, now time.Time) bool {
	return d.expired != nil && d.expired(value, now)
}

func (d *jsonDatabase[K, V]) evictOneLocked() {
	var victim K
	var selected V
	found := false
	for key, value := range d.records {
		if !found || (d.evictLess != nil && d.evictLess(value, selected)) {
			victim, selected, found = key, value, true
		}
	}
	if found {
		delete(d.records, victim)
		d.writes++
		if d.onEvict != nil {
			d.onEvict(victim, selected)
		}
	}
}

func (d *jsonDatabase[K, V]) flush() (jsonDatabaseStats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked("")
}

func (d *jsonDatabase[K, V]) flushLocked(trigger string) (jsonDatabaseStats, error) {
	d.removeExpiredLocked(d.now().UTC())
	stats := jsonDatabaseStats{Name: d.name, Reads: d.reads, Writes: d.writes, ExpiredRemoved: d.expiredRemoved}
	if d.dirty {
		if err := d.writeLocked(); err != nil {
			return stats, err
		}
		if d.afterWrite != nil {
			d.afterWrite(d.records)
		}
		d.dirty = false
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

func (d *jsonDatabase[K, V]) writeLocked() error {
	if d.path == "" {
		return nil
	}
	values := make([]V, 0, len(d.records))
	for _, value := range d.records {
		if d.prepareForWrite != nil {
			value = d.prepareForWrite(value)
		}
		values = append(values, value)
	}
	if d.sortLess != nil {
		sort.Slice(values, func(i, j int) bool { return d.sortLess(values[i], values[j]) })
	}
	return jsonfile.Write(d.path, jsonDatabaseFile[V]{Version: d.version, Entries: values}, 0750, 0640)
}

func (d *jsonDatabase[K, V]) setDeferred(deferred bool) {
	d.mu.Lock()
	d.deferWrites = deferred
	d.mu.Unlock()
}
func (d *jsonDatabase[K, V]) size() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.records) }

type managedJSONDatabase interface {
	flush() (jsonDatabaseStats, error)
	setDeferred(bool)
}

type jsonDatabaseManager struct {
	log    *slog.Logger
	stores []managedJSONDatabase
}

func (m *jsonDatabaseManager) add(stores ...managedJSONDatabase) {
	m.stores = append(m.stores, stores...)
}
func (m *jsonDatabaseManager) setDeferred(value bool) {
	for _, store := range m.stores {
		store.setDeferred(value)
	}
}

func (m *jsonDatabaseManager) flush(trigger string) {
	parts := make([]string, 0, len(m.stores))
	for _, store := range m.stores {
		stats, err := store.flush()
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
