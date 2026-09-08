package jsonstore

import (
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Database contains the mechanics shared by MilterGuard's small,
// complete-file JSON stores. Domain-specific code supplies record identity,
// expiry, eviction and ordering policies.
type Database[K comparable, V any] struct {
	mu              sync.RWMutex
	name            string
	path            string
	version         int
	maxEntries      int
	readLimit       int64
	records         map[K]V
	key             func(V) K
	identity        Identity[V]
	lastID          uint64
	expired         func(V, time.Time) bool
	maintain        func(V, time.Time) (V, bool, bool)
	evictLess       func(V, V) bool
	sortLess        func(V, V) bool
	prepareForWrite func(V) V
	afterWrite      func(V) V
	onEvict         func(K, V, int)
	cloneValue      func(V) V
	now             func() time.Time
	log             *slog.Logger
	deferWrites     bool
	dirty           bool
	reads           uint64
	writes          uint64
	deletes         uint64
}

type jsonDatabaseFile[V any] struct {
	Version int    `json:"version"`
	LastID  uint64 `json:"last_id"`
	Entries []V    `json:"entries"`
}

// Identity lets Database assign persistent numeric IDs without requiring
// domain records to implement storage-specific methods.
type Identity[V any] struct {
	Get func(V) uint64
	Set func(V, uint64) V
}

type Stats struct {
	Name    string
	Reads   uint64
	Writes  uint64
	Deletes uint64
	Flushed bool
}

func New[K comparable, V any](name, path string, version, maxEntries int, readLimit int64, key func(V) K, identity Identity[V], expired func(V, time.Time) bool, evictLess, sortLess func(V, V) bool, log *slog.Logger) *Database[K, V] {
	return &Database[K, V]{name: name, path: path, version: version, maxEntries: maxEntries, readLimit: readLimit, records: make(map[K]V), key: key, identity: identity, now: time.Now, expired: expired, evictLess: evictLess, sortLess: sortLess, log: log}
}

func (d *Database[K, V]) SetClock(now func() time.Time)                        { d.now = now }
func (d *Database[K, V]) SetMaintenance(fn func(V, time.Time) (V, bool, bool)) { d.maintain = fn }
func (d *Database[K, V]) SetWriteHooks(prepare func(V) V, after func(V) V) {
	d.prepareForWrite, d.afterWrite = prepare, after
}
func (d *Database[K, V]) SetEvictionHook(fn func(K, V, int)) { d.onEvict = fn }
func (d *Database[K, V]) SetClone(fn func(V) V)              { d.cloneValue = fn }

func (d *Database[K, V]) Load(acceptedVersion func(int) bool, normalize func(V) (V, bool, bool)) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var file jsonDatabaseFile[V]
	if err := readFile(d.path, d.readLimit, &file); err != nil {
		return false, err
	}
	if !acceptedVersion(file.Version) {
		return false, fmt.Errorf("%w: unsupported %s version %d", ErrIncompatibleFormat, d.name, file.Version)
	}
	changed := file.Version != d.version
	lastID := file.LastID
	seenIDs := make(map[uint64]bool, len(file.Entries))
	loaded := make(map[K]V, len(file.Entries))
	var loadWrites, loadDeletes uint64
	now := d.now().UTC()
	for _, value := range file.Entries {
		value, keep, modified := normalize(value)
		changed = changed || modified
		if !keep || d.isExpired(value, now) {
			changed = true
			loadDeletes++
			continue
		}
		if modified {
			loadWrites++
		}
		id := d.identity.Get(value)
		if id == 0 {
			return false, fmt.Errorf("%w: %s contains a record without an ID", ErrIncompatibleFormat, d.name)
		}
		if seenIDs[id] {
			return false, fmt.Errorf("%w: %s contains duplicate record ID %d", ErrIncompatibleFormat, d.name, id)
		}
		seenIDs[id] = true
		if id > lastID {
			lastID = id
			changed = true
		}
		key := d.key(value)
		if _, exists := loaded[key]; exists {
			return false, fmt.Errorf("%w: %s contains duplicate logical record key", ErrIncompatibleFormat, d.name)
		}
		loaded[key] = value
	}
	clear(d.records)
	for key, value := range loaded {
		d.records[key] = value
	}
	d.lastID = lastID
	d.writes += loadWrites
	d.deletes += loadDeletes
	for len(d.records) > d.maxEntries {
		d.evictOneLocked()
		changed = true
	}
	if changed {
		d.dirty = true
	}
	return changed, nil
}

func (d *Database[K, V]) Get(key K) (V, bool) {
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
		d.deletes++
		var zero V
		return zero, false
	}
	d.reads++
	return value, true
}

func (d *Database[K, V]) Put(value V) error {
	key := d.key(value)
	return d.Update(func(records map[K]V) (uint64, uint64, uint64, bool) {
		if existing, found := records[key]; found && d.identity.Get(value) == 0 {
			value = d.identity.Set(value, d.identity.Get(existing))
		}
		records[key] = value
		return 0, 1, 0, true
	})
}

// Add appends records whose keys depend on their newly assigned IDs.
func (d *Database[K, V]) Add(values ...V) ([]V, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	added := make([]V, 0, len(values))
	backup := make(map[K]V, len(d.records))
	for key, value := range d.records {
		if d.cloneValue != nil {
			value = d.cloneValue(value)
		}
		backup[key] = value
	}
	backupLastID := d.lastID
	for _, value := range values {
		var err error
		value, err = d.assignIDLocked(value)
		if err != nil {
			d.replaceLocked(backup)
			d.lastID = backupLastID
			return nil, err
		}
		d.records[d.key(value)] = value
		added = append(added, value)
	}
	d.writes += uint64(len(values))
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
			d.lastID = backupLastID
			return nil, err
		}
	}
	return added, nil
}

func (d *Database[K, V]) Delete(key K) (bool, error) {
	deleted := false
	err := d.Update(func(records map[K]V) (uint64, uint64, uint64, bool) {
		if _, found := records[key]; !found {
			return 0, 0, 0, false
		}
		delete(records, key)
		deleted = true
		return 0, 0, 1, true
	})
	return deleted, err
}

func (d *Database[K, V]) View(fn func(V) bool) []V {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now().UTC()
	result := make([]V, 0)
	for _, value := range d.records {
		if d.isExpired(value, now) {
			continue
		}
		if fn(value) {
			result = append(result, value)
			d.reads++
		}
	}
	return result
}

// Update provides one atomic transaction for feature operations that need to
// read and modify several related records.
func (d *Database[K, V]) Update(fn func(map[K]V) (reads, writes, deletes uint64, changed bool)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	backup := make(map[K]V, len(d.records))
	backupLastID := d.lastID
	for key, value := range d.records {
		if d.cloneValue != nil {
			value = d.cloneValue(value)
		}
		backup[key] = value
	}
	reads, writes, deletes, changed := fn(d.records)
	d.reads += reads
	if !changed {
		return nil
	}
	d.writes += writes
	d.deletes += deletes
	if err := d.assignMissingIDsLocked(); err != nil {
		d.replaceLocked(backup)
		d.lastID = backupLastID
		return err
	}
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
			d.lastID = backupLastID
			return err
		}
	}
	return nil
}

func (d *Database[K, V]) replaceLocked(values map[K]V) {
	clear(d.records)
	for key, value := range values {
		d.records[key] = value
	}
}

func (d *Database[K, V]) removeExpiredLocked(now time.Time) uint64 {
	var removed uint64
	for key, value := range d.records {
		maintained := false
		if d.maintain != nil {
			updated, keep, changed := d.maintain(value, now)
			if !keep {
				delete(d.records, key)
				removed++
				continue
			}
			d.records[key] = updated
			value = updated
			maintained = changed
		}
		if d.isExpired(value, now) {
			delete(d.records, key)
			removed++
			continue
		}
		if maintained {
			d.dirty = true
			d.writes++
		}
	}
	if removed > 0 {
		d.dirty = true
		d.deletes += removed
	}
	return removed
}

func (d *Database[K, V]) assignMissingIDsLocked() error {
	seen := make(map[uint64]bool, len(d.records))
	for key, value := range d.records {
		id := d.identity.Get(value)
		if id != 0 {
			if seen[id] {
				return fmt.Errorf("%s contains duplicate record ID %d", d.name, id)
			}
			seen[id] = true
			if id > d.lastID {
				d.lastID = id
			}
			continue
		}
		updated, err := d.assignIDLocked(value)
		if err != nil {
			return err
		}
		d.records[key] = updated
		seen[d.identity.Get(updated)] = true
	}
	return nil
}

func (d *Database[K, V]) assignIDLocked(value V) (V, error) {
	if d.identity.Get(value) != 0 {
		return value, nil
	}
	if d.lastID == math.MaxUint64 {
		return value, fmt.Errorf("%s record ID space exhausted", d.name)
	}
	d.lastID++
	return d.identity.Set(value, d.lastID), nil
}

func (d *Database[K, V]) isExpired(value V, now time.Time) bool {
	return d.expired != nil && d.expired(value, now)
}

func (d *Database[K, V]) evictOneLocked() {
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
		d.deletes++
		if d.onEvict != nil {
			d.onEvict(victim, selected, len(d.records))
		}
	}
}

func (d *Database[K, V]) Flush() (Stats, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.flushLocked("")
}

func (d *Database[K, V]) flushLocked(trigger string) (Stats, error) {
	previousLastID := d.lastID
	if err := d.assignMissingIDsLocked(); err != nil {
		return Stats{Name: d.name, Reads: d.reads, Writes: d.writes, Deletes: d.deletes}, err
	}
	if d.lastID != previousLastID {
		d.dirty = true
	}
	d.removeExpiredLocked(d.now().UTC())
	stats := Stats{Name: d.name, Reads: d.reads, Writes: d.writes, Deletes: d.deletes}
	if d.dirty {
		if err := d.writeLocked(); err != nil {
			return stats, err
		}
		if d.afterWrite != nil {
			for key, value := range d.records {
				d.records[key] = d.afterWrite(value)
			}
		}
		d.dirty = false
		stats.Flushed = true
	}
	d.reads, d.writes, d.deletes = 0, 0, 0
	if trigger != "" && d.log != nil {
		flushed := "no"
		if stats.Flushed {
			flushed = "yes"
		}
		d.log.Debug("JSON stores flushed", "trigger", trigger, "summary", fmt.Sprintf("%s: r %d, w %d, d %d, f %s", stats.Name, stats.Reads, stats.Writes, stats.Deletes, flushed))
	}
	return stats, nil
}

func (d *Database[K, V]) writeLocked() error {
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
	return writeFile(d.path, jsonDatabaseFile[V]{Version: d.version, LastID: d.lastID, Entries: values}, 0750, 0640)
}

func (d *Database[K, V]) SetDeferred(deferred bool) {
	d.mu.Lock()
	d.deferWrites = deferred
	d.mu.Unlock()
}
func (d *Database[K, V]) Size() int { d.mu.RLock(); defer d.mu.RUnlock(); return len(d.records) }

// Snapshot returns an isolated copy of the current records for diagnostics and
// tests. Callers cannot mutate database state through the returned map.
func (d *Database[K, V]) Snapshot() map[K]V {
	d.mu.RLock()
	defer d.mu.RUnlock()
	result := make(map[K]V, len(d.records))
	for key, value := range d.records {
		if d.cloneValue != nil {
			value = d.cloneValue(value)
		}
		result[key] = value
	}
	return result
}

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
		parts = append(parts, fmt.Sprintf("%s: r %d, w %d, d %d, f %s", stats.Name, stats.Reads, stats.Writes, stats.Deletes, flushed))
		if err != nil && m.log != nil {
			m.log.Error("cannot flush JSON store", "store", stats.Name, "trigger", trigger, "error", err)
		}
	}
	if m.log != nil {
		m.log.Debug("JSON stores flushed", "trigger", trigger, "summary", strings.Join(parts, ", "))
	}
}
