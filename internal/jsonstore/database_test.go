package jsonstore

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testJSONRecord struct {
	StoreID uint64    `json:"id"`
	Key     string    `json:"key"`
	Expires time.Time `json:"expires"`
	Value   string    `json:"value"`
}

type testSliceRecord struct {
	StoreID uint64
	Key     string
	Values  []string
}

type testManagedDatabase struct {
	mu       sync.Mutex
	deferred bool
	flushes  int
}

func (store *testManagedDatabase) SetDeferred(value bool) {
	store.mu.Lock()
	store.deferred = value
	store.mu.Unlock()
}

func (store *testManagedDatabase) Flush() (Stats, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.flushes++
	return Stats{Name: "Test"}, nil
}

func (store *testManagedDatabase) state() (bool, int) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.deferred, store.flushes
}

var testIdentity = Identity[testJSONRecord]{
	Get: func(v testJSONRecord) uint64 { return v.StoreID },
	Set: func(v testJSONRecord, id uint64) testJSONRecord { v.StoreID = id; return v },
}

var testSliceIdentity = Identity[testSliceRecord]{
	Get: func(v testSliceRecord) uint64 { return v.StoreID },
	Set: func(v testSliceRecord, id uint64) testSliceRecord { v.StoreID = id; return v },
}

func TestJSONDatabaseGetAndViewReturnIsolatedClones(t *testing.T) {
	db := New("Test", "", 1, 10, 1<<20,
		func(v testSliceRecord) string { return v.Key }, testSliceIdentity, nil, nil, nil, nil)
	db.SetClone(func(record testSliceRecord) testSliceRecord {
		record.Values = append([]string(nil), record.Values...)
		return record
	})
	db.SetDeferred(true)
	if err := db.Put(testSliceRecord{Key: "record", Values: []string{"stored"}}); err != nil {
		t.Fatal(err)
	}

	fromGet, found := db.Get("record")
	if !found {
		t.Fatal("record not found")
	}
	fromGet.Values[0] = "changed through Get"

	fromView := db.View(func(record testSliceRecord) bool {
		record.Values[0] = "changed in View callback"
		return true
	})
	if len(fromView) != 1 {
		t.Fatalf("View returned %d records", len(fromView))
	}
	fromView[0].Values[0] = "changed after View"

	stored, found := db.Get("record")
	if !found || len(stored.Values) != 1 || stored.Values[0] != "stored" {
		t.Fatalf("returned slice mutated stored state: %#v, %v", stored, found)
	}
}

func TestJSONDatabaseSettersAreSafeDuringConcurrentAccess(t *testing.T) {
	db := New("Test", "", 1, 4, 1<<20,
		func(v testJSONRecord) string { return v.Key }, testIdentity, nil,
		func(a, b testJSONRecord) bool { return a.Key < b.Key }, nil, nil)
	db.SetDeferred(true)

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for range 200 {
			db.SetClock(time.Now)
			db.SetMaintenance(func(record testJSONRecord, _ time.Time) (testJSONRecord, bool, bool) {
				return record, true, false
			})
			db.SetWriteHooks(func(record testJSONRecord) testJSONRecord { return record }, func(record testJSONRecord) testJSONRecord { return record })
			db.SetEvictionHook(func(string, testJSONRecord, int) {})
			db.SetClone(func(record testJSONRecord) testJSONRecord { return record })
		}
	}()
	go func() {
		defer workers.Done()
		for index := range 200 {
			_ = db.Put(testJSONRecord{Key: fmt.Sprintf("key-%d", index)})
			_, _ = db.Get(fmt.Sprintf("key-%d", index))
			_ = db.Snapshot()
			_, _ = db.Flush()
		}
	}()
	workers.Wait()
}

func TestJSONDatabaseManagerLogsCombinedFlushStatistics(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Now().UTC()
	first := New("IP", filepath.Join(t.TempDir(), "ip.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.Key }, testIdentity, func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) }, nil, nil, logger)
	second := New("Contacts", filepath.Join(t.TempDir(), "contacts.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.Key }, testIdentity, nil, nil, nil, logger)
	manager := NewManager(logger)
	manager.Add(first, second)
	manager.SetDeferred(true)
	if err := first.Put(testJSONRecord{Key: "one", Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := first.Get("one"); !ok {
		t.Fatal("stored record not readable")
	}
	manager.Flush("shutdown")
	logged := output.String()
	for _, want := range []string{`"trigger":"shutdown"`, `IP: r 1, w 1, d 0, f yes`, `Contacts: r 0, w 0, d 0, f no`} {
		if !strings.Contains(logged, want) {
			t.Fatalf("flush log missing %q: %s", want, logged)
		}
	}
}

func TestJSONDatabaseManagerAppliesDeferredModeToLateStore(t *testing.T) {
	manager := NewManager(nil)
	manager.SetDeferred(true)
	store := &testManagedDatabase{}
	manager.Add(store)
	deferred, _ := store.state()
	if !deferred {
		t.Fatal("late store did not inherit deferred-write mode")
	}
}

func TestJSONDatabaseManagerConcurrentOperations(t *testing.T) {
	manager := NewManager(nil)
	stores := make([]*testManagedDatabase, 100)
	for index := range stores {
		stores[index] = &testManagedDatabase{}
	}

	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		for _, store := range stores {
			manager.Add(store)
		}
	}()
	go func() {
		defer workers.Done()
		for index := range stores {
			manager.SetDeferred(index%2 == 0)
		}
	}()
	go func() {
		defer workers.Done()
		for range stores {
			manager.Flush("test")
		}
	}()
	workers.Wait()

	manager.SetDeferred(true)
	manager.Flush("final")
	for index, store := range stores {
		deferred, flushes := store.state()
		if !deferred || flushes < 1 {
			t.Fatalf("store %d state: deferred=%v flushes=%d", index, deferred, flushes)
		}
	}
}

func TestJSONDatabaseReadWriteDeleteExpiryAndStats(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	db := New("Test", filepath.Join(t.TempDir(), "test.json"), 1, 2, 1<<20,
		func(v testJSONRecord) string { return v.Key }, testIdentity,
		func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) },
		func(a, b testJSONRecord) bool { return a.Expires.Before(b.Expires) }, nil, nil)
	db.SetClock(func() time.Time { return now })
	db.SetDeferred(true)
	if err := db.Update(func(records map[string]testJSONRecord) (uint64, uint64, uint64, bool) {
		records["live"] = testJSONRecord{Key: "live", Expires: now.Add(time.Hour), Value: "kept"}
		records["old"] = testJSONRecord{Key: "old", Expires: now.Add(-time.Hour), Value: "expired"}
		return 0, 2, 0, true
	}); err != nil {
		t.Fatal(err)
	}
	if value, ok := db.Get("live"); !ok || value.Value != "kept" {
		t.Fatalf("live record = %#v, %v", value, ok)
	}
	if _, ok := db.Get("old"); ok {
		t.Fatal("expired record was readable")
	}
	if deleted, err := db.Delete("live"); err != nil || !deleted {
		t.Fatalf("delete = %v, %v", deleted, err)
	}
	if _, ok := db.Get("live"); ok {
		t.Fatal("deleted record remained readable before flush")
	}
	stats, err := db.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Reads != 1 || stats.Writes != 2 || stats.Deletes != 2 || !stats.Flushed {
		t.Fatalf("stats = %#v", stats)
	}
	if _, err := db.Load(func(version int) bool { return version == 1 }, func(v testJSONRecord) (testJSONRecord, bool, bool) { return v, true, false }); err != nil {
		t.Fatal(err)
	}
}

func TestJSONDatabaseCountsMaintenanceAndEvictionByRecord(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	db := New("Test", filepath.Join(t.TempDir(), "test.json"), 1, 2, 1<<20,
		func(v testJSONRecord) string { return v.Key }, testIdentity, nil,
		func(a, b testJSONRecord) bool { return a.Key < b.Key }, nil, nil)
	db.SetClock(func() time.Time { return now })
	db.SetMaintenance(func(record testJSONRecord, _ time.Time) (testJSONRecord, bool, bool) {
		switch record.Value {
		case "update":
			record.Value = "updated"
			return record, true, true
		case "delete":
			return record, false, true
		default:
			return record, true, false
		}
	})
	db.SetDeferred(true)
	if err := db.Update(func(records map[string]testJSONRecord) (uint64, uint64, uint64, bool) {
		records["a"] = testJSONRecord{Key: "a", Value: "update"}
		records["b"] = testJSONRecord{Key: "b", Value: "delete"}
		return 0, 2, 0, true
	}); err != nil {
		t.Fatal(err)
	}
	stats, err := db.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Writes != 3 || stats.Deletes != 1 {
		t.Fatalf("maintenance stats = %#v", stats)
	}

	if err := db.Put(testJSONRecord{Key: "b", Value: "keep"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(testJSONRecord{Key: "c", Value: "keep"}); err != nil {
		t.Fatal(err)
	}
	stats, err = db.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Writes != 2 || stats.Deletes != 1 {
		t.Fatalf("eviction stats = %#v", stats)
	}
}

func TestJSONDatabaseAssignsMonotonicIDsAndPersistsLastID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.json")
	newDatabase := func() *Database[string, testJSONRecord] {
		return New("Test", path, 1, 10, 1<<20, func(v testJSONRecord) string { return v.Key }, testIdentity, nil, nil, nil, nil)
	}
	db := newDatabase()
	if err := db.Put(testJSONRecord{Key: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(testJSONRecord{Key: "b"}); err != nil {
		t.Fatal(err)
	}
	if deleted, err := db.Delete("b"); err != nil || !deleted {
		t.Fatalf("delete b = %v, %v", deleted, err)
	}
	if err := db.Put(testJSONRecord{Key: "c"}); err != nil {
		t.Fatal(err)
	}
	var persisted jsonDatabaseFile[testJSONRecord]
	if err := readFile(path, 1<<20, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 1 || persisted.LastID != 3 || len(persisted.Entries) != 2 {
		t.Fatalf("persisted database = %#v", persisted)
	}
	ids := map[string]uint64{}
	for _, entry := range persisted.Entries {
		ids[entry.Key] = entry.StoreID
	}
	if ids["a"] != 1 || ids["c"] != 3 {
		t.Fatalf("record IDs = %#v", ids)
	}

	reloaded := newDatabase()
	if _, err := reloaded.Load(func(version int) bool { return version == 1 }, func(v testJSONRecord) (testJSONRecord, bool, bool) { return v, true, false }); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Put(testJSONRecord{Key: "d"}); err != nil {
		t.Fatal(err)
	}
	if entry, ok := reloaded.Get("d"); !ok || entry.StoreID != 4 {
		t.Fatalf("new record after reload = %#v, %v", entry, ok)
	}
}

func TestJSONDatabaseAddAssignsIDBeforeDerivingKey(t *testing.T) {
	db := New("Test", filepath.Join(t.TempDir(), "test.json"), 1, 10, 1<<20,
		func(v testJSONRecord) uint64 { return v.StoreID }, testIdentity, nil, nil, nil, nil)
	added, err := db.Add(testJSONRecord{Key: "a"}, testJSONRecord{Key: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 || added[0].StoreID != 1 || added[1].StoreID != 2 {
		t.Fatalf("assigned records = %#v", added)
	}
	if first, ok := db.Get(1); !ok || first.Key != "a" {
		t.Fatalf("first added record = %#v, %v", first, ok)
	}
	if second, ok := db.Get(2); !ok || second.Key != "b" {
		t.Fatalf("second added record = %#v, %v", second, ok)
	}
}

func TestJSONDatabaseRetainsDirtyUpdateAfterWriteFailure(t *testing.T) {
	directory := t.TempDir()
	blocker := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	db := New("Test", filepath.Join(blocker, "test.json"), 1, 10, 1<<20,
		func(v testJSONRecord) string { return v.Key }, testIdentity, nil, nil, nil, nil)
	if err := db.Put(testJSONRecord{Key: "retained", Value: "memory"}); err == nil {
		t.Fatal("write through a non-directory unexpectedly succeeded")
	}
	if record, found := db.Get("retained"); !found || record.Value != "memory" {
		t.Fatalf("failed write rolled back in-memory update: %#v, %v", record, found)
	}

	goodPath := filepath.Join(directory, "retry.json")
	db.mu.Lock()
	db.path = goodPath
	db.mu.Unlock()
	if stats, err := db.Flush(); err != nil || !stats.Flushed {
		t.Fatalf("retry flush = %#v, %v", stats, err)
	}
	if _, err := os.Stat(goodPath); err != nil {
		t.Fatalf("retry did not persist retained state: %v", err)
	}
}

func TestJSONDatabaseRetainsAddedRecordsAfterWriteFailure(t *testing.T) {
	directory := t.TempDir()
	blocker := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("block"), 0600); err != nil {
		t.Fatal(err)
	}
	db := New("Test", filepath.Join(blocker, "test.json"), 1, 10, 1<<20,
		func(v testJSONRecord) uint64 { return v.StoreID }, testIdentity, nil, nil, nil, nil)
	added, err := db.Add(testJSONRecord{Key: "retained"})
	if err == nil {
		t.Fatal("write through a non-directory unexpectedly succeeded")
	}
	if len(added) != 1 || added[0].StoreID != 1 {
		t.Fatalf("failed write did not return retained addition: %#v", added)
	}
	if record, found := db.Get(1); !found || record.Key != "retained" {
		t.Fatalf("failed write rolled back added record: %#v, %v", record, found)
	}
}

func TestJSONDatabaseRejectsMissingAndDuplicateIDsWithoutPartialLoad(t *testing.T) {
	for _, test := range []struct {
		name    string
		entries []testJSONRecord
	}{
		{"missing", []testJSONRecord{{Key: "a", StoreID: 1}, {Key: "b"}}},
		{"duplicate", []testJSONRecord{{Key: "a", StoreID: 1}, {Key: "b", StoreID: 1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.json")
			if err := writeFile(path, jsonDatabaseFile[testJSONRecord]{Version: 1, LastID: 1, Entries: test.entries}, 0750, 0640); err != nil {
				t.Fatal(err)
			}
			db := New("Test", path, 1, 10, 1<<20, func(v testJSONRecord) string { return v.Key }, testIdentity, nil, nil, nil, nil)
			if _, err := db.Load(func(version int) bool { return version == 1 }, func(v testJSONRecord) (testJSONRecord, bool, bool) { return v, true, false }); err == nil {
				t.Fatal("invalid IDs were accepted")
			}
			if db.Size() != 0 {
				t.Fatalf("partial records remained after failed load: %#v", db.Snapshot())
			}
		})
	}
}

func TestJSONDatabaseRejectsDuplicateLogicalKeysWithoutReplacingLiveState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.json")
	entries := []testJSONRecord{
		{Key: "duplicate", StoreID: 1, Value: "first"},
		{Key: "duplicate", StoreID: 2, Value: "second"},
	}
	if err := writeFile(path, jsonDatabaseFile[testJSONRecord]{Version: 1, LastID: 2, Entries: entries}, 0750, 0640); err != nil {
		t.Fatal(err)
	}
	db := New("Test", path, 1, 10, 1<<20, func(v testJSONRecord) string { return v.Key }, testIdentity, nil, nil, nil, nil)
	db.SetDeferred(true)
	if err := db.Put(testJSONRecord{Key: "existing", StoreID: 7, Value: "live"}); err != nil {
		t.Fatal(err)
	}
	_, err := db.Load(func(version int) bool { return version == 1 }, func(v testJSONRecord) (testJSONRecord, bool, bool) { return v, true, false })
	if err == nil || !strings.Contains(err.Error(), "duplicate logical record key") {
		t.Fatalf("duplicate logical keys returned error %v", err)
	}
	if records := db.Snapshot(); len(records) != 1 || records["existing"].Value != "live" {
		t.Fatalf("failed load replaced live state: %#v", records)
	}
}

func TestJSONDatabaseEvictionHookRunsAfterUnlock(t *testing.T) {
	db := New("Test", filepath.Join(t.TempDir(), "test.json"), 1, 1, 1<<20,
		func(v testJSONRecord) string { return v.Key }, testIdentity, nil,
		func(a, b testJSONRecord) bool { return a.Key < b.Key }, nil, nil)
	db.SetDeferred(true)
	if err := db.Put(testJSONRecord{Key: "a"}); err != nil {
		t.Fatal(err)
	}

	type observation struct {
		key        string
		reported   int
		actualSize int
	}
	observed := make(chan observation, 1)
	db.SetEvictionHook(func(key string, _ testJSONRecord, size int) {
		observed <- observation{key: key, reported: size, actualSize: db.Size()}
	})
	done := make(chan error, 1)
	go func() {
		done <- db.Put(testJSONRecord{Key: "b"})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Put deadlocked while eviction hook called back into database")
	}
	select {
	case got := <-observed:
		if got.key != "a" || got.reported != 1 || got.actualSize != 1 {
			t.Fatalf("eviction observation = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("eviction hook was not called")
	}
}
