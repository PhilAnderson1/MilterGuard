package jsonstore

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testJSONRecord struct {
	StoreID uint64    `json:"id"`
	Key     string    `json:"key"`
	Expires time.Time `json:"expires"`
	Value   string    `json:"value"`
}

var testIdentity = Identity[testJSONRecord]{
	Get: func(v testJSONRecord) uint64 { return v.StoreID },
	Set: func(v testJSONRecord, id uint64) testJSONRecord { v.StoreID = id; return v },
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
