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
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
	Value   string    `json:"value"`
}

func TestJSONDatabaseManagerLogsCombinedFlushStatistics(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	now := time.Now().UTC()
	first := New("IP", filepath.Join(t.TempDir(), "ip.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.ID }, func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) }, nil, nil, logger)
	second := New("Contacts", filepath.Join(t.TempDir(), "contacts.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.ID }, nil, nil, nil, logger)
	manager := NewManager(logger)
	manager.Add(first, second)
	manager.SetDeferred(true)
	if err := first.Put(testJSONRecord{ID: "one", Expires: now.Add(time.Hour)}); err != nil {
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
		func(v testJSONRecord) string { return v.ID },
		func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) },
		func(a, b testJSONRecord) bool { return a.Expires.Before(b.Expires) }, nil, nil)
	db.Now = func() time.Time { return now }
	db.SetDeferred(true)
	if err := db.Update(func(records map[string]testJSONRecord) (uint64, uint64, uint64, bool) {
		records["live"] = testJSONRecord{ID: "live", Expires: now.Add(time.Hour), Value: "kept"}
		records["old"] = testJSONRecord{ID: "old", Expires: now.Add(-time.Hour), Value: "expired"}
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
		func(v testJSONRecord) string { return v.ID }, nil,
		func(a, b testJSONRecord) bool { return a.ID < b.ID }, nil, nil)
	db.Now = func() time.Time { return now }
	db.Maintain = func(record testJSONRecord, _ time.Time) (testJSONRecord, bool, bool) {
		switch record.Value {
		case "update":
			record.Value = "updated"
			return record, true, true
		case "delete":
			return record, false, true
		default:
			return record, true, false
		}
	}
	db.SetDeferred(true)
	if err := db.Update(func(records map[string]testJSONRecord) (uint64, uint64, uint64, bool) {
		records["a"] = testJSONRecord{ID: "a", Value: "update"}
		records["b"] = testJSONRecord{ID: "b", Value: "delete"}
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

	if err := db.Put(testJSONRecord{ID: "b", Value: "keep"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Put(testJSONRecord{ID: "c", Value: "keep"}); err != nil {
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
