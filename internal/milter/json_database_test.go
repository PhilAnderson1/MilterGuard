package milter

import (
	"bytes"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
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
	first := newJSONDatabase("IP", filepath.Join(t.TempDir(), "ip.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.ID }, func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) }, nil, nil, logger)
	second := newJSONDatabase("Contacts", filepath.Join(t.TempDir(), "contacts.json"), 1, 10, 1<<20, func(v testJSONRecord) string { return v.ID }, nil, nil, nil, logger)
	manager := &jsonDatabaseManager{log: logger}
	manager.add(first, second)
	manager.setDeferred(true)
	if err := first.put(testJSONRecord{ID: "one", Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := first.get("one"); !ok {
		t.Fatal("stored record not readable")
	}
	manager.flush("shutdown")
	logged := output.String()
	for _, want := range []string{`"trigger":"shutdown"`, `IP: r 1, w 1, e 0, f yes`, `Contacts: r 0, w 0, e 0, f no`} {
		if !strings.Contains(logged, want) {
			t.Fatalf("flush log missing %q: %s", want, logged)
		}
	}
}

func TestFeatureStoresReportFlushStatistics(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	directory := t.TempDir()
	ip := newIPReputationStore(config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 10, StateFile: filepath.Join(directory, "ip.json")}, logger)
	contacts := newCorrespondentStore(config.CorrespondentsConfig{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all", File: filepath.Join(directory, "contacts.json"), MaxEntries: 10}, logger)
	rejections := newRejectionHistoryStore(config.RejectionHistoryConfig{File: filepath.Join(directory, "rejections.json"), Expiry: config.Duration(time.Hour), MaxEntries: 10}, logger)
	manager := &jsonDatabaseManager{log: logger}
	manager.add(ip.db, contacts.db, rejections.db)
	manager.setDeferred(true)
	address := netip.MustParseAddr("192.0.2.10")
	ip.add(address, "unwanted", 1, connectionDNSResult{})
	ip.lookup(address)
	if err := contacts.learn("local@example.com", []string{"friend@example.net"}); err != nil {
		t.Fatal(err)
	}
	contacts.match("friend@example.net", []string{"local@example.com"})
	if err := rejections.add("sender@example.net", "", []string{"local@example.com"}, []string{"test"}); err != nil {
		t.Fatal(err)
	}
	rejections.list("local@example.com")
	manager.flush("timer")
	logged := output.String()
	for _, want := range []string{"IP: r 1, w 1, e 0, f yes", "Contacts: r 1, w 1, e 0, f yes", "Rejections: r 1, w 1, e 0, f yes"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("flush log missing %q: %s", want, logged)
		}
	}
}

func TestJSONDatabaseReadWriteDeleteExpiryAndStats(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	db := newJSONDatabase("Test", filepath.Join(t.TempDir(), "test.json"), 1, 2, 1<<20,
		func(v testJSONRecord) string { return v.ID },
		func(v testJSONRecord, at time.Time) bool { return !v.Expires.After(at) },
		func(a, b testJSONRecord) bool { return a.Expires.Before(b.Expires) }, nil, nil)
	db.now = func() time.Time { return now }
	db.setDeferred(true)
	if err := db.update(func(records map[string]testJSONRecord) (uint64, uint64, bool) {
		records["live"] = testJSONRecord{ID: "live", Expires: now.Add(time.Hour), Value: "kept"}
		records["old"] = testJSONRecord{ID: "old", Expires: now.Add(-time.Hour), Value: "expired"}
		return 0, 2, true
	}); err != nil {
		t.Fatal(err)
	}
	if value, ok := db.get("live"); !ok || value.Value != "kept" {
		t.Fatalf("live record = %#v, %v", value, ok)
	}
	if _, ok := db.get("old"); ok {
		t.Fatal("expired record was readable")
	}
	if deleted, err := db.delete("live"); err != nil || !deleted {
		t.Fatalf("delete = %v, %v", deleted, err)
	}
	if _, ok := db.get("live"); ok {
		t.Fatal("deleted record remained readable before flush")
	}
	stats, err := db.flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Reads != 1 || stats.Writes != 3 || stats.ExpiredRemoved != 1 || !stats.Flushed {
		t.Fatalf("stats = %#v", stats)
	}
	if _, err := db.load(func(version int) bool { return version == 1 }, func(v testJSONRecord) (testJSONRecord, bool, bool) { return v, true, false }); err != nil {
		t.Fatal(err)
	}
}
