package milter

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestIPReputationDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip.json")
	cfg := config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), RepeatThreshold: 3,
		RepeatWindow: config.Duration(24 * time.Hour), RepeatBlockDuration: config.Duration(24 * time.Hour),
		MaxEntries: 10, StateFile: path,
	}
	store := newIPReputationStore(cfg, nil)
	store.db.SetDeferred(true)
	store.add(netip.MustParseAddr("192.0.2.1"), 1, connectionDNSResult{})
	assertNotPersisted(t, path)
	if _, err := store.db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, blocked := newIPReputationStore(cfg, nil).lookup(netip.MustParseAddr("192.0.2.1")); !blocked {
		t.Fatal("flushed IP reputation was not reloadable")
	}
}

func TestCorrespondentDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "correspondents.json")
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender",
		RecipientMatch: "all", File: path, MaxEntries: 10,
	}
	store := newCorrespondentStore(cfg, nil)
	store.db.SetDeferred(true)
	if err := store.learn("local@example.com", []string{"friend@example.net"}); err != nil {
		t.Fatal(err)
	}
	assertNotPersisted(t, path)
	if _, err := store.db.Flush(); err != nil {
		t.Fatal(err)
	}
	if match := newCorrespondentStore(cfg, nil).match("friend@example.net", []string{"local@example.com"}); !match.Known {
		t.Fatal("flushed correspondent was not reloadable")
	}
}

func TestRejectionHistoryDeferredPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejections.json")
	cfg := config.RejectionHistoryConfig{File: path, Expiry: config.Duration(24 * time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.db.SetDeferred(true)
	if err := store.add("sender@example.net", "", []string{"local@example.com"}, []string{"Unwanted message"}); err != nil {
		t.Fatal(err)
	}
	assertNotPersisted(t, path)
	if _, err := store.db.Flush(); err != nil {
		t.Fatal(err)
	}
	if entries := newRejectionHistoryStore(cfg, nil).list("local@example.com"); len(entries) != 1 || entries[0].Reason != "Unwanted message" {
		t.Fatalf("flushed rejection history = %#v", entries)
	}
}

func TestPersistenceFlushRemovesExpiredRecords(t *testing.T) {
	base := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

	t.Run("IP reputation", func(t *testing.T) {
		store := newIPReputationStore(config.IPReputationConfig{
			BlockDuration: config.Duration(time.Hour), RepeatThreshold: 3, RepeatWindow: config.Duration(time.Hour),
			RepeatBlockDuration: config.Duration(24 * time.Hour), MaxEntries: 10, StateFile: filepath.Join(t.TempDir(), "ip.json"),
		}, nil)
		store.now = func() time.Time { return base }
		store.db.SetDeferred(true)
		if err := store.db.Put(rejectedIPRecord{IP: "192.0.2.1", LastActivityAt: base.Add(-2 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Flush(); err != nil {
			t.Fatal(err)
		}
		if len(store.snapshot()) != 0 {
			t.Fatal("expired IP record was not removed during flush")
		}
	})

	t.Run("correspondents", func(t *testing.T) {
		store := newCorrespondentStore(config.CorrespondentsConfig{
			UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all", StaleAfter: config.Duration(time.Hour),
			File: filepath.Join(t.TempDir(), "correspondents.json"), MaxEntries: 10,
		}, nil)
		store.now = func() time.Time { return base }
		store.db.SetDeferred(true)
		entry := correspondentEntry{LocalAddress: "local@example.com", Correspondent: "old@example.net", LearnedAt: base.Add(-2 * time.Hour), LastActivityAt: base.Add(-2 * time.Hour), WhitelistType: whitelistManual}
		if err := store.db.Put(entry); err != nil {
			t.Fatal(err)
		}
		if match := store.match(entry.Correspondent, []string{entry.LocalAddress}); match.Known {
			t.Fatal("stale correspondent was used before scheduled cleanup")
		}
		if len(store.snapshot()) != 1 {
			t.Fatal("full correspondent cleanup ran before the interval elapsed")
		}
		if _, err := store.db.Flush(); err != nil {
			t.Fatal(err)
		}
		if len(store.snapshot()) != 0 {
			t.Fatal("stale correspondent was not removed at flush interval")
		}
	})

	t.Run("rejection history", func(t *testing.T) {
		store := newRejectionHistoryStore(config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "rejections.json"), Expiry: config.Duration(time.Hour), MaxEntries: 10}, nil)
		store.now = func() time.Time { return base }
		store.db.SetDeferred(true)
		if _, err := store.db.Add(rejectionHistoryEntry{Sender: "old@example.net", Recipients: []string{"local@example.com"}, RejectedAt: base.Add(-2 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if entries := store.list("local@example.com"); len(entries) != 0 {
			t.Fatal("expired rejection was returned before scheduled cleanup")
		}
		if store.db.Size() == 0 {
			t.Fatal("full rejection cleanup ran before the interval elapsed")
		}
		if _, err := store.db.Flush(); err != nil {
			t.Fatal(err)
		}
		if store.db.Size() != 0 {
			t.Fatal("expired rejection was not removed at flush interval")
		}
	})
}

func assertNotPersisted(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deferred state was written before flush: %v", err)
	}
}
