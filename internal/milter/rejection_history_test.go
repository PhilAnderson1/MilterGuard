package milter

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestRejectionHistoryPersistsPerRecipientAndExpires(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(24 * time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.now = func() time.Time { return now }
	if err := store.add("Sender <NEWS@Example.NET>", "bounce@example.net", []string{"Alice@Example.com", "bob@example.com", "alice@example.com"}, []string{"Credential theft link"}); err != nil {
		t.Fatal(err)
	}
	if got := store.list("alice@example.com"); len(got) != 1 || got[0].Sender != "news@example.net" || !got[0].RejectedAt.Equal(now) {
		t.Fatalf("Alice history = %#v", got)
	}
	if got := store.list("carol@example.com"); len(got) != 0 {
		t.Fatalf("cross-recipient history exposed: %#v", got)
	}
	reloaded := newRejectionHistoryStore(cfg, nil)
	if got := reloaded.list("bob@example.com"); len(got) != 1 {
		t.Fatalf("reloaded history = %#v", got)
	}
	reloaded.now = func() time.Time { return now.Add(25 * time.Hour) }
	if got := reloaded.list("alice@example.com"); len(got) != 0 {
		t.Fatalf("expired history retained: %#v", got)
	}
}

func TestRejectionHistoryEvictsOldest(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(24 * time.Hour), MaxEntries: 2}
	store := newRejectionHistoryStore(cfg, nil)
	store.now = func() time.Time { return now }
	for _, sender := range []string{"one@example.net", "two@example.net", "three@example.net"} {
		if err := store.add(sender, "", []string{"alice@example.com"}, []string{"Unwanted message"}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	got := store.list("alice@example.com")
	if len(got) != 2 || got[0].Sender != "three@example.net" || got[1].Sender != "two@example.net" {
		t.Fatalf("bounded history = %#v", got)
	}
}

func TestRejectionHistoryListsMostRecentFirst(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(24 * time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.now = func() time.Time { return now }
	if err := store.add("older@example.net", "", []string{"alice@example.com"}, []string{"Older reason"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := store.add("newer@example.net", "", []string{"alice@example.com"}, []string{"Newer reason"}); err != nil {
		t.Fatal(err)
	}
	got := store.list("alice@example.com")
	if len(got) != 2 || got[0].Sender != "newer@example.net" || got[1].Sender != "older@example.net" {
		t.Fatalf("history order = %#v", got)
	}
}

func TestRejectionHistoryWildcardAndFormatting(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 34, 56, 0, time.UTC)
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.now = func() time.Time { return now }
	if err := store.add("news@example.net", "", []string{"alice@example.com", "bob@example.com"}, []string{"Phishing link", "Impersonated sender"}); err != nil {
		t.Fatal(err)
	}
	entries := store.list("*")
	if len(entries) != 2 {
		t.Fatalf("wildcard history count = %d", len(entries))
	}
	formatted := formatRejectionHistory(entries)
	for _, want := range []string{
		"From: news@example.net\nTo: alice@example.com\nDate: 2026-09-03 12:34:56 UTC\nReason: Phishing link; Impersonated sender\n\n",
		"From: news@example.net\nTo: bob@example.com\nDate: 2026-09-03 12:34:56 UTC\nReason: Phishing link; Impersonated sender\n\n",
	} {
		if !strings.Contains(formatted, want) {
			t.Errorf("formatted history missing %q: %s", want, formatted)
		}
	}
}

func TestRejectionReasonIsSingleLineAndBounded(t *testing.T) {
	reason := rejectionReason([]string{"first\nreason", strings.Repeat("x", maxRejectionReasonRunes+100)})
	if strings.ContainsAny(reason, "\r\n\t") {
		t.Fatalf("reason contains control whitespace: %q", reason)
	}
	if got := len([]rune(reason)); got != maxRejectionReasonRunes+1 {
		t.Fatalf("bounded reason length = %d", got)
	}
}

func TestRejectionHistoryReadLimitScalesWithConfiguredEntries(t *testing.T) {
	const maxEntries = 10000
	want := int64(maxEntries) * estimatedRejectionHistoryEntryBytes * persistentStoreReadMargin
	if got := persistentStoreReadLimit(maxEntries, estimatedRejectionHistoryEntryBytes); got != want {
		t.Fatalf("read limit = %d, want %d", got, want)
	}
}
