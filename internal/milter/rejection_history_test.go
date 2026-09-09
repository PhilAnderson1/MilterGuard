package milter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestRejectionHistoryPersistsOneEventWithMultipleRecipientsAndExpires(t *testing.T) {
	now := time.Now().UTC()
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(24 * time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	store.now = func() time.Time { return now }
	if err := store.add("Sender <NEWS@Example.NET>", "bounce@example.net", "Account alert", []string{"Alice@Example.com", "bob@example.com", "alice@example.com"}, []string{"Credential theft link"}); err != nil {
		t.Fatal(err)
	}
	if got := store.list("alice@example.com"); len(got) != 1 || got[0].Sender != "news@example.net" || got[0].Subject != "Account alert" || !got[0].RejectedAt.Equal(now) {
		t.Fatalf("Alice history = %#v", got)
	}
	all := store.list("*")
	if len(all) != 1 || all[0].ID == 0 || len(all[0].Recipients) != 2 {
		t.Fatalf("rejection record IDs = %#v", all)
	}
	all[0].Recipients[0] = "mutated@example.invalid"
	if stored := store.list("*"); len(stored) != 1 || slices.Contains(stored[0].Recipients, "mutated@example.invalid") {
		t.Fatalf("returned recipients mutated rejection history: %#v", stored)
	}
	if got := store.list("alice@example.com"); len(got) != 1 || len(got[0].Recipients) != 1 || got[0].Recipients[0] != "alice@example.com" {
		t.Fatalf("recipient-specific history disclosed other recipients: %#v", got)
	}
	if got := store.list("carol@example.com"); len(got) != 0 {
		t.Fatalf("cross-recipient history exposed: %#v", got)
	}
	reloaded := newRejectionHistoryStore(cfg, nil)
	if got := reloaded.list("bob@example.com"); len(got) != 1 || got[0].ID == 0 {
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
		if err := store.add(sender, "", "", []string{"alice@example.com"}, []string{"Unwanted message"}); err != nil {
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
	if err := store.add("older@example.net", "", "Older subject", []string{"alice@example.com"}, []string{"Older reason"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := store.add("newer@example.net", "", "Newer subject", []string{"alice@example.com"}, []string{"Newer reason"}); err != nil {
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
	if err := store.add("news@example.net", "", "Urgent\naccount notice", []string{"alice@example.com", "bob@example.com"}, []string{"Phishing link", "Impersonated sender"}); err != nil {
		t.Fatal(err)
	}
	entries := store.list("*")
	if len(entries) != 1 {
		t.Fatalf("wildcard history count = %d", len(entries))
	}
	formatted := formatRejectionHistory(entries)
	want := "From: news@example.net\nTo: alice@example.com, bob@example.com\nSubject: Urgent account notice\nDate: 2026-09-03 12:34:56 UTC\nRejection ID: 1\nReason: Phishing link; Impersonated sender\n\n"
	if !strings.Contains(formatted, want) {
		t.Errorf("formatted history missing %q: %s", want, formatted)
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
	want := int64(maxEntries) * maximumRejectionHistoryEntryBytes * persistentStoreReadMargin
	if got := persistentStoreReadLimit(maxEntries, maximumRejectionHistoryEntryBytes); got != want {
		t.Fatalf("read limit = %d, want %d", got, want)
	}
}

func TestRejectionHistoryEntryBoundCoversMaximumRecord(t *testing.T) {
	address := strings.Repeat("a", 242) + "@example.com"
	recipients := make([]string, maxLearnedRecipients)
	for i := range recipients {
		recipients[i] = address
	}
	record := rejectionHistoryEntry{
		ID:         ^uint64(0),
		Sender:     address,
		Subject:    strings.Repeat("<", maxRejectionSubjectRunes) + "…",
		Recipients: recipients,
		RejectedAt: time.Now().UTC(),
		Reason:     strings.Repeat("<", maxRejectionReasonRunes) + "…",
	}
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(encoded)) > maximumRejectionHistoryEntryBytes {
		t.Fatalf("maximum encoded record is %d bytes, exceeds bound %d", len(encoded), maximumRejectionHistoryEntryBytes)
	}
}

func TestRejectionHistoryCapsRecipientsPerRecord(t *testing.T) {
	cfg := config.RejectionHistoryConfig{File: filepath.Join(t.TempDir(), "history.json"), Expiry: config.Duration(time.Hour), MaxEntries: 10}
	store := newRejectionHistoryStore(cfg, nil)
	recipients := make([]string, maxLearnedRecipients+10)
	for i := range recipients {
		recipients[i] = fmt.Sprintf("recipient-%03d@example.com", i)
	}
	if err := store.add("sender@example.com", "", "test subject", recipients, []string{"test"}); err != nil {
		t.Fatal(err)
	}
	entries := store.list("*")
	if len(entries) != 1 || len(entries[0].Recipients) != maxLearnedRecipients {
		t.Fatalf("stored recipient counts = %d entries, %d recipients", len(entries), len(entries[0].Recipients))
	}
}

func TestRejectionHistoryLoadPersistsNormalizedAddresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	document := struct {
		Version int                     `json:"version"`
		LastID  uint64                  `json:"last_id"`
		Entries []rejectionHistoryEntry `json:"entries"`
	}{
		Version: 1,
		LastID:  1,
		Entries: []rejectionHistoryEntry{{
			ID: 1, Sender: "Alice@Example.COM", Subject: "Account\nalert",
			Recipients: []string{"BOB@Example.COM", "bob@example.com"},
			RejectedAt: time.Now().UTC(),
		}},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	store := newRejectionHistoryStore(config.RejectionHistoryConfig{
		File: path, Expiry: config.Duration(time.Hour), MaxEntries: 10,
	}, nil)
	if store.loadErr != nil {
		t.Fatal(store.loadErr)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var normalized struct {
		Entries []rejectionHistoryEntry `json:"entries"`
	}
	if err := json.Unmarshal(persisted, &normalized); err != nil {
		t.Fatal(err)
	}
	if len(normalized.Entries) != 1 || normalized.Entries[0].Sender != "alice@example.com" || normalized.Entries[0].Subject != "Account alert" || !slices.Equal(normalized.Entries[0].Recipients, []string{"bob@example.com"}) {
		t.Fatalf("persisted normalized history = %#v", normalized.Entries)
	}
}
