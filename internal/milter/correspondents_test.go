package milter

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestCorrespondentStorePersistsPerSenderRelationships(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "per_sender",
		File:                         path,
		MaxEntries:                   10,
	}
	store := newCorrespondentStore(cfg, slog.Default())
	if err := store.learn("Owner@Example.COM", []string{"Alice@Example.net", "alice@example.net", "invalid"}); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, path); mode.Perm() != 0640 {
		t.Fatalf("database permissions = %o, want 0640", mode.Perm())
	}
	reloaded := newCorrespondentStore(cfg, slog.Default())
	if match := reloaded.match("alice@example.net", []string{"owner@example.com"}); !match.Known || !match.AllRecipientsMatched {
		t.Fatalf("saved relationship did not reload: %#v", match)
	}
	if match := reloaded.match("alice@example.net", []string{"other@example.com"}); match.Known {
		t.Fatalf("per-sender relationship leaked to another user: %#v", match)
	}
}

func TestCorrespondentStorePersistsRecordIDAndLastID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", LegitimateSenderMinMessages: 5,
		File: path, MaxEntries: 10,
	}
	store := newCorrespondentStore(cfg, slog.Default())
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	persisted := readCorrespondentFile(t, path)
	if persisted.Version != correspondentFileVersion || persisted.LastID != 1 || len(persisted.Entries) != 1 {
		t.Fatalf("persisted file = %#v", persisted)
	}
	if persisted.Entries[0].ID != 1 {
		t.Fatalf("persisted entry ID = %d", persisted.Entries[0].ID)
	}
}

func TestCorrespondentStoreScopeChangesOnlyMatching(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	globalConfig := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "global",
		File:                         path,
		MaxEntries:                   10,
	}
	store := newCorrespondentStore(globalConfig, slog.Default())
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	if match := store.match("alice@example.net", []string{"anyone@example.com"}); !match.Known || !match.AllRecipientsMatched {
		t.Fatalf("global relationship did not match: %#v", match)
	}

	perSenderConfig := globalConfig
	perSenderConfig.Scope = "per_sender"
	perSender := newCorrespondentStore(perSenderConfig, slog.Default())
	if match := perSender.match("alice@example.net", []string{"owner@example.com"}); !match.Known || !match.AllRecipientsMatched {
		t.Fatalf("relationship was not retained when switching to per-sender matching: %#v", match)
	}
	if match := perSender.match("alice@example.net", []string{"anyone@example.com"}); match.Known {
		t.Fatalf("global learning discarded the local sender relationship: %#v", match)
	}
}

func TestCorrespondentStoreEvictsOldestAtCapacity(t *testing.T) {
	store := newCorrespondentStore(config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "global",
		File:                         filepath.Join(t.TempDir(), "allowlist.json"),
		MaxEntries:                   1,
	}, slog.Default())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"first@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := store.learn("owner@example.com", []string{"second@example.net"}); err != nil {
		t.Fatal(err)
	}
	if store.match("first@example.net", nil).Known || !store.match("second@example.net", nil).Known {
		t.Fatal("capacity eviction did not retain the newest relationship")
	}
}

func TestCorrespondentStoreEvictsLeastRecentlyActive(t *testing.T) {
	store := newCorrespondentStore(config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global",
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 2,
	}, slog.Default())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"first@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.learn("owner@example.com", []string{"second@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.learn("owner@example.com", []string{"first@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.learn("owner@example.com", []string{"third@example.net"}); err != nil {
		t.Fatal(err)
	}
	if !store.match("first@example.net", nil).Known || store.match("second@example.net", nil).Known || !store.match("third@example.net", nil).Known {
		t.Fatal("capacity eviction did not retain the most recently active relationships")
	}
}

func TestCorrespondentStoreRemovesStaleRelationships(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	store := newCorrespondentStore(config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global",
		File: path, MaxEntries: 10, StaleAfter: config.Duration(24 * time.Hour),
	}, slog.Default())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if store.match("alice@example.net", nil).Known {
		t.Fatal("stale relationship still matched")
	}
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	if entries := readCorrespondentFile(t, path).Entries; len(entries) != 0 {
		t.Fatalf("persisted stale relationships = %d, want 0", len(entries))
	}
}

func TestCorrespondentActivityPersistenceIsThrottled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	store := newCorrespondentStore(config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender",
		File: path, MaxEntries: 10, ActivityUpdateInterval: config.Duration(24 * time.Hour),
	}, slog.Default())
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	initial := readCorrespondentFile(t, path).Entries[0].LastActivityAt
	now = now.Add(time.Hour)
	if err := store.touchInbound("alice@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	if persisted := readCorrespondentFile(t, path).Entries[0].LastActivityAt; !persisted.Equal(initial) {
		t.Fatalf("activity persisted before update interval: %s", persisted)
	}
	now = now.Add(24 * time.Hour)
	if err := store.touchInbound("alice@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	if persisted := readCorrespondentFile(t, path).Entries[0].LastActivityAt; !persisted.Equal(now) {
		t.Fatalf("persisted activity = %s, want %s", persisted, now)
	}
}

func TestInboundLegitimateSenderCandidateLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "per_sender", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99,
		LegitimateSenderRequireDKIM: true, File: path, MaxEntries: 10,
	}
	store := newCorrespondentStore(cfg, slog.Default())
	record := func(classification string, score float64, dkim bool) {
		t.Helper()
		if err := store.recordInboundClassification("news@example.net", []string{"owner@example.com"}, true, classification, score, .9, dkim); err != nil {
			t.Fatal(err)
		}
	}
	record("legitimate", 1, false)
	if len(store.entries) != 0 {
		t.Fatal("message without required DKIM created a candidate")
	}
	record("legitimate", 1, true)
	key := store.key("owner@example.com", "news@example.net")
	if entry := store.entries[key]; entry.LegitimateEmailCount != 1 || store.qualified(entry) {
		t.Fatalf("first candidate result = %#v", entry)
	}
	record("legitimate", .9, true)
	record("unwanted", .89, true)
	if count := store.entries[key].LegitimateEmailCount; count != 1 {
		t.Fatalf("neutral results changed count to %d", count)
	}
	record("legitimate", 1, true)
	record("legitimate", 1, true)
	if match := store.match("news@example.net", []string{"owner@example.com"}); !match.Known {
		t.Fatal("threshold-qualified inbound sender is not known")
	}
	record("unwanted", .89, true)
	if _, exists := store.entries[key]; !exists {
		t.Fatal("below-threshold unwanted classification deleted inbound-learned entry")
	}
	record("unwanted", .9, true)
	if _, exists := store.entries[key]; exists {
		t.Fatal("unwanted classification did not delete inbound-learned entry")
	}

	record("legitimate", 1, true)
	if err := store.learn("owner@example.com", []string{"news@example.net"}); err != nil {
		t.Fatal(err)
	}
	entry := store.entries[key]
	if entry.WhitelistType != whitelistAuthenticatedOutbound || entry.LegitimateEmailCount != 0 || !store.qualified(entry) {
		t.Fatalf("authenticated outbound promotion = %#v", entry)
	}
	record("unwanted", 1, true)
	if _, exists := store.entries[key]; !exists {
		t.Fatal("unwanted classification deleted authenticated-outbound entry")
	}
}

func TestCorrespondentCapacityEvictsCandidateBeforeQualifiedEntry(t *testing.T) {
	store := newCorrespondentStore(config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "per_sender", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99,
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 2,
	}, slog.Default())
	if err := store.learn("owner@example.com", []string{"trusted@example.net"}); err != nil {
		t.Fatal(err)
	}
	if err := store.recordInboundClassification("candidate1@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	if err := store.recordInboundClassification("candidate2@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	if !store.match("trusted@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("candidate evicted a qualified authenticated-outbound relationship")
	}
	if _, exists := store.entries[store.key("owner@example.com", "candidate1@example.net")]; exists {
		t.Fatal("old candidate was not evicted first")
	}
}

func TestManualCorrespondentManagement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	cfg := config.CorrespondentsConfig{
		UseAllowlist: true, Scope: "per_sender", LegitimateSenderMinMessages: 5,
		File: path, MaxEntries: 10,
	}
	created, err := AddManualCorrespondent(cfg, "News@Example.NET", "Owner@Example.COM")
	if err != nil || !created {
		t.Fatalf("manual add: created=%v err=%v", created, err)
	}
	created, err = AddManualCorrespondent(cfg, "news@example.net", "owner@example.com")
	if err != nil || created {
		t.Fatalf("manual update: created=%v err=%v", created, err)
	}
	data := readCorrespondentFile(t, path)
	if len(data.Entries) != 1 || data.Entries[0].WhitelistType != whitelistManual || data.Entries[0].LegitimateEmailCount != 0 {
		t.Fatalf("manual entry = %#v", data.Entries)
	}
	store := newCorrespondentStore(cfg, slog.Default())
	if !store.match("news@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("manual entry is not immediately qualified")
	}
	if _, err := AddManualCorrespondent(cfg, "news@example.net", "second@example.com"); err != nil {
		t.Fatal(err)
	}
	removed, err := DeleteCorrespondents(cfg, "news@example.net", "owner@example.com")
	if err != nil || removed != 1 {
		t.Fatalf("exact delete: removed=%d err=%v", removed, err)
	}
	removed, err = DeleteCorrespondents(cfg, "news@example.net", "*")
	if err != nil || removed != 1 {
		t.Fatalf("wildcard delete: removed=%d err=%v", removed, err)
	}
	if entries := readCorrespondentFile(t, path).Entries; len(entries) != 0 {
		t.Fatalf("entries remain after deletion: %#v", entries)
	}
}

func TestManualCorrespondentOverridesInboundCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	cfg := config.CorrespondentsConfig{
		LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender",
		LegitimateSenderMinMessages: 5, LegitimateSenderMinScore: .99,
		File: path, MaxEntries: 10,
	}
	store := newCorrespondentStore(cfg, slog.Default())
	if err := store.recordInboundClassification("news@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	if _, err := AddManualCorrespondent(cfg, "news@example.net", "owner@example.com"); err != nil {
		t.Fatal(err)
	}
	entry := readCorrespondentFile(t, path).Entries[0]
	if entry.WhitelistType != whitelistManual || entry.LegitimateEmailCount != 0 {
		t.Fatalf("candidate was not promoted to manual: %#v", entry)
	}
}

type correspondentTestFile struct {
	Version int                  `json:"version"`
	LastID  uint64               `json:"last_id"`
	Entries []correspondentEntry `json:"entries"`
}

func readCorrespondentFile(t *testing.T, path string) correspondentTestFile {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var data correspondentTestFile
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestListAllowlistIsRecipientScopedAndQualifiedOnly(t *testing.T) {
	cfg := config.CorrespondentsConfig{UseAllowlist: true, Scope: "per_sender", File: filepath.Join(t.TempDir(), "correspondents.json"), MaxEntries: 10, LegitimateSenderMinMessages: 3}
	store := newCorrespondentStore(cfg, nil)
	if _, err := store.addManual("z@example.net", "bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.addManual("a@example.net", "alice@example.com"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.entries[store.key("alice@example.com", "candidate@example.net")] = correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "candidate@example.net", WhitelistType: whitelistRepeatedLegitimate, LegitimateEmailCount: 1}
	store.mu.Unlock()
	alice := store.listAllowlist("alice@example.com")
	if len(alice) != 1 || alice[0].Correspondent != "a@example.net" {
		t.Fatalf("Alice allowlist = %#v", alice)
	}
	all := store.listAllowlist("*")
	if len(all) != 2 || all[0].LocalAddress != "alice@example.com" || all[1].LocalAddress != "bob@example.com" {
		t.Fatalf("global allowlist = %#v", all)
	}
}

func TestListAllowlistIsMostRecentlyActiveFirst(t *testing.T) {
	cfg := config.CorrespondentsConfig{UseAllowlist: true, Scope: "per_sender", File: filepath.Join(t.TempDir(), "correspondents.json"), MaxEntries: 10}
	store := newCorrespondentStore(cfg, nil)
	older := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	store.mu.Lock()
	store.entries[store.key("alice@example.com", "older@example.net")] = correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "older@example.net", WhitelistType: whitelistManual, LearnedAt: older, LastActivityAt: older}
	store.entries[store.key("alice@example.com", "newer@example.net")] = correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "newer@example.net", WhitelistType: whitelistManual, LearnedAt: newer, LastActivityAt: newer}
	store.mu.Unlock()
	got := store.listAllowlist("alice@example.com")
	if len(got) != 2 || got[0].Correspondent != "newer@example.net" || got[1].Correspondent != "older@example.net" {
		t.Fatalf("allowlist order = %#v", got)
	}
}

func TestCorrespondentStatisticsCountAffectedRecords(t *testing.T) {
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "per_sender",
		File:                         filepath.Join(t.TempDir(), "correspondents.json"),
		MaxEntries:                   10,
	}
	store := newCorrespondentStore(cfg, nil)
	store.enableDeferredPersistence()
	if err := store.learn("local@example.com", []string{"one@example.net", "two@example.net"}); err != nil {
		t.Fatal(err)
	}
	stats, err := store.db.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Writes != 2 || stats.Deletes != 0 {
		t.Fatalf("learning stats = %#v", stats)
	}
	if removed, err := store.deleteManual("one@example.net", "*"); err != nil || removed != 1 {
		t.Fatalf("delete = %d, %v", removed, err)
	}
	stats, err = store.db.Flush()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Writes != 0 || stats.Deletes != 1 {
		t.Fatalf("deletion stats = %#v", stats)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
