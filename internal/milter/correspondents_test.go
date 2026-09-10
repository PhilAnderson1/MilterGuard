package milter

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

func testCorrespondentDatabase(t *testing.T, path string) *sqlstore.Store {
	t.Helper()
	database, err := sqlstore.Open(context.Background(), path, sqlstore.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func newTestCorrespondentStore(t *testing.T, cfg config.CorrespondentsConfig, log *slog.Logger) *correspondentStore {
	t.Helper()
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	return newCorrespondentStore(cfg, database, log)
}

func putTestCorrespondent(t *testing.T, store *correspondentStore, entry correspondentEntry) {
	t.Helper()
	_, err := store.db.Exec(context.Background(), `INSERT INTO correspondents
		(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
		VALUES (?, ?, ?, ?, ?, ?)`, entry.LocalAddress, entry.Correspondent, unixMillis(entry.LearnedAt),
		unixMillis(entry.LastActivityAt), entry.WhitelistType, entry.LegitimateEmailCount)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCorrespondentStorePersistsPerSenderRelationships(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	cfg := config.CorrespondentsConfig{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 10}
	database := testCorrespondentDatabase(t, path)
	store := newCorrespondentStore(cfg, database, slog.Default())
	if err := store.learn("Owner@Example.COM", []string{"Alice@Example.net", "alice@example.net", "invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := testCorrespondentDatabase(t, path)
	reloaded := newCorrespondentStore(cfg, reopened, slog.Default())
	if match := reloaded.match("alice@example.net", []string{"owner@example.com"}); !match.Known || !match.AllRecipientsMatched {
		t.Fatalf("saved relationship did not reload: %#v", match)
	}
	if match := reloaded.match("alice@example.net", []string{"other@example.com"}); match.Known {
		t.Fatalf("per-sender relationship leaked to another user: %#v", match)
	}
}

func TestCorrespondentStoreScopeChangesOnlyMatching(t *testing.T) {
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	cfg := config.CorrespondentsConfig{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 10}
	store := newCorrespondentStore(cfg, database, nil)
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	if match := store.match("alice@example.net", []string{"anyone@example.com"}); !match.Known {
		t.Fatalf("global relationship did not match: %#v", match)
	}
	cfg.Scope = "per_sender"
	perSender := newCorrespondentStore(cfg, database, nil)
	if !perSender.match("alice@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("relationship was not retained under per-sender matching")
	}
	if perSender.match("alice@example.net", []string{"anyone@example.com"}).Known {
		t.Fatal("per-sender relationship leaked to another local address")
	}
}

func TestCorrespondentStoreEvictsLeastUsefulAtCapacity(t *testing.T) {
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "global", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99, MaxEntries: 2,
	}
	store := newTestCorrespondentStore(t, cfg, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"trusted@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.recordInboundClassification("candidate1@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.recordInboundClassification("candidate2@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	if !store.match("trusted@example.net", nil).Known {
		t.Fatal("candidate evicted qualified relationship")
	}
	if _, exists := store.snapshot()["owner@example.com\x00candidate1@example.net"]; exists {
		t.Fatal("old unqualified candidate was not evicted first")
	}
}

func TestCorrespondentStoreEvictsOldestQualifiedAtCapacity(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 2,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	for _, sender := range []string{"first@example.net", "second@example.net"} {
		if err := store.learn("owner@example.com", []string{sender}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	if err := store.learn("owner@example.com", []string{"first@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.learn("owner@example.com", []string{"third@example.net"}); err != nil {
		t.Fatal(err)
	}
	if !store.match("first@example.net", nil).Known || store.match("second@example.net", nil).Known || !store.match("third@example.net", nil).Known {
		t.Fatal("capacity eviction did not retain most recently active relationships")
	}
}

func TestCorrespondentStoreIgnoresAndCleansStaleRelationships(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 10,
		StaleAfter: config.Duration(24 * time.Hour),
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if store.match("alice@example.net", nil).Known {
		t.Fatal("stale relationship still matched")
	}
	if err := store.learn("owner@example.com", []string{"bob@example.net"}); err != nil {
		t.Fatal(err)
	}
	if len(store.snapshot()) != 1 {
		t.Fatal("stale relationship was not removed during write maintenance")
	}
}

func TestCorrespondentCleanupRemovesOnlyStaleRelationships(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		UseAllowlist: true, Scope: "global", MaxEntries: 10, StaleAfter: config.Duration(24 * time.Hour),
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "local@example.com", Correspondent: "stale@example.net", WhitelistType: whitelistManual, LearnedAt: now.Add(-48 * time.Hour), LastActivityAt: now.Add(-25 * time.Hour)})
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "local@example.com", Correspondent: "current@example.net", WhitelistType: whitelistManual, LearnedAt: now.Add(-48 * time.Hour), LastActivityAt: now.Add(-23 * time.Hour)})
	if deleted, err := store.cleanup(); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("deleted records = %d, want 1", deleted)
	}
	records := store.snapshot()
	if len(records) != 1 || records["local@example.com\x00current@example.net"].Correspondent == "" {
		t.Fatalf("records after cleanup = %#v", records)
	}
}

func TestCorrespondentActivityUpdatesAreThrottled(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 10,
		ActivityUpdateInterval: config.Duration(24 * time.Hour),
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.learn("owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	initial := store.snapshot()["owner@example.com\x00alice@example.net"].LastActivityAt
	now = now.Add(time.Hour)
	if err := store.touchInbound("alice@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := store.snapshot()["owner@example.com\x00alice@example.net"].LastActivityAt; !got.Equal(initial) {
		t.Fatalf("activity updated before interval: %s", got)
	}
	now = now.Add(24 * time.Hour)
	if err := store.touchInbound("alice@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := store.snapshot()["owner@example.com\x00alice@example.net"].LastActivityAt; !got.Equal(now) {
		t.Fatalf("activity = %s, want %s", got, now)
	}
}

func TestInboundLegitimateSenderCandidateLifecycle(t *testing.T) {
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "per_sender", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99,
		LegitimateSenderRequireDKIM: true, MaxEntries: 10,
	}
	store := newTestCorrespondentStore(t, cfg, nil)
	record := func(classification string, score float64, dkim bool) {
		t.Helper()
		if err := store.recordInboundClassification("news@example.net", []string{"owner@example.com"}, true, classification, score, .9, dkim); err != nil {
			t.Fatal(err)
		}
	}
	record("legitimate", 1, false)
	if len(store.snapshot()) != 0 {
		t.Fatal("message without required DKIM created candidate")
	}
	record("legitimate", 1, true)
	key := "owner@example.com\x00news@example.net"
	if entry := store.snapshot()[key]; entry.LegitimateEmailCount != 1 || store.qualified(entry) {
		t.Fatalf("first candidate = %#v", entry)
	}
	record("legitimate", .9, true)
	record("unwanted", .89, true)
	if store.snapshot()[key].LegitimateEmailCount != 1 {
		t.Fatal("neutral result changed candidate count")
	}
	record("legitimate", 1, true)
	record("legitimate", 1, true)
	if !store.match("news@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("qualified inbound sender is not known")
	}
	record("unwanted", .9, true)
	if _, exists := store.snapshot()[key]; exists {
		t.Fatal("unwanted classification did not remove learned candidate")
	}
	record("legitimate", 1, true)
	if err := store.learn("owner@example.com", []string{"news@example.net"}); err != nil {
		t.Fatal(err)
	}
	record("unwanted", 1, true)
	entry := store.snapshot()[key]
	if entry.WhitelistType != whitelistAuthenticatedOutbound || entry.LegitimateEmailCount != 0 {
		t.Fatalf("authenticated outbound promotion = %#v", entry)
	}
}

func TestManualCorrespondentManagement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	cfg := config.Config{
		Persistence:    config.PersistenceConfig{DatabaseFile: path},
		Correspondents: config.CorrespondentsConfig{UseAllowlist: true, Scope: "per_sender", LegitimateSenderMinMessages: 5, MaxEntries: 10},
	}
	created, err := AddManualCorrespondent(cfg, "News@Example.NET", "Owner@Example.COM")
	if err != nil || !created {
		t.Fatalf("manual add: created=%v err=%v", created, err)
	}
	created, err = AddManualCorrespondent(cfg, "news@example.net", "owner@example.com")
	if err != nil || created {
		t.Fatalf("manual update: created=%v err=%v", created, err)
	}
	database := testCorrespondentDatabase(t, path)
	store := newCorrespondentStore(cfg.Correspondents, database, nil)
	if !store.match("news@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("manual entry is not immediately qualified")
	}
	_ = database.Close()
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
}

func TestListAllowlistIsScopedQualifiedAndOrdered(t *testing.T) {
	cfg := config.CorrespondentsConfig{UseAllowlist: true, Scope: "per_sender", MaxEntries: 10, LegitimateSenderMinMessages: 3}
	store := newTestCorrespondentStore(t, cfg, nil)
	older := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "older@example.net", WhitelistType: whitelistManual, LearnedAt: older, LastActivityAt: older})
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "candidate@example.net", WhitelistType: whitelistRepeatedLegitimate, LegitimateEmailCount: 1, LearnedAt: newer, LastActivityAt: newer})
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "alice@example.com", Correspondent: "newer@example.net", WhitelistType: whitelistManual, LearnedAt: newer, LastActivityAt: newer})
	putTestCorrespondent(t, store, correspondentEntry{LocalAddress: "bob@example.com", Correspondent: "bob@example.net", WhitelistType: whitelistManual, LearnedAt: newer, LastActivityAt: newer})
	alice := store.listAllowlist("alice@example.com")
	if len(alice) != 2 || alice[0].Correspondent != "newer@example.net" || alice[1].Correspondent != "older@example.net" {
		t.Fatalf("Alice allowlist = %#v", alice)
	}
	if all := store.listAllowlist("*"); len(all) != 3 {
		t.Fatalf("global allowlist = %#v", all)
	}
}

func TestCorrespondentConcurrentLearningIsAtomic(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 100,
	}, nil)
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.learn("owner@example.com", []string{"friend@example.net"}); err != nil {
				t.Errorf("learn: %v", err)
			}
		}()
	}
	wait.Wait()
	if records := store.snapshot(); len(records) != 1 {
		t.Fatalf("concurrent learning created %d records", len(records))
	}
}

func TestCorrespondentLookupIndexes(t *testing.T) {
	store := newTestCorrespondentStore(t, config.CorrespondentsConfig{
		UseAllowlist: true, Scope: "per_sender", LegitimateSenderMinMessages: 3, MaxEntries: 100,
	}, nil)
	assertPlanUsesIndex := func(query, index string, args ...any) {
		t.Helper()
		rows, err := store.db.Query(context.Background(), "EXPLAIN QUERY PLAN "+query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var plan string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan += detail
		}
		if !strings.Contains(plan, index) {
			t.Fatalf("query plan %q does not use %s", plan, index)
		}
	}
	assertPlanUsesIndex(`SELECT id FROM correspondents WHERE local_address = ? AND correspondent = ?`,
		"sqlite_autoindex_correspondents_1", "local@example.com", "friend@example.net")
	assertPlanUsesIndex(`SELECT id FROM correspondents WHERE correspondent = ?`,
		"correspondents_correspondent_idx", "friend@example.net")
}
