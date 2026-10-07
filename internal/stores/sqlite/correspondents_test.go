package sqlite

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func newCorrespondentRepository(options CorrespondentOptions, database *sqlitedb.Store, log *slog.Logger) *correspondentRepository {
	return NewCorrespondents(database, options, log).(*correspondentRepository)
}

func recordInboundClassification(repository *correspondentRepository, ctx context.Context, correspondent string, recipients []string, complete bool, verdict stores.InboundVerdict, score, minimum float64, aligned bool) error {
	return repository.RecordInboundClassification(ctx, stores.InboundClassification{Correspondent: correspondent, Recipients: recipients,
		RecipientsComplete: complete, Verdict: verdict, Score: score, UnwantedMinScore: minimum, AuthenticationSatisfied: aligned})
}

func matchCorrespondent(t *testing.T, repository *correspondentRepository, ctx context.Context, correspondent string, recipients []string) stores.CorrespondentMatch {
	t.Helper()
	result, err := repository.Match(ctx, correspondent, recipients)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func listCorrespondents(repository *correspondentRepository, ctx context.Context, recipient string, since time.Time) ([]stores.Correspondent, error) {
	scope := stores.RecipientScope{Address: recipient}
	if recipient == "*" {
		scope = stores.RecipientScope{All: true}
	}
	page, err := repository.ListCorrespondents(ctx, stores.CorrespondentListQuery{Recipients: scope, ActiveSince: since, Limit: 1000})
	return page.Entries, err
}

func correspondentSnapshot(t *testing.T, repository *correspondentRepository) map[string]stores.Correspondent {
	t.Helper()
	result := make(map[string]stores.Correspondent)
	rows, err := repository.db.Query(context.Background(), `SELECT id, local_address, correspondent,
		learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count FROM correspondents`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		entry, err := scanCorrespondent(rows)
		if err != nil {
			t.Fatal(err)
		}
		result[entry.LocalAddress+"\x00"+entry.Correspondent] = entry
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func testCorrespondentDatabase(t *testing.T, path string) *sqlitedb.Store {
	t.Helper()
	database, err := sqlitedb.Open(context.Background(), path, sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func newTestCorrespondentRepository(t *testing.T, cfg CorrespondentOptions, log *slog.Logger) *correspondentRepository {
	t.Helper()
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	return newCorrespondentRepository(cfg, database, log)
}

func putTestCorrespondent(t *testing.T, repository *correspondentRepository, entry stores.Correspondent) {
	t.Helper()
	_, err := repository.db.Exec(context.Background(), `INSERT INTO correspondents
		(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
		VALUES (?, ?, ?, ?, ?, ?)`, entry.LocalAddress, entry.Correspondent, unixMillis(entry.LearnedAt),
		unixMillis(entry.LastActivityAt), entry.CorrespondentType, entry.LegitimateEmailCount)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCorrespondentStorePersistsPerSenderRelationships(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	cfg := CorrespondentOptions{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 10}
	database := testCorrespondentDatabase(t, path)
	store := newCorrespondentRepository(cfg, database, slog.Default())
	if err := store.LearnAuthenticated(context.Background(), "Owner@Example.COM", []string{"Alice@Example.net", "alice@example.net", "invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := testCorrespondentDatabase(t, path)
	reloaded := newCorrespondentRepository(cfg, reopened, slog.Default())
	if match := matchCorrespondent(t, reloaded, context.Background(), "alice@example.net", []string{"owner@example.com"}); !match.Known || !match.AllRecipientsMatched {
		t.Fatalf("saved relationship did not reload: %#v", match)
	}
	if match := matchCorrespondent(t, reloaded, context.Background(), "alice@example.net", []string{"other@example.com"}); match.Known {
		t.Fatalf("per-sender relationship leaked to another user: %#v", match)
	}
}

func TestManualCorrespondentOperationsRequireAvailableAllowlist(t *testing.T) {
	tests := []struct {
		name  string
		store *correspondentRepository
	}{
		{name: "nil store"},
		{name: "nil database", store: newCorrespondentRepository(CorrespondentOptions{UseAllowlist: true}, nil, nil)},
		{name: "allowlist disabled", store: newTestCorrespondentRepository(t, CorrespondentOptions{MaxEntries: 10}, nil)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.store.AddManual(context.Background(), "sender@example.net", "owner@example.com"); err == nil || !strings.Contains(err.Error(), "disabled or unavailable") {
				t.Fatalf("add error = %v", err)
			}
			if _, err := test.store.DeleteCorrespondent(context.Background(), "sender@example.net", stores.RecipientScope{Address: "owner@example.com"}); err == nil || !strings.Contains(err.Error(), "disabled or unavailable") {
				t.Fatalf("delete error = %v", err)
			}
		})
	}
}

func TestCorrespondentPolicyRejectsInvalidVocabulary(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "invalid", MaxEntries: 10,
	}, nil)
	ctx := context.Background()
	if err := store.LearnAuthenticated(ctx, "owner@example.com", []string{"sender@example.net"}); err == nil {
		t.Fatal("LearnAuthenticated accepted an invalid correspondent scope")
	}
	if err := store.TouchInbound(ctx, "sender@example.net", []string{"owner@example.com"}); err == nil {
		t.Fatal("TouchInbound accepted an invalid correspondent scope")
	}
	if _, err := store.Match(ctx, "sender@example.net", []string{"owner@example.com"}); err == nil {
		t.Fatal("Match accepted an invalid correspondent scope")
	}
	if err := store.RecordInboundClassification(ctx, stores.InboundClassification{
		Correspondent: "sender@example.net", Recipients: []string{"owner@example.com"}, RecipientsComplete: true,
		Verdict: stores.InboundVerdictLegitimate, Score: 1,
	}); err == nil {
		t.Fatal("RecordInboundClassification accepted an invalid correspondent scope")
	}

	store.options.Scope = stores.CorrespondentScopePerSender
	if err := store.RecordInboundClassification(ctx, stores.InboundClassification{
		Correspondent: "sender@example.net", Recipients: []string{"owner@example.com"}, RecipientsComplete: true,
		Verdict: "invalid", Score: 1,
	}); err == nil {
		t.Fatal("RecordInboundClassification accepted an invalid verdict")
	}
}

func TestAddManualCreatesAndConvertsExistingCorrespondents(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{UseAllowlist: true, MaxEntries: 10}, nil)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	created, err := store.AddManual(context.Background(), "New@Example.NET", "Owner@Example.COM")
	if err != nil || !created {
		t.Fatalf("new manual correspondent created=%t, err=%v", created, err)
	}
	createdEntry := correspondentSnapshot(t, store)["owner@example.com\x00new@example.net"]
	if createdEntry.CorrespondentType != stores.CorrespondentKindManual || createdEntry.LegitimateEmailCount != 0 ||
		!createdEntry.LearnedAt.Equal(now) || !createdEntry.LastActivityAt.Equal(now) {
		t.Fatalf("new manual correspondent=%+v", createdEntry)
	}

	learnedAt := now.Add(-48 * time.Hour)
	putTestCorrespondent(t, store, stores.Correspondent{
		LocalAddress: "other@example.com", Correspondent: "candidate@example.net",
		CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 2,
		LearnedAt: learnedAt, LastActivityAt: now.Add(-24 * time.Hour),
	})
	now = now.Add(time.Hour)
	created, err = store.AddManual(context.Background(), "Candidate@Example.NET", "Other@Example.COM")
	if err != nil || created {
		t.Fatalf("existing manual correspondent created=%t, err=%v", created, err)
	}
	records := correspondentSnapshot(t, store)
	converted := records["other@example.com\x00candidate@example.net"]
	if len(records) != 2 || converted.CorrespondentType != stores.CorrespondentKindManual || converted.LegitimateEmailCount != 0 ||
		!converted.LearnedAt.Equal(learnedAt) || !converted.LastActivityAt.Equal(now) {
		t.Fatalf("converted manual correspondent=%+v records=%d", converted, len(records))
	}
}

func TestDeleteCorrespondentHonorsRecipientScope(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{UseAllowlist: true, MaxEntries: 10}, nil)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	for _, entry := range []stores.Correspondent{
		{LocalAddress: "first@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now, LastActivityAt: now},
		{LocalAddress: "second@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now, LastActivityAt: now},
		{LocalAddress: "first@example.com", Correspondent: "unrelated@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now, LastActivityAt: now},
	} {
		putTestCorrespondent(t, store, entry)
	}

	removed, err := store.DeleteCorrespondent(context.Background(), "Sender@Example.NET", stores.RecipientScope{Address: "First@Example.COM"})
	if err != nil || removed != 1 {
		t.Fatalf("recipient deletion removed=%d, err=%v", removed, err)
	}
	records := correspondentSnapshot(t, store)
	if _, found := records["first@example.com\x00sender@example.net"]; found {
		t.Fatal("recipient-scoped deletion retained its target")
	}
	if _, found := records["second@example.com\x00sender@example.net"]; !found {
		t.Fatal("recipient-scoped deletion removed another recipient's relationship")
	}
	if _, found := records["first@example.com\x00unrelated@example.net"]; !found {
		t.Fatal("recipient-scoped deletion removed an unrelated correspondent")
	}

	removed, err = store.DeleteCorrespondent(context.Background(), "sender@example.net", stores.RecipientScope{All: true})
	if err != nil || removed != 1 {
		t.Fatalf("all-recipient deletion removed=%d, err=%v", removed, err)
	}
	records = correspondentSnapshot(t, store)
	if len(records) != 1 || records["first@example.com\x00unrelated@example.net"].Correspondent == "" {
		t.Fatalf("records after all-recipient deletion=%#v", records)
	}

	_, err = store.DeleteCorrespondent(context.Background(), "sender@example.net", stores.RecipientScope{})
	if err == nil || !strings.Contains(err.Error(), "invalid correspondent deletion scope") {
		t.Fatalf("invalid scope error=%v", err)
	}
}

func TestCorrespondentLearningRecipientLimit(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 1000,
	}, nil)
	recipients := make([]string, maxCorrespondentRecipients+10)
	for index := range recipients {
		recipients[index] = fmt.Sprintf("recipient-%d@example.net", index)
	}
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", recipients); err != nil {
		t.Fatal(err)
	}
	if records := correspondentSnapshot(t, store); len(records) != maxCorrespondentRecipients {
		t.Fatalf("learned records = %d, want %d", len(records), maxCorrespondentRecipients)
	}
}

func TestCorrespondentStoreScopeChangesOnlyMatching(t *testing.T) {
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	cfg := CorrespondentOptions{LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 10}
	store := newCorrespondentRepository(cfg, database, nil)
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	if match := matchCorrespondent(t, store, context.Background(), "alice@example.net", []string{"anyone@example.com"}); !match.Known {
		t.Fatalf("global relationship did not match: %#v", match)
	}
	cfg.Scope = "per_sender"
	perSender := newCorrespondentRepository(cfg, database, nil)
	if !matchCorrespondent(t, perSender, context.Background(), "alice@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("relationship was not retained under per-sender matching")
	}
	if matchCorrespondent(t, perSender, context.Background(), "alice@example.net", []string{"anyone@example.com"}).Known {
		t.Fatal("per-sender relationship leaked to another local address")
	}
}

func TestCorrespondentCleanupEvictsLeastUsefulAtCapacity(t *testing.T) {
	cfg := CorrespondentOptions{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "global", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99, MaxEntries: 2,
	}
	store := newTestCorrespondentRepository(t, cfg, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"trusted@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := recordInboundClassification(store, context.Background(), "candidate1@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := recordInboundClassification(store, context.Background(), "candidate2@example.net", []string{"owner@example.com"}, true, "legitimate", 1, .9, true); err != nil {
		t.Fatal(err)
	}
	if len(correspondentSnapshot(t, store)) != 3 {
		t.Fatal("capacity was enforced before periodic cleanup")
	}
	if _, err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !matchCorrespondent(t, store, context.Background(), "trusted@example.net", nil).Known {
		t.Fatal("candidate evicted qualified relationship")
	}
	if _, exists := correspondentSnapshot(t, store)["owner@example.com\x00candidate1@example.net"]; exists {
		t.Fatal("old unqualified candidate was not evicted first")
	}
}

func TestCorrespondentCleanupEvictsOldestQualifiedAtCapacity(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 2,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	for _, sender := range []string{"first@example.net", "second@example.net"} {
		if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{sender}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Hour)
	}
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"first@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"third@example.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !matchCorrespondent(t, store, context.Background(), "first@example.net", nil).Known || matchCorrespondent(t, store, context.Background(), "second@example.net", nil).Known || !matchCorrespondent(t, store, context.Background(), "third@example.net", nil).Known {
		t.Fatal("capacity eviction did not retain most recently active relationships")
	}
}

func TestCorrespondentStoreIgnoresAndCleansStaleRelationships(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "global", MaxEntries: 10,
		StaleAfter: 24 * time.Hour,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(25 * time.Hour)
	if matchCorrespondent(t, store, context.Background(), "alice@example.net", nil).Known {
		t.Fatal("stale relationship still matched")
	}
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"bob@example.net"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(correspondentSnapshot(t, store)) != 1 {
		t.Fatal("stale relationship was not removed during periodic cleanup")
	}
}

func TestCorrespondentActivityDoesNotResurrectStaleRelationship(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		UseAllowlist: true, Scope: "per_sender", MaxEntries: 10,
		StaleAfter: 24 * time.Hour,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	staleActivity := now.Add(-25 * time.Hour)
	putTestCorrespondent(t, store, stores.Correspondent{
		LocalAddress: "owner@example.com", Correspondent: "sender@example.net",
		CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-48 * time.Hour), LastActivityAt: staleActivity,
	})

	if err := store.TouchInbound(context.Background(), "sender@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	record := correspondentSnapshot(t, store)["owner@example.com\x00sender@example.net"]
	if !record.LastActivityAt.Equal(staleActivity) {
		t.Fatalf("stale activity was refreshed from %s to %s", staleActivity, record.LastActivityAt)
	}
	if match := matchCorrespondent(t, store, context.Background(), "sender@example.net", []string{"owner@example.com"}); match.Known {
		t.Fatalf("stale relationship was resurrected: %#v", match)
	}
	if deleted, err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("cleanup deleted %d stale relationships, want 1", deleted)
	}
	if len(correspondentSnapshot(t, store)) != 0 {
		t.Fatal("stale relationship remained after cleanup")
	}
}

func TestCorrespondentCleanupRemovesOnlyStaleRelationships(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		UseAllowlist: true, Scope: "global", MaxEntries: 10, StaleAfter: 24 * time.Hour,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "local@example.com", Correspondent: "stale@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-48 * time.Hour), LastActivityAt: now.Add(-25 * time.Hour)})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "local@example.com", Correspondent: "current@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-48 * time.Hour), LastActivityAt: now.Add(-23 * time.Hour)})
	if deleted, err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("deleted records = %d, want 1", deleted)
	}
	records := correspondentSnapshot(t, store)
	if len(records) != 1 || records["local@example.com\x00current@example.net"].Correspondent == "" {
		t.Fatalf("records after cleanup = %#v", records)
	}
}

func TestCorrespondentActivityUpdatesImmediately(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 10,
	}, nil)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"alice@example.net"}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := store.TouchInbound(context.Background(), "alice@example.net", []string{"owner@example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := correspondentSnapshot(t, store)["owner@example.com\x00alice@example.net"].LastActivityAt; !got.Equal(now) {
		t.Fatalf("activity = %s, want %s", got, now)
	}
}

func TestCorrespondentOutboundBatchPreservesRelationshipRules(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "per_sender",
		LegitimateSenderMinMessages:  3,
		StaleAfter:                   48 * time.Hour,
		MaxEntries:                   20,
	}, nil)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "owner@example.com", Correspondent: "manual@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour)})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "owner@example.com", Correspondent: "candidate@example.net", CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 2, LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour)})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "owner@example.com", Correspondent: "stale@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-96 * time.Hour), LastActivityAt: now.Add(-49 * time.Hour)})

	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{
		"manual@example.net", "candidate@example.net", "stale@example.net", "new@example.net",
	}); err != nil {
		t.Fatal(err)
	}
	records := correspondentSnapshot(t, store)
	if len(records) != 4 {
		t.Fatalf("batch learned %d relationships, want 4", len(records))
	}
	manual := records["owner@example.com\x00manual@example.net"]
	if manual.CorrespondentType != stores.CorrespondentKindManual || !manual.LastActivityAt.Equal(now) {
		t.Fatalf("manual relationship changed unexpectedly: %+v", manual)
	}
	for _, correspondent := range []string{"candidate@example.net", "stale@example.net", "new@example.net"} {
		entry := records["owner@example.com\x00"+correspondent]
		if entry.CorrespondentType != stores.CorrespondentKindAuthenticatedOutbound || entry.LegitimateEmailCount != 0 || !entry.LastActivityAt.Equal(now) {
			t.Errorf("outbound relationship %s = %+v", correspondent, entry)
		}
	}
	if stale := records["owner@example.com\x00stale@example.net"]; !stale.LearnedAt.Equal(now) {
		t.Fatalf("stale relationship was not recreated: %+v", stale)
	}
}

func TestCorrespondentOutboundLearningRollsBackOnInsertFailure(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true,
		UseAllowlist:                 true,
		Scope:                        "per_sender",
		LegitimateSenderMinMessages:  3,
		StaleAfter:                   48 * time.Hour,
		MaxEntries:                   20,
	}, nil)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	candidate := stores.Correspondent{
		LocalAddress: "owner@example.com", Correspondent: "candidate@example.net",
		CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 2,
		LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour),
	}
	stale := stores.Correspondent{
		LocalAddress: "owner@example.com", Correspondent: "stale@example.net",
		CorrespondentType: stores.CorrespondentKindManual,
		LearnedAt:         now.Add(-96 * time.Hour), LastActivityAt: now.Add(-49 * time.Hour),
	}
	putTestCorrespondent(t, store, candidate)
	putTestCorrespondent(t, store, stale)
	if _, err := store.db.Exec(context.Background(), `CREATE TRIGGER fail_outbound_correspondent BEFORE INSERT ON correspondents
		WHEN NEW.correspondent = 'fail@example.net' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}

	err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{
		"candidate@example.net", "stale@example.net", "fail@example.net",
	})
	if err == nil {
		t.Fatal("outbound learning insertion failure was ignored")
	}
	records := correspondentSnapshot(t, store)
	if len(records) != 2 {
		t.Fatalf("partially committed outbound records = %#v", records)
	}
	gotCandidate := records["owner@example.com\x00candidate@example.net"]
	if gotCandidate.CorrespondentType != candidate.CorrespondentType || gotCandidate.LegitimateEmailCount != candidate.LegitimateEmailCount ||
		!gotCandidate.LearnedAt.Equal(candidate.LearnedAt) || !gotCandidate.LastActivityAt.Equal(candidate.LastActivityAt) {
		t.Fatalf("candidate conversion was not rolled back: %+v", gotCandidate)
	}
	gotStale := records["owner@example.com\x00stale@example.net"]
	if gotStale.CorrespondentType != stale.CorrespondentType || !gotStale.LearnedAt.Equal(stale.LearnedAt) ||
		!gotStale.LastActivityAt.Equal(stale.LastActivityAt) {
		t.Fatalf("stale deletion was not rolled back: %+v", gotStale)
	}
}

func TestCorrespondentInboundBatchPreservesRelationshipRules(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnLegitimateSenders:      true,
		UseAllowlist:                true,
		Scope:                       "per_sender",
		LegitimateSenderMinMessages: 3,
		LegitimateSenderMinScore:    .9,
		StaleAfter:                  48 * time.Hour,
		MaxEntries:                  20,
	}, nil)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "candidate@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 2, LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour)})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "manual@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour)})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "stale@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now.Add(-96 * time.Hour), LastActivityAt: now.Add(-49 * time.Hour)})

	recipients := []string{"candidate@example.com", "manual@example.com", "stale@example.com", "new@example.com"}
	if err := recordInboundClassification(store, context.Background(), "sender@example.net", recipients, true, "legitimate", .95, .9, true); err != nil {
		t.Fatal(err)
	}
	records := correspondentSnapshot(t, store)
	if candidate := records["candidate@example.com\x00sender@example.net"]; candidate.LegitimateEmailCount != 3 {
		t.Fatalf("existing candidate was not promoted: %+v", candidate)
	}
	if !matchCorrespondent(t, store, context.Background(), "sender@example.net", []string{"candidate@example.com"}).Known {
		t.Fatal("promoted candidate was not matched by the production qualification query")
	}
	if manual := records["manual@example.com\x00sender@example.net"]; manual.CorrespondentType != stores.CorrespondentKindManual {
		t.Fatalf("manual relationship changed unexpectedly: %+v", manual)
	}
	for _, recipient := range []string{"stale@example.com", "new@example.com"} {
		entry := records[recipient+"\x00sender@example.net"]
		if entry.CorrespondentType != stores.CorrespondentKindRepeatedLegitimateInbound || entry.LegitimateEmailCount != 1 || !entry.LearnedAt.Equal(now) {
			t.Errorf("new inbound candidate for %s = %+v", recipient, entry)
		}
	}
}

func TestCorrespondentInboundLearningRollsBackOnInsertFailure(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnLegitimateSenders:      true,
		UseAllowlist:                true,
		Scope:                       "per_sender",
		LegitimateSenderMinMessages: 3,
		LegitimateSenderMinScore:    .9,
		StaleAfter:                  48 * time.Hour,
		MaxEntries:                  20,
	}, nil)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	candidate := stores.Correspondent{
		LocalAddress: "candidate@example.com", Correspondent: "sender@example.net",
		CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 2,
		LearnedAt: now.Add(-24 * time.Hour), LastActivityAt: now.Add(-time.Hour),
	}
	stale := stores.Correspondent{
		LocalAddress: "stale@example.com", Correspondent: "sender@example.net",
		CorrespondentType: stores.CorrespondentKindManual,
		LearnedAt:         now.Add(-96 * time.Hour), LastActivityAt: now.Add(-49 * time.Hour),
	}
	putTestCorrespondent(t, store, candidate)
	putTestCorrespondent(t, store, stale)
	if _, err := store.db.Exec(context.Background(), `CREATE TRIGGER fail_inbound_correspondent BEFORE INSERT ON correspondents
		WHEN NEW.local_address = 'fail@example.com' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}

	err := recordInboundClassification(store, context.Background(), "sender@example.net", []string{
		"candidate@example.com", "stale@example.com", "fail@example.com",
	}, true, "legitimate", .95, .9, true)
	if err == nil {
		t.Fatal("inbound learning insertion failure was ignored")
	}
	records := correspondentSnapshot(t, store)
	if len(records) != 2 {
		t.Fatalf("partially committed inbound records = %#v", records)
	}
	gotCandidate := records["candidate@example.com\x00sender@example.net"]
	if gotCandidate.CorrespondentType != candidate.CorrespondentType || gotCandidate.LegitimateEmailCount != candidate.LegitimateEmailCount ||
		!gotCandidate.LearnedAt.Equal(candidate.LearnedAt) || !gotCandidate.LastActivityAt.Equal(candidate.LastActivityAt) {
		t.Fatalf("candidate promotion was not rolled back: %+v", gotCandidate)
	}
	gotStale := records["stale@example.com\x00sender@example.net"]
	if gotStale.CorrespondentType != stale.CorrespondentType || !gotStale.LearnedAt.Equal(stale.LearnedAt) ||
		!gotStale.LastActivityAt.Equal(stale.LastActivityAt) {
		t.Fatalf("stale deletion was not rolled back: %+v", gotStale)
	}
}

func TestInboundLegitimateSenderCandidateLifecycle(t *testing.T) {
	cfg := CorrespondentOptions{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true, UseAllowlist: true,
		Scope: "per_sender", LegitimateSenderMinMessages: 3, LegitimateSenderMinScore: .99,
		LegitimateSenderRequireAuthentication: true, MaxEntries: 10,
	}
	store := newTestCorrespondentRepository(t, cfg, nil)
	record := func(verdict stores.InboundVerdict, score float64, dkim bool) {
		t.Helper()
		if err := recordInboundClassification(store, context.Background(), "news@example.net", []string{"owner@example.com"}, true, verdict, score, .9, dkim); err != nil {
			t.Fatal(err)
		}
	}
	record("legitimate", 1, false)
	if len(correspondentSnapshot(t, store)) != 0 {
		t.Fatal("message without required authentication created candidate")
	}
	record("legitimate", 1, true)
	key := "owner@example.com\x00news@example.net"
	if entry := correspondentSnapshot(t, store)[key]; entry.LegitimateEmailCount != 1 {
		t.Fatalf("first candidate = %#v", entry)
	}
	if matchCorrespondent(t, store, context.Background(), "news@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("unqualified first candidate was matched by the production qualification query")
	}
	record("legitimate", .9, true)
	record("unwanted", .89, true)
	if correspondentSnapshot(t, store)[key].LegitimateEmailCount != 1 {
		t.Fatal("neutral result changed candidate count")
	}
	record("legitimate", 1, true)
	record("legitimate", 1, true)
	if !matchCorrespondent(t, store, context.Background(), "news@example.net", []string{"owner@example.com"}).Known {
		t.Fatal("qualified inbound sender is not known")
	}
	record("unwanted", .9, true)
	if _, exists := correspondentSnapshot(t, store)[key]; exists {
		t.Fatal("unwanted classification did not remove learned candidate")
	}
	record("legitimate", 1, true)
	if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"news@example.net"}); err != nil {
		t.Fatal(err)
	}
	record("unwanted", 1, true)
	entry := correspondentSnapshot(t, store)[key]
	if entry.CorrespondentType != stores.CorrespondentKindAuthenticatedOutbound || entry.LegitimateEmailCount != 0 {
		t.Fatalf("authenticated outbound promotion = %#v", entry)
	}
}

func TestUnwantedClassificationRemovesOnlyRecipientScopedLearnedCorrespondent(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		UseAllowlist: true, Scope: "per_sender", MaxEntries: 10,
	}, nil)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	for _, entry := range []stores.Correspondent{
		{LocalAddress: "first@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 3, LearnedAt: now, LastActivityAt: now},
		{LocalAddress: "second@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 3, LearnedAt: now, LastActivityAt: now},
		{LocalAddress: "third@example.com", Correspondent: "sender@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: now, LastActivityAt: now},
	} {
		putTestCorrespondent(t, store, entry)
	}

	if err := recordInboundClassification(store, context.Background(), "sender@example.net", []string{"first@example.com", "third@example.com"}, true, "unwanted", .9, .9, false); err != nil {
		t.Fatal(err)
	}
	records := correspondentSnapshot(t, store)
	if _, found := records["first@example.com\x00sender@example.net"]; found {
		t.Fatal("recipient-scoped unwanted classification retained its learned correspondent")
	}
	if _, found := records["second@example.com\x00sender@example.net"]; !found {
		t.Fatal("recipient-scoped unwanted classification removed another recipient's learned correspondent")
	}
	if _, found := records["third@example.com\x00sender@example.net"]; !found {
		t.Fatal("unwanted classification removed a manual relationship for the same correspondent")
	}
}

func TestListAllowlistIsScopedQualifiedAndOrdered(t *testing.T) {
	cfg := CorrespondentOptions{UseAllowlist: true, Scope: "per_sender", MaxEntries: 10, LegitimateSenderMinMessages: 3}
	store := newTestCorrespondentRepository(t, cfg, nil)
	older := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "alice@example.com", Correspondent: "older@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: older, LastActivityAt: older})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "alice@example.com", Correspondent: "candidate@example.net", CorrespondentType: stores.CorrespondentKindRepeatedLegitimateInbound, LegitimateEmailCount: 1, LearnedAt: newer, LastActivityAt: newer})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "alice@example.com", Correspondent: "newer@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: newer, LastActivityAt: newer})
	putTestCorrespondent(t, store, stores.Correspondent{LocalAddress: "bob@example.com", Correspondent: "bob@example.net", CorrespondentType: stores.CorrespondentKindManual, LearnedAt: newer, LastActivityAt: newer})
	alice, err := listCorrespondents(store, context.Background(), "alice@example.com", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(alice) != 2 || alice[0].Correspondent != "newer@example.net" || alice[1].Correspondent != "older@example.net" {
		t.Fatalf("Alice allowlist = %#v", alice)
	}
	all, err := listCorrespondents(store, context.Background(), "*", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 ||
		all[0].LocalAddress != "alice@example.com" || all[0].Correspondent != "newer@example.net" ||
		all[1].LocalAddress != "bob@example.com" || all[1].Correspondent != "bob@example.net" ||
		all[2].LocalAddress != "alice@example.com" || all[2].Correspondent != "older@example.net" {
		t.Fatalf("global allowlist order = %#v", all)
	}
	recent, err := listCorrespondents(store, context.Background(), "*", newer)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 2 ||
		recent[0].LocalAddress != "alice@example.com" || recent[0].Correspondent != "newer@example.net" ||
		recent[1].LocalAddress != "bob@example.com" || recent[1].Correspondent != "bob@example.net" {
		t.Fatalf("recent allowlist order = %#v", recent)
	}
}

func TestCorrespondentConcurrentLearningIsAtomic(t *testing.T) {
	store := newTestCorrespondentRepository(t, CorrespondentOptions{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", MaxEntries: 100,
	}, nil)
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if err := store.LearnAuthenticated(context.Background(), "owner@example.com", []string{"friend@example.net"}); err != nil {
				t.Errorf("learn: %v", err)
			}
		}()
	}
	wait.Wait()
	if records := correspondentSnapshot(t, store); len(records) != 1 {
		t.Fatalf("concurrent learning created %d records", len(records))
	}
}
