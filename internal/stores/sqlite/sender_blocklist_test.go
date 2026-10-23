package sqlite

import (
	"context"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func newTestSenderBlocklist(t *testing.T, now *time.Time, maxEntries int) stores.SenderBlocklistRepository {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewSenderBlocklist(db, SenderBlocklistOptions{
		Expiry: 24 * time.Hour, MaxEntries: maxEntries, Now: func() time.Time { return *now },
	})
}

func addSenderBlock(t *testing.T, repository stores.SenderBlocklistRepository, recipient string, kind stores.SenderBlockKind, value string) stores.SenderBlockEntry {
	t.Helper()
	_, entry, err := repository.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: recipient, SenderKind: kind, SenderValue: value,
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestSenderBlocklistNormalizesRefreshesAndLists(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	repository := newTestSenderBlocklist(t, &now, 10)
	created, first, err := repository.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: "Alice@Local.Example", SenderKind: stores.SenderBlockExactMailbox, SenderValue: "Fred@Example.COM",
	})
	if err != nil || !created {
		t.Fatalf("first add = created %t, entry %+v, err %v", created, first, err)
	}
	now = now.Add(time.Hour)
	created, refreshed, err := repository.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: "alice@local.example", SenderKind: stores.SenderBlockExactMailbox, SenderValue: "fred@example.com",
	})
	if err != nil || created || refreshed.ID != first.ID || !refreshed.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("refresh = created %t, entry %+v, err %v", created, refreshed, err)
	}
	page, err := repository.ListSenderBlocks(context.Background(), stores.SenderBlockListQuery{
		Recipients: stores.RecipientScope{Address: "alice@local.example"}, Limit: 10,
	})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Pattern() != "fred@example.com" {
		t.Fatalf("list = %+v, err %v", page, err)
	}
}

func TestSenderBlocklistSetMatchDeduplicatesScopesAndPatterns(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	repository := newTestSenderBlocklist(t, &now, 20)
	addSenderBlock(t, repository, "alice@local.example", stores.SenderBlockExactMailbox, "fred@mail.example.com")
	addSenderBlock(t, repository, "alice@local.example", stores.SenderBlockDomain, "example.com")
	addSenderBlock(t, repository, "*", stores.SenderBlockDomain, "example.com")

	match, err := repository.MatchSenderBlocks(context.Background(), stores.SenderBlockMatchQuery{
		VisibleSenders: []string{"Fred@Mail.Example.COM", "other@elsewhere.example"},
		Recipients:     []string{"Alice@Local.Example", "bob@local.example"}, IncludeSubdomains: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(match.BlockedRecipients, []string{"alice@local.example", "bob@local.example"}) ||
		match.MatchedKind != stores.SenderBlockExactMailbox || match.MatchedSender != "fred@mail.example.com" {
		t.Fatalf("match = %+v", match)
	}
}

func TestSenderBlocklistSubdomainPolicyAndDomainBoundary(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	repository := newTestSenderBlocklist(t, &now, 10)
	addSenderBlock(t, repository, "alice@local.example", stores.SenderBlockDomain, "example.com")
	query := stores.SenderBlockMatchQuery{
		VisibleSenders: []string{"sender@mail.example.com"}, Recipients: []string{"alice@local.example"},
	}
	without, err := repository.MatchSenderBlocks(context.Background(), query)
	if err != nil || len(without.BlockedRecipients) != 0 {
		t.Fatalf("exact-domain mode match = %+v, err %v", without, err)
	}
	query.IncludeSubdomains = true
	with, err := repository.MatchSenderBlocks(context.Background(), query)
	if err != nil || len(with.BlockedRecipients) != 1 {
		t.Fatalf("subdomain mode match = %+v, err %v", with, err)
	}
	query.VisibleSenders = []string{"sender@notexample.com"}
	boundary, err := repository.MatchSenderBlocks(context.Background(), query)
	if err != nil || len(boundary.BlockedRecipients) != 0 {
		t.Fatalf("domain-boundary match = %+v, err %v", boundary, err)
	}
}

func TestSenderBlocklistExpiryDeletionAndCapacityCleanup(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	repository := newTestSenderBlocklist(t, &now, 2)
	addSenderBlock(t, repository, "a@local.example", stores.SenderBlockExactMailbox, "one@example.com")
	now = now.Add(time.Hour)
	addSenderBlock(t, repository, "a@local.example", stores.SenderBlockExactMailbox, "two@example.com")
	now = now.Add(time.Hour)
	addSenderBlock(t, repository, "a@local.example", stores.SenderBlockExactMailbox, "three@example.com")
	deleted, err := repository.Cleanup(context.Background())
	if err != nil || deleted != 1 {
		t.Fatalf("capacity cleanup deleted %d, err %v", deleted, err)
	}
	page, err := repository.ListSenderBlocks(context.Background(), stores.SenderBlockListQuery{
		Recipients: stores.RecipientScope{Address: "a@local.example"}, Limit: 10,
	})
	if err != nil || len(page.Entries) != 2 || page.Entries[0].SenderValue != "three@example.com" || page.Entries[1].SenderValue != "two@example.com" {
		t.Fatalf("post-capacity list = %+v, err %v", page, err)
	}
	now = now.Add(25 * time.Hour)
	match, err := repository.MatchSenderBlocks(context.Background(), stores.SenderBlockMatchQuery{
		VisibleSenders: []string{"two@example.com"}, Recipients: []string{"a@local.example"}, IncludeSubdomains: true,
	})
	if err != nil || len(match.BlockedRecipients) != 0 {
		t.Fatalf("expired match = %+v, err %v", match, err)
	}
	deleted, err = repository.Cleanup(context.Background())
	if err != nil || deleted != 2 {
		t.Fatalf("expiry cleanup deleted %d, err %v", deleted, err)
	}
}

func TestSenderBlocklistDeleteIsExactToScopeAndPattern(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	repository := newTestSenderBlocklist(t, &now, 10)
	addSenderBlock(t, repository, "alice@local.example", stores.SenderBlockDomain, "example.com")
	addSenderBlock(t, repository, "*", stores.SenderBlockDomain, "example.com")
	removed, err := repository.DeleteSenderBlocks(context.Background(), stores.SenderBlockDeleteQuery{
		SenderKind: stores.SenderBlockDomain, SenderValue: "example.com",
		Recipients: stores.RecipientScope{Address: "alice@local.example"},
	})
	if err != nil || removed != 1 {
		t.Fatalf("delete = %d, %v", removed, err)
	}
	page, err := repository.ListSenderBlocks(context.Background(), stores.SenderBlockListQuery{
		Recipients: stores.RecipientScope{All: true}, Limit: 10,
	})
	if err != nil || len(page.Entries) != 1 || page.Entries[0].Recipient != "*" {
		t.Fatalf("remaining entries = %+v, err %v", page, err)
	}
	removed, err = repository.DeleteSenderBlocks(context.Background(), stores.SenderBlockDeleteQuery{
		SenderKind: stores.SenderBlockDomain, SenderValue: "example.com",
		Recipients: stores.RecipientScope{Address: "*"},
	})
	if err != nil || removed != 1 {
		t.Fatalf("server-wide delete = %d, %v", removed, err)
	}
	addSenderBlock(t, repository, "*", stores.SenderBlockDomain, "example.com")
	addSenderBlock(t, repository, "bob@local.example", stores.SenderBlockDomain, "example.com")
	removed, err = repository.DeleteSenderBlocks(context.Background(), stores.SenderBlockDeleteQuery{
		SenderKind: stores.SenderBlockDomain, SenderValue: "example.com", Recipients: stores.RecipientScope{All: true},
	})
	if err != nil || removed != 2 {
		t.Fatalf("bulk delete = %d, %v", removed, err)
	}
}

func TestExactSenderBlockRemovesConflictingCorrespondents(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	correspondents := newCorrespondentRepository(CorrespondentOptions{UseAllowlist: true, MaxEntries: 10}, database, nil)
	blocks := NewSenderBlocklist(database, SenderBlocklistOptions{Expiry: 24 * time.Hour, MaxEntries: 10, Now: func() time.Time { return now }})
	for _, recipient := range []string{"first@example.com", "second@example.com"} {
		if _, err := correspondents.AddManual(context.Background(), "sender@example.net", recipient); err != nil {
			t.Fatal(err)
		}
	}

	if _, _, err := blocks.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: "first@example.com", SenderKind: stores.SenderBlockExactMailbox, SenderValue: "sender@example.net",
	}); err != nil {
		t.Fatal(err)
	}
	records := correspondentSnapshot(t, correspondents)
	if _, found := records["first@example.com\x00sender@example.net"]; found {
		t.Fatal("recipient-specific block retained the conflicting correspondent")
	}
	if _, found := records["second@example.com\x00sender@example.net"]; !found {
		t.Fatal("recipient-specific block removed another recipient's correspondent")
	}

	if _, _, err := blocks.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: "*", SenderKind: stores.SenderBlockExactMailbox, SenderValue: "sender@example.net",
	}); err != nil {
		t.Fatal(err)
	}
	if records := correspondentSnapshot(t, correspondents); len(records) != 0 {
		t.Fatalf("server-wide exact block retained correspondents: %+v", records)
	}
}

func TestDomainSenderBlockPreservesExactCorrespondents(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
	correspondents := newCorrespondentRepository(CorrespondentOptions{UseAllowlist: true, MaxEntries: 10}, database, nil)
	blocks := NewSenderBlocklist(database, SenderBlocklistOptions{Expiry: 24 * time.Hour, MaxEntries: 10, Now: func() time.Time { return now }})
	if _, err := correspondents.AddManual(context.Background(), "sender@example.net", "owner@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := blocks.AddSenderBlock(context.Background(), stores.SenderBlockEntry{
		Recipient: "owner@example.com", SenderKind: stores.SenderBlockDomain, SenderValue: "example.net",
	}); err != nil {
		t.Fatal(err)
	}
	if records := correspondentSnapshot(t, correspondents); len(records) != 1 {
		t.Fatalf("domain block removed exact correspondent: %+v", records)
	}
}

func TestManualSenderConflictChangesRollBackOnInsertFailure(t *testing.T) {
	for _, operation := range []string{"allow", "recipient block", "server-wide block"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			database := testCorrespondentDatabase(t, filepath.Join(t.TempDir(), "milterguard.db"))
			correspondents := newCorrespondentRepository(CorrespondentOptions{UseAllowlist: true, MaxEntries: 10}, database, nil)
			blocks := NewSenderBlocklist(database, SenderBlocklistOptions{Expiry: 24 * time.Hour, MaxEntries: 10})
			const sender = "sender@example.net"
			const recipient = "owner@example.com"
			table := "sender_blocklist"
			if operation == "allow" {
				addSenderBlock(t, blocks, recipient, stores.SenderBlockExactMailbox, sender)
				table = "correspondents"
			} else {
				for _, address := range []string{recipient, "other@example.com"} {
					if _, err := correspondents.AddManual(ctx, sender, address); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := correspondentSnapshot(t, correspondents)
			query := stores.SenderBlockListQuery{Recipients: stores.RecipientScope{All: true}, Limit: 10}
			beforeBlocks, err := blocks.ListSenderBlocks(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(ctx, "CREATE TRIGGER fail_conflict_insert BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT, 'injected conflict failure'); END"); err != nil {
				t.Fatal(err)
			}
			if operation == "allow" {
				_, err = correspondents.AddManual(ctx, sender, recipient)
			} else {
				scope := recipient
				if operation == "server-wide block" {
					scope = "*"
				}
				_, _, err = blocks.AddSenderBlock(ctx, stores.SenderBlockEntry{Recipient: scope, SenderKind: stores.SenderBlockExactMailbox, SenderValue: sender})
			}
			if err == nil || !strings.Contains(err.Error(), "injected conflict failure") {
				t.Fatalf("insert error = %v", err)
			}
			if after := correspondentSnapshot(t, correspondents); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed change altered correspondents: before=%+v after=%+v", before, after)
			}
			afterBlocks, err := blocks.ListSenderBlocks(ctx, query)
			if err != nil || !reflect.DeepEqual(beforeBlocks, afterBlocks) {
				t.Fatalf("failed change altered blocks: before=%+v after=%+v err=%v", beforeBlocks, afterBlocks, err)
			}
		})
	}
}
