package sqlite

import (
	"context"
	"path/filepath"
	"slices"
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
