package sqlite

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	testMaxRejectionReasonRunes = 1000
	testMaxRejectionRecipients  = 100
)

type rejectionHistoryStore = rejectionRepository
type rejectionHistoryEntry = stores.Rejection

func newRejectionHistoryStore(options RejectionOptions, db *sqlitedb.Store, log *slog.Logger) *rejectionHistoryStore {
	return NewRejections(db, options, log).(*rejectionRepository)
}

func (s *rejectionHistoryStore) addWithID(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) (uint64, error) {
	return s.AddRejection(ctx, stores.NewRejection{VisibleSender: visible, EnvelopeSender: envelope, Subject: subject, Recipients: recipients, Reasons: reasons})
}
func (s *rejectionHistoryStore) add(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) error {
	_, err := s.addWithID(ctx, visible, envelope, subject, recipients, reasons)
	return err
}
func (s *rejectionHistoryStore) list(ctx context.Context, recipient string, since time.Time) ([]stores.Rejection, error) {
	scope := stores.RecipientScope{Address: recipient}
	if recipient == "*" {
		scope = stores.RecipientScope{All: true}
	}
	page, err := s.ListRejections(ctx, stores.RejectionListQuery{Recipients: scope, RejectedSince: since, Limit: 1000})
	return page.Entries, err
}
func (s *rejectionHistoryStore) getByID(ctx context.Context, id uint64, recipient string, admin bool) (stores.Rejection, bool, error) {
	scope := stores.RecipientScope{Address: recipient}
	if admin {
		scope = stores.RecipientScope{All: true}
	}
	return s.RejectionByID(ctx, id, scope)
}
func (s *rejectionHistoryStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }
func (s *rejectionHistoryStore) size(ctx context.Context) int {
	count, _ := s.Count(ctx)
	return count
}

func newTestRejectionHistoryStore(t *testing.T, cfg RejectionOptions) (*rejectionHistoryStore, *sqlitedb.Store) {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return newRejectionHistoryStore(cfg, db, nil), db
}

func rejectionEntries(t *testing.T, store stores.RejectionHistoryRepository, recipient string) []rejectionHistoryEntry {
	t.Helper()
	scope := stores.RecipientScope{Address: recipient}
	if recipient == "*" {
		scope = stores.RecipientScope{All: true}
	}
	page, err := store.ListRejections(context.Background(), stores.RejectionListQuery{Recipients: scope, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

func TestRejectionHistoryPersistsOneEventWithMultipleRecipients(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	cfg := RejectionOptions{Expiry: 24 * time.Hour, MaxEntries: 10}
	db, err := sqlitedb.Open(context.Background(), path, sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	store := newRejectionHistoryStore(cfg, db, nil)
	store.now = func() time.Time { return now }
	id, err := store.addWithID(context.Background(), "Sender <NEWS@Example.NET>", "bounce@example.net", "Account alert", []string{"Alice@Example.com", "bob@example.com", "alice@example.com"}, []string{"Credential theft link"})
	if err != nil || id == 0 {
		t.Fatalf("add ID = %d, err = %v", id, err)
	}
	alice := rejectionEntries(t, store, "alice@example.com")
	if len(alice) != 1 || alice[0].Sender != "news@example.net" || alice[0].Subject != "Account alert" || !alice[0].RejectedAt.Equal(now) {
		t.Fatalf("Alice history = %#v", alice)
	}
	all := rejectionEntries(t, store, "*")
	if len(all) != 1 || all[0].ID != id || !slices.Equal(all[0].Recipients, []string{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("all history = %#v", all)
	}
	if len(alice[0].Recipients) != 1 || alice[0].Recipients[0] != "alice@example.com" {
		t.Fatalf("recipient-specific history disclosed other recipients: %#v", alice)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(context.Background(), path, sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reloaded := newRejectionHistoryStore(cfg, reopened, nil)
	if got := rejectionEntries(t, reloaded, "bob@example.com"); len(got) != 1 || got[0].ID != id {
		t.Fatalf("reloaded history = %#v", got)
	}
}

func TestRejectionHistoryListAppliesRequestedCutoff(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	store, _ := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: 30 * 24 * time.Hour, MaxEntries: 10})
	store.now = func() time.Time { return now.Add(-8 * 24 * time.Hour) }
	if err := store.add(context.Background(), "old@example.net", "", "Old", []string{"local@example.com"}, []string{"unwanted"}); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now }
	if err := store.add(context.Background(), "new@example.net", "", "New", []string{"local@example.com"}, []string{"unwanted"}); err != nil {
		t.Fatal(err)
	}
	entries, err := store.list(context.Background(), "local@example.com", now.Add(-7*24*time.Hour))
	if err != nil || len(entries) != 1 || entries[0].Sender != "new@example.net" {
		t.Fatalf("recent history = %#v, %v", entries, err)
	}
}

func TestRejectionHistoryGetByIDEnforcesRecipientAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	store, _ := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: 24 * time.Hour, MaxEntries: 10})
	store.now = func() time.Time { return now }
	id, err := store.addWithID(context.Background(), "sender@example.net", "", "Subject", []string{"alice@example.com", "bob@example.com"}, []string{"Reason"})
	if err != nil {
		t.Fatal(err)
	}
	entry, found, err := store.getByID(context.Background(), id, "ALICE@example.com", false)
	if err != nil || !found || !slices.Equal(entry.Recipients, []string{"alice@example.com"}) {
		t.Fatalf("owner lookup = %#v, found=%v, err=%v", entry, found, err)
	}
	if _, found, err := store.getByID(context.Background(), id, "other@example.com", false); err != nil || found {
		t.Fatalf("unauthorized lookup: found=%v err=%v", found, err)
	}
	entry, found, err = store.getByID(context.Background(), id, "", true)
	if err != nil || !found || !slices.Equal(entry.Recipients, []string{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("administrator lookup = %#v, found=%v, err=%v", entry, found, err)
	}
	store.now = func() time.Time { return now.Add(24*time.Hour + time.Millisecond) }
	if _, found, err := store.getByID(context.Background(), id, "alice@example.com", false); err != nil || found {
		t.Fatalf("expired lookup: found=%v err=%v", found, err)
	}
	if _, found, err := store.getByID(context.Background(), id+1, "alice@example.com", false); err != nil || found {
		t.Fatalf("missing lookup: found=%v err=%v", found, err)
	}
}

func TestRejectionHistoryExpiryAndCapacityCascadeRecipients(t *testing.T) {
	base := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store, db := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 2})
	store.now = func() time.Time { return base }
	for _, sender := range []string{"one@example.net", "two@example.net", "three@example.net"} {
		if err := store.add(context.Background(), sender, "", "", []string{"alice@example.com"}, []string{"unwanted"}); err != nil {
			t.Fatal(err)
		}
		base = base.Add(time.Minute)
	}
	if got := rejectionEntries(t, store, "alice@example.com"); len(got) != 3 {
		t.Fatalf("history was bounded before periodic cleanup: %#v", got)
	}
	if deleted, err := store.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("capacity cleanup deleted %d records, want 1", deleted)
	}
	got := rejectionEntries(t, store, "alice@example.com")
	if len(got) != 2 || got[0].Sender != "three@example.net" || got[1].Sender != "two@example.net" {
		t.Fatalf("bounded history = %#v", got)
	}
	var orphanCount int
	if err := db.QueryRow(context.Background(), `SELECT COUNT(*) FROM rejection_recipients rr LEFT JOIN rejections r ON r.id = rr.rejection_id WHERE r.id IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		t.Fatalf("orphan recipients = %d, err = %v", orphanCount, err)
	}
	base = base.Add(2 * time.Hour)
	if got := rejectionEntries(t, store, "*"); len(got) != 0 {
		t.Fatalf("expired history visible = %#v", got)
	}
	if deleted, err := store.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 2 {
		t.Fatalf("deleted records = %d, want 2", deleted)
	}
	var recipientCount int
	if err := db.QueryRow(context.Background(), `SELECT COUNT(*) FROM rejection_recipients`).Scan(&recipientCount); err != nil || recipientCount != 0 {
		t.Fatalf("recipient rows after cleanup = %d, err = %v", recipientCount, err)
	}
}

func TestRejectionHistorySameTimestampUsesNewestIDFirst(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store, _ := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	store.now = func() time.Time { return now }
	for _, sender := range []string{"older@example.net", "newer@example.net"} {
		if err := store.add(context.Background(), sender, "", "", []string{"alice@example.com"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	got := rejectionEntries(t, store, "alice@example.com")
	if len(got) != 2 || got[0].Sender != "newer@example.net" || got[1].Sender != "older@example.net" {
		t.Fatalf("history order = %#v", got)
	}
}

func TestRejectionHistoryFormattingAndBounds(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 34, 56, 0, time.UTC)
	store, _ := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	store.now = func() time.Time { return now }
	if err := store.add(context.Background(), "news@example.net", "", "Urgent\naccount notice", []string{"alice@example.com", "bob@example.com"}, []string{"Phishing link", "Impersonated sender"}); err != nil {
		t.Fatal(err)
	}
	entry := rejectionEntries(t, store, "*")[0]
	if entry.Subject != "Urgent account notice" || entry.Reason != "Phishing link; Impersonated sender" {
		t.Fatalf("normalized entry = %#v", entry)
	}
	reason := rejectionReason([]string{"first\nreason", strings.Repeat("x", testMaxRejectionReasonRunes+100)})
	if strings.ContainsAny(reason, "\r\n\t") || len([]rune(reason)) != testMaxRejectionReasonRunes+1 {
		t.Fatalf("bounded reason = %q", reason)
	}
}

func TestRejectionHistoryCapsRecipientsPerRecord(t *testing.T) {
	store, _ := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	recipients := make([]string, testMaxRejectionRecipients+10)
	for i := range recipients {
		recipients[i] = fmt.Sprintf("recipient-%03d@example.com", i)
	}
	if err := store.add(context.Background(), "sender@example.com", "", "test", recipients, nil); err != nil {
		t.Fatal(err)
	}
	entries := rejectionEntries(t, store, "*")
	if len(entries) != 1 || len(entries[0].Recipients) != testMaxRejectionRecipients {
		t.Fatalf("stored entries = %#v", entries)
	}
}

func TestRejectionHistoryConcurrentInsertions(t *testing.T) {
	const count = 20
	store, db := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: count})
	var wg sync.WaitGroup
	errs := make(chan error, count)
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.addWithID(context.Background(), fmt.Sprintf("sender-%d@example.net", i), "", "test", []string{"local@example.com"}, nil)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if entries := rejectionEntries(t, store, "*"); len(entries) != count {
		t.Fatalf("entry count = %d", len(entries))
	}
	var orphanCount int
	if err := db.QueryRow(context.Background(), `SELECT COUNT(*) FROM rejection_recipients rr LEFT JOIN rejections r ON r.id = rr.rejection_id WHERE r.id IS NULL`).Scan(&orphanCount); err != nil || orphanCount != 0 {
		t.Fatalf("orphan recipients = %d, err = %v", orphanCount, err)
	}
}

func TestRejectionHistoryRollsBackParentWhenRecipientInsertFails(t *testing.T) {
	store, db := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	if _, err := db.Exec(context.Background(), `CREATE TRIGGER reject_recipient BEFORE INSERT ON rejection_recipients
		WHEN NEW.recipient = 'fail@example.com' BEGIN SELECT RAISE(ABORT, 'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := store.add(context.Background(), "sender@example.net", "", "test", []string{"ok@example.com", "fail@example.com"}, nil); err == nil {
		t.Fatal("recipient insertion failure was ignored")
	}
	if got := store.size(context.Background()); got != 0 {
		t.Fatalf("partially committed rejection count = %d", got)
	}
}

func TestRejectionHistoryRecipientLookupUsesIndex(t *testing.T) {
	_, db := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	rows, err := db.Query(context.Background(), `EXPLAIN QUERY PLAN SELECT r.id
		FROM rejection_recipients rr JOIN rejections r ON r.id = rr.rejection_id
		WHERE rr.recipient = ? AND r.rejected_at_ms >= ?
		ORDER BY r.rejected_at_ms DESC, r.id DESC`, "local@example.com", int64(0))
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
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "rejection_recipients_recipient_idx") {
		t.Fatalf("query plan does not use recipient index: %s", plan)
	}
}

func TestRejectionHistoryListReportsDatabaseFailure(t *testing.T) {
	store, db := newTestRejectionHistoryStore(t, RejectionOptions{Expiry: time.Hour, MaxEntries: 10})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.list(context.Background(), "local@example.com", time.Time{}); err == nil {
		t.Fatal("closed database was reported as empty history")
	}
}
