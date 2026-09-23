package milter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type correspondentEntry = stores.Correspondent
type rejectionHistoryEntry = stores.Rejection
type domainRegistrationRecord = stores.DomainRegistration
type rejectedIPRecord struct {
	ID              uint64
	IP              string
	Strikes         []time.Time
	BlockLevel      string
	BlockedUntil    time.Time
	LegitimateCount int
	LastActivityAt  time.Time
}

func testRecipientScope(recipient string) stores.RecipientScope {
	if recipient == "*" {
		return stores.RecipientScope{All: true}
	}
	return stores.RecipientScope{Address: recipient}
}

// These adapters let the Milter integration tests exercise repository
// contracts while retaining direct SQL inspection for persistence assertions.
// Production code depends only on the interfaces in internal/stores.
type correspondentStore struct {
	stores.CorrespondentRepository
	db  *sqlitedb.Store
	now func() time.Time
	cfg config.CorrespondentsConfig
}

func newCorrespondentStore(cfg config.CorrespondentsConfig, db *sqlitedb.Store, log *slog.Logger) *correspondentStore {
	store := &correspondentStore{db: db, now: time.Now, cfg: cfg}
	store.CorrespondentRepository = newCorrespondentRepository(cfg, db, func() time.Time { return store.now() }, log)
	return store
}

func newTestCorrespondentStore(t *testing.T, cfg config.CorrespondentsConfig, log *slog.Logger) *correspondentStore {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return newCorrespondentStore(cfg, db, log)
}

func (s *correspondentStore) qualified(entry correspondentEntry) bool {
	return entry.WhitelistType != whitelistRepeatedLegitimate || entry.LegitimateEmailCount >= s.cfg.LegitimateSenderMinMessages
}

type rejectionHistoryStore struct {
	stores.RejectionHistoryRepository
	now func() time.Time
}

type ipReputationTestState struct {
	db  *sqlitedb.Store
	now func() time.Time
}

var ipReputationTestStates sync.Map

func setIPTestClock(store *ipReputationStore, now func() time.Time) {
	state, ok := ipReputationTestStates.Load(store)
	if !ok {
		panic("IP reputation test store is not registered")
	}
	state.(*ipReputationTestState).now = now
}

func ipTestDatabase(store *ipReputationStore) *sqlitedb.Store {
	state, ok := ipReputationTestStates.Load(store)
	if !ok {
		panic("IP reputation test store is not registered")
	}
	return state.(*ipReputationTestState).db
}

func newRejectionHistoryStore(cfg config.RejectionHistoryConfig, db *sqlitedb.Store, log *slog.Logger) *rejectionHistoryStore {
	store := &rejectionHistoryStore{now: time.Now}
	store.RejectionHistoryRepository = newRejectionRepository(cfg, db, func() time.Time { return store.now() }, log)
	return store
}

func newTestRejectionHistoryStore(t *testing.T, cfg config.RejectionHistoryConfig) (*rejectionHistoryStore, *sqlitedb.Store) {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return newRejectionHistoryStore(cfg, db, nil), db
}

func rejectionEntries(t *testing.T, repository stores.RejectionHistoryRepository, recipient string) []rejectionHistoryEntry {
	t.Helper()
	page, err := repository.ListRejections(context.Background(), stores.RejectionListQuery{
		Recipients: testRecipientScope(recipient), Limit: admincmd.MaxListRows,
	})
	if err != nil {
		t.Fatal(err)
	}
	return page.Entries
}

const (
	testMaxCorrespondentRecipients = 100
	whitelistAuthenticatedOutbound = stores.CorrespondentKindAuthenticatedOutbound
	whitelistRepeatedLegitimate    = stores.CorrespondentKindRepeatedLegitimateInbound
	whitelistManual                = stores.CorrespondentKindManual
	rejectedIPBlockShort           = stores.IPBlockLevelShort
	rejectedIPBlockRepeat          = stores.IPBlockLevelRepeat
)

func testCorrespondentMatch(t *testing.T, repository stores.CorrespondentRepository, ctx context.Context, correspondent string, recipients []string) stores.CorrespondentMatch {
	t.Helper()
	result, err := repository.Match(ctx, correspondent, recipients)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func unixMillis(value time.Time) int64     { return value.UTC().UnixMilli() }
func timeFromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func (s *correspondentStore) learn(ctx context.Context, local string, recipients []string) error {
	return s.LearnAuthenticated(ctx, local, recipients)
}

func (s *correspondentStore) touchInbound(ctx context.Context, correspondent string, recipients []string) error {
	return s.TouchInbound(ctx, correspondent, recipients)
}

func (s *correspondentStore) recordInboundClassification(ctx context.Context, correspondent string, recipients []string, complete bool, classification string, score, minimum float64, aligned bool) error {
	return s.RecordInboundClassification(ctx, stores.InboundClassification{Correspondent: correspondent, Recipients: recipients,
		RecipientsComplete: complete, Classification: classification, Score: score, UnwantedMinScore: minimum, DKIMAligned: aligned})
}

func (s *correspondentStore) match(t *testing.T, ctx context.Context, correspondent string, recipients []string) stores.CorrespondentMatch {
	t.Helper()
	result, err := s.Match(ctx, correspondent, recipients)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func (s *correspondentStore) listAllowlist(ctx context.Context, recipient string, since time.Time) ([]stores.Correspondent, error) {
	page, err := s.ListCorrespondents(ctx, stores.CorrespondentListQuery{Recipients: testRecipientScope(recipient), ActiveSince: since, Limit: admincmd.MaxListRows})
	return page.Entries, err
}

func (s *correspondentStore) addManual(ctx context.Context, sender, recipient string) (bool, error) {
	if s == nil || s.CorrespondentRepository == nil {
		return false, fmt.Errorf("correspondent allowlist is disabled or unavailable")
	}
	return s.AddManual(ctx, sender, recipient)
}

func (s *correspondentStore) deleteCorrespondent(ctx context.Context, sender, recipient string) (int, error) {
	if s == nil || s.CorrespondentRepository == nil {
		return 0, fmt.Errorf("correspondent allowlist is disabled or unavailable")
	}
	return s.DeleteCorrespondent(ctx, sender, testRecipientScope(recipient))
}

func (s *correspondentStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }

func (s *rejectionHistoryStore) addWithID(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) (uint64, error) {
	return s.AddRejection(ctx, stores.NewRejection{VisibleSender: visible, EnvelopeSender: envelope, Subject: subject, Recipients: recipients, Reasons: reasons})
}
func (s *rejectionHistoryStore) add(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) error {
	_, err := s.addWithID(ctx, visible, envelope, subject, recipients, reasons)
	return err
}

func (s *rejectionHistoryStore) list(ctx context.Context, recipient string, since time.Time) ([]stores.Rejection, error) {
	page, err := s.ListRejections(ctx, stores.RejectionListQuery{Recipients: testRecipientScope(recipient), RejectedSince: since, Limit: admincmd.MaxListRows})
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
func (s *rejectionHistoryStore) size(t *testing.T, ctx context.Context) int {
	t.Helper()
	count, err := s.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func (s *ipReputationStore) recordLegitimate(t *testing.T, ctx context.Context, addr netip.Addr) {
	t.Helper()
	if err := s.RecordLegitimate(ctx, addr); err != nil {
		t.Fatal(err)
	}
}
func (s *ipReputationStore) cleanup(ctx context.Context) (int64, error) {
	return s.repository.(stores.PersistentIPReputationRepository).Cleanup(ctx)
}
func (s *ipReputationStore) size(t *testing.T, ctx context.Context) int {
	t.Helper()
	count, err := s.repository.(stores.PersistentIPReputationRepository).Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return count
}
func (s *ipReputationStore) manualAdd(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	return s.AddManualBlock(ctx, addr)
}
func (s *ipReputationStore) manualDelete(ctx context.Context, addr netip.Addr) (bool, error) {
	return s.Delete(ctx, addr)
}
func (s *ipReputationStore) listActive(ctx context.Context, since time.Time) ([]stores.IPBlock, error) {
	page, err := s.ListActiveBlocks(ctx, stores.IPBlockListQuery{ActiveSince: since, Limit: admincmd.MaxListRows})
	return page.Entries, err
}

func (s *domainRegistrationStore) get(ctx context.Context, domain string) (stores.DomainRegistration, bool, error) {
	return s.repository.DomainRegistration(ctx, domain)
}

func (s *domainRegistrationStore) put(ctx context.Context, record stores.DomainRegistration) error {
	return s.repository.PutDomainRegistration(ctx, record)
}

func (s *domainRegistrationStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }
func (s *domainRegistrationStore) size(t *testing.T, ctx context.Context) int {
	t.Helper()
	count, err := s.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func (s *correspondentStore) snapshot() map[string]correspondentEntry {
	result := make(map[string]correspondentEntry)
	if s == nil || s.db == nil {
		return result
	}
	rows, err := s.db.Query(context.Background(), `SELECT id, local_address, correspondent,
		learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count FROM correspondents`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var entry correspondentEntry
		var id, learnedAt, lastActivityAt int64
		if err := rows.Scan(&id, &entry.LocalAddress, &entry.Correspondent, &learnedAt,
			&lastActivityAt, &entry.WhitelistType, &entry.LegitimateEmailCount); err != nil {
			return result
		}
		entry.ID = uint64(id)
		entry.LearnedAt = timeFromMillis(learnedAt)
		entry.LastActivityAt = timeFromMillis(lastActivityAt)
		result[entry.LocalAddress+"\x00"+entry.Correspondent] = entry
	}
	if rows.Err() != nil {
		return map[string]correspondentEntry{}
	}
	return result
}

func (s *ipReputationStore) snapshot() map[netip.Addr]rejectedIPRecord {
	result := map[netip.Addr]rejectedIPRecord{}
	stateValue, ok := ipReputationTestStates.Load(s)
	if s == nil || !ok {
		return result
	}
	db := stateValue.(*ipReputationTestState).db
	rows, err := db.Query(context.Background(), `SELECT id,ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms FROM ip_reputation`)
	if err != nil {
		return result
	}
	for rows.Next() {
		var r rejectedIPRecord
		var id, activity int64
		var level sql.NullString
		var blocked sql.NullInt64
		if rows.Scan(&id, &r.IP, &level, &blocked, &r.LegitimateCount, &activity) != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		r.ID, r.BlockLevel, r.LastActivityAt = uint64(id), level.String, timeFromMillis(activity)
		if blocked.Valid {
			r.BlockedUntil = timeFromMillis(blocked.Int64)
		}
		addr, err := netip.ParseAddr(r.IP)
		if err != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		result[addr] = r
	}
	rows.Close()
	for addr, record := range result {
		strikeRows, err := db.Query(context.Background(), `SELECT struck_at_ms FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id`, record.ID)
		if err != nil {
			return map[netip.Addr]rejectedIPRecord{}
		}
		for strikeRows.Next() {
			var milliseconds int64
			if strikeRows.Scan(&milliseconds) != nil {
				strikeRows.Close()
				return map[netip.Addr]rejectedIPRecord{}
			}
			record.Strikes = append(record.Strikes, timeFromMillis(milliseconds))
		}
		strikeRows.Close()
		result[addr] = record
	}
	return result
}
