package milter

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type fakeDomainRegistrationLookup struct {
	registered time.Time
	expires    time.Time
	err        error
	calls      atomic.Int32
}

type flakyDomainRegistrationRepository struct {
	stores.DomainRegistrationRepository
	writes int
	err    error
}

func (r *flakyDomainRegistrationRepository) PutDomainRegistration(ctx context.Context, record stores.DomainRegistration) error {
	r.writes++
	if r.writes == 1 {
		return r.err
	}
	return r.DomainRegistrationRepository.PutDomainRegistration(ctx, record)
}

var domainTestDatabases sync.Map

func TestDomainRegistrationFailurePruningExpiresAndBoundsEntries(t *testing.T) {
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	store := &domainRegistrationStore{
		maxSize: 3,
		failures: map[string]time.Time{
			"expired.example": now.Add(-time.Second),
			"one.example":     now.Add(time.Minute),
			"two.example":     now.Add(time.Minute),
			"three.example":   now.Add(time.Minute),
			"four.example":    now.Add(time.Minute),
		},
	}

	store.mu.Lock()
	store.pruneFailuresLocked(now)
	if _, found := store.failures["expired.example"]; found {
		store.mu.Unlock()
		t.Fatal("expired domain-registration failure was retained")
	}
	if got, want := len(store.failures), store.maxSize-1; got != want {
		store.mu.Unlock()
		t.Fatalf("failures after pruning = %d, want %d to leave insertion capacity", got, want)
	}
	store.failures["new.example"] = now.Add(domainRegistrationFailureRetry)
	got := len(store.failures)
	store.mu.Unlock()

	if got != store.maxSize {
		t.Fatalf("failures after insertion = %d, want configured maximum %d", got, store.maxSize)
	}
}

func TestDomainRegistrationCleanupHonorsCanceledContext(t *testing.T) {
	store := newTestDomainRegistrationStore(t, time.Now().UTC(), &fakeDomainRegistrationLookup{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.cleanup(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error = %v, want context cancellation", err)
	}
}

type blockingDomainRegistrationLookup struct {
	registered time.Time
	expires    time.Time
	started    chan struct{}
	release    chan struct{}
	calls      atomic.Int32
}

type panickingDomainRegistrationLookup struct{}

func (panickingDomainRegistrationLookup) Lookup(context.Context, string) (time.Time, time.Time, error) {
	panic("test RDAP panic")
}

func (f *blockingDomainRegistrationLookup) Lookup(ctx context.Context, _ string) (time.Time, time.Time, error) {
	if f.calls.Add(1) == 1 {
		close(f.started)
	}
	select {
	case <-f.release:
		return f.registered, f.expires, nil
	case <-ctx.Done():
		return time.Time{}, time.Time{}, ctx.Err()
	}
}

func (f *fakeDomainRegistrationLookup) Lookup(context.Context, string) (time.Time, time.Time, error) {
	f.calls.Add(1)
	return f.registered, f.expires, f.err
}

func newTestDomainRegistrationStore(t *testing.T, now time.Time, lookup domainRegistrationLookup) *domainRegistrationStore {
	return newTestDomainRegistrationStoreWithMax(t, now, lookup, 10)
}

func newTestDomainRegistrationStoreWithMax(t *testing.T, now time.Time, lookup domainRegistrationLookup, maxEntries int) *domainRegistrationStore {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.DomainRegistrationConfig{
		Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: maxEntries,
	}
	store := newDomainRegistrationStore(cfg, newDomainRepository(cfg, db, func() time.Time { return now }), lookup, slog.Default())
	store.now = func() time.Time { return now }
	domainTestDatabases.Store(store, db)
	t.Cleanup(func() { domainTestDatabases.Delete(store) })
	return store
}

func putTestDomainRegistration(t *testing.T, store *domainRegistrationStore, record domainRegistrationRecord) {
	t.Helper()
	if err := store.put(context.Background(), record); err != nil {
		t.Fatal(err)
	}
}

func TestDomainRegistrationLookupUsesRegistrableDomainAndCachesSuccess(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &fakeDomainRegistrationLookup{registered: now.Add(-3 * 24 * time.Hour), expires: now.Add(362 * 24 * time.Hour)}
	store := newTestDomainRegistrationStore(t, now, lookup)

	first, err := store.evidence(context.Background(), "mail.campaign.example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.evidence(context.Background(), "other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Available || !second.Available || first.Domain != "example.com" {
		t.Fatalf("unexpected evidence: first=%+v second=%+v", first, second)
	}
	if lookup.calls.Load() != 1 {
		t.Fatalf("RDAP calls = %d, want 1", lookup.calls.Load())
	}
}

func TestDomainRegistrationWithoutExpiryUsesTwoWeekCacheDeadline(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &fakeDomainRegistrationLookup{registered: now.Add(-3 * 24 * time.Hour)}
	store := newTestDomainRegistrationStore(t, now, lookup)
	current := now
	store.now = func() time.Time { return current }

	first, err := store.evidence(context.Background(), "example.com")
	if err != nil || !first.Available || !first.RegisteredAt.Equal(lookup.registered) {
		t.Fatalf("initial evidence = %+v, %v", first, err)
	}
	stored, found, err := store.repository.DomainRegistration(context.Background(), "example.com")
	if err != nil || !found || !stored.ExpiresAt.Equal(now.Add(domainRegistrationMissingExpiryCache)) {
		t.Fatalf("cached registration = %+v, found=%v, err=%v", stored, found, err)
	}
	current = now.Add(domainRegistrationMissingExpiryCache - time.Second)
	if _, err := store.evidence(context.Background(), "example.com"); err != nil || lookup.calls.Load() != 1 {
		t.Fatalf("unexpired fallback cache: calls=%d, err=%v", lookup.calls.Load(), err)
	}
	current = now.Add(domainRegistrationMissingExpiryCache)
	if _, err := store.evidence(context.Background(), "example.com"); err != nil || lookup.calls.Load() != 2 {
		t.Fatalf("expired fallback cache: calls=%d, err=%v", lookup.calls.Load(), err)
	}
}

func TestDomainRegistrationExpiredRecordRefreshesLazily(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &fakeDomainRegistrationLookup{registered: now.Add(-400 * 24 * time.Hour), expires: now.Add(330 * 24 * time.Hour)}
	store := newTestDomainRegistrationStore(t, now, lookup)
	putTestDomainRegistration(t, store, domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(-time.Hour)})

	info, err := store.evidence(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !info.RegisteredAt.Equal(lookup.registered) || lookup.calls.Load() != 1 {
		t.Fatalf("expired record was not refreshed: info=%+v calls=%d", info, lookup.calls.Load())
	}
}

func TestDomainRegistrationFailureIsTemporarilySuppressed(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &fakeDomainRegistrationLookup{err: errors.New("unavailable")}
	store := newTestDomainRegistrationStore(t, now, lookup)
	for range 2 {
		if info, _ := store.evidence(context.Background(), "example.com"); info.Available {
			t.Fatal("lookup failure produced domain evidence")
		}
	}
	if lookup.calls.Load() != 1 {
		t.Fatalf("RDAP calls = %d, want 1 during retry suppression", lookup.calls.Load())
	}
	if got := store.failures["example.com"]; !got.Equal(now.Add(domainRegistrationFailureRetry)) {
		t.Fatalf("retry at = %s, want %s", got, now.Add(domainRegistrationFailureRetry))
	}
}

func TestDomainRegistrationWriteFailureDoesNotSuppressLookup(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &fakeDomainRegistrationLookup{registered: now.Add(-24 * time.Hour), expires: now.Add(364 * 24 * time.Hour)}
	store := newTestDomainRegistrationStore(t, now, lookup)
	writeErr := errors.New("database busy")
	repository := &flakyDomainRegistrationRepository{DomainRegistrationRepository: store.repository, err: writeErr}
	store.repository = repository
	if _, err := store.evidence(context.Background(), "example.com"); !errors.Is(err, writeErr) {
		t.Fatalf("first lookup error = %v, want database error", err)
	}
	if retryAt := store.failures["example.com"]; !retryAt.IsZero() {
		t.Fatalf("database write failure suppressed RDAP until %s", retryAt)
	}
	if info, err := store.evidence(context.Background(), "example.com"); err != nil || !info.Available {
		t.Fatalf("retry after database recovery = %+v, %v", info, err)
	}
	if got := lookup.calls.Load(); got != 2 {
		t.Fatalf("RDAP calls = %d, want 2", got)
	}
}

func TestDomainRegistrationCallerCancellationDoesNotSuppressRetries(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &blockingDomainRegistrationLookup{
		registered: now.Add(-24 * time.Hour), expires: now.Add(364 * 24 * time.Hour),
		started: make(chan struct{}), release: make(chan struct{}),
	}
	store := newTestDomainRegistrationStore(t, now, lookup)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := store.evidence(ctx, "example.com")
		result <- err
	}()
	<-lookup.started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled lookup error = %v, want context cancellation", err)
	}
	if retryAt := store.failures["example.com"]; !retryAt.IsZero() {
		t.Fatalf("canceled lookup suppressed retries until %s", retryAt)
	}
	close(lookup.release)
	if info, err := store.evidence(context.Background(), "example.com"); err != nil || !info.Available {
		t.Fatalf("retry after cancellation = %+v, %v", info, err)
	}
}

func TestDomainRegistrationLookupDeadlineHasShortRetry(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &blockingDomainRegistrationLookup{
		started: make(chan struct{}), release: make(chan struct{}),
	}
	store := newTestDomainRegistrationStore(t, now, lookup)
	store.timeout = time.Millisecond
	if _, err := store.evidence(context.Background(), "example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup error = %v, want deadline exceeded", err)
	}
	if got := store.failures["example.com"]; !got.Equal(now.Add(domainRegistrationDeadlineRetry)) {
		t.Fatalf("retry at = %s, want %s", got, now.Add(domainRegistrationDeadlineRetry))
	}
}

func TestDomainRegistrationLookupPanicIsRecovered(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := newTestDomainRegistrationStore(t, now, panickingDomainRegistrationLookup{})
	if info, err := store.evidence(context.Background(), "example.com"); err == nil || info.Available {
		t.Fatalf("panic result = %+v, %v; want unavailable evidence and error", info, err)
	}
}

func TestDomainRegistrationSuppressesConcurrentDuplicateLookup(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	lookup := &blockingDomainRegistrationLookup{
		registered: now.Add(-24 * time.Hour), expires: now.Add(364 * 24 * time.Hour),
		started: make(chan struct{}), release: make(chan struct{}),
	}
	store := newTestDomainRegistrationStore(t, now, lookup)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			info, err := store.evidence(context.Background(), "mail.example.com")
			if err == nil && !info.Available {
				err = errors.New("domain evidence unavailable")
			}
			results <- err
		}()
	}
	<-lookup.started
	close(lookup.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if lookup.calls.Load() != 1 {
		t.Fatalf("concurrent RDAP calls = %d, want 1", lookup.calls.Load())
	}
}

func TestDomainRegistrationCleanupRemovesRecordsTwoWeeksPastExpiry(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := newTestDomainRegistrationStore(t, now, &fakeDomainRegistrationLookup{})
	for _, record := range []domainRegistrationRecord{
		{Domain: "expired.example", RegisteredAt: now.Add(-400 * 24 * time.Hour), ExpiresAt: now.Add(-15 * 24 * time.Hour)},
		{Domain: "grace.example", RegisteredAt: now.Add(-400 * 24 * time.Hour), ExpiresAt: now.Add(-13 * 24 * time.Hour)},
	} {
		putTestDomainRegistration(t, store, record)
	}
	if deleted, err := store.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("deleted records = %d, want 1", deleted)
	}
	if _, found, err := store.get(context.Background(), "expired.example"); err != nil || found {
		t.Fatal("record beyond expiry grace was retained")
	}
	if _, found, err := store.get(context.Background(), "grace.example"); err != nil || !found {
		t.Fatal("record within expiry grace was removed")
	}
}

func TestDisabledDomainRegistrationStillCleansExistingRecords(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := config.DomainRegistrationConfig{Enabled: false, Timeout: config.Duration(time.Second), MaxEntries: 10}
	store := newDomainRegistrationStore(cfg, newDomainRepository(cfg, db, func() time.Time { return now }), nil, slog.Default())
	putTestDomainRegistration(t, store, domainRegistrationRecord{
		Domain: "expired.example", RegisteredAt: now.Add(-400 * 24 * time.Hour), ExpiresAt: now.Add(-15 * 24 * time.Hour),
	})

	deleted, err := store.cleanup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("deleted records = %d, want 1", deleted)
	}
	if _, found, err := store.get(context.Background(), "expired.example"); err != nil || found {
		t.Fatalf("disabled domain-registration cleanup retained expired record: found=%t err=%v", found, err)
	}
}

func TestDomainRegistrationPersistsAndUpsertsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	db, err := sqlitedb.Open(context.Background(), path, sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DomainRegistrationConfig{Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10}
	store := newDomainRegistrationStore(cfg, newDomainRepository(cfg, db, time.Now), &fakeDomainRegistrationLookup{}, nil)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	first := domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(24 * time.Hour)}
	if err := store.put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	stored, found, err := store.get(context.Background(), "example.com")
	if err != nil || !found {
		t.Fatalf("initial record: found=%v, err=%v", found, err)
	}
	updated := domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-730 * 24 * time.Hour), ExpiresAt: now.Add(365 * 24 * time.Hour)}
	if err := store.put(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	stored, found, err = store.get(context.Background(), "example.com")
	if err != nil || !found || !stored.RegisteredAt.Equal(updated.RegisteredAt) || !stored.ExpiresAt.Equal(updated.ExpiresAt) {
		t.Fatalf("updated record = %+v, found=%v, err=%v", stored, found, err)
	}
	if count, err := store.Count(context.Background()); err != nil || count != 1 {
		t.Fatalf("records after upsert = %d, err=%v", count, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(context.Background(), path, sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reloaded := newDomainRegistrationStore(cfg, newDomainRepository(cfg, reopened, time.Now), &fakeDomainRegistrationLookup{}, nil)
	if record, found, err := reloaded.get(context.Background(), "example.com"); err != nil || !found ||
		!record.RegisteredAt.Equal(updated.RegisteredAt) || !record.ExpiresAt.Equal(updated.ExpiresAt) {
		t.Fatalf("reloaded record = %+v, found=%v, err=%v", record, found, err)
	}
}

func TestDomainRegistrationFailedRefreshRetainsExpiredRecord(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := newTestDomainRegistrationStore(t, now, &fakeDomainRegistrationLookup{err: errors.New("unavailable")})
	expired := domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	putTestDomainRegistration(t, store, expired)
	if info, err := store.evidence(context.Background(), "example.com"); err == nil || info.Available {
		t.Fatalf("failed refresh evidence = %+v, err=%v", info, err)
	}
	stored, found, err := store.get(context.Background(), "example.com")
	if err != nil || !found || !stored.ExpiresAt.Equal(expired.ExpiresAt) {
		t.Fatalf("expired record after failure = %+v, found=%v, err=%v", stored, found, err)
	}
}

func TestDomainRegistrationCapacityKeepsLatestExpirations(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	store := newTestDomainRegistrationStoreWithMax(t, now, &fakeDomainRegistrationLookup{}, 2)
	for i, domain := range []string{"soon.example", "middle.example", "late.example"} {
		putTestDomainRegistration(t, store, domainRegistrationRecord{Domain: domain, RegisteredAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(time.Duration(i+1) * 24 * time.Hour)})
	}
	if store.size(t, context.Background()) != 3 {
		t.Fatal("capacity was enforced before periodic cleanup")
	}
	if deleted, err := store.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	} else if deleted != 1 {
		t.Fatalf("capacity cleanup deleted %d records, want 1", deleted)
	}
	if _, found, err := store.get(context.Background(), "soon.example"); err != nil || found {
		t.Fatalf("earliest record retained: found=%v, err=%v", found, err)
	}
	for _, domain := range []string{"middle.example", "late.example"} {
		if _, found, err := store.get(context.Background(), domain); err != nil || !found {
			t.Fatalf("%s missing: found=%v, err=%v", domain, found, err)
		}
	}
}

func TestDomainRegistrationLookupUsesUniqueIndex(t *testing.T) {
	now := time.Now().UTC()
	store := newTestDomainRegistrationStore(t, now, &fakeDomainRegistrationLookup{})
	dbValue, ok := domainTestDatabases.Load(store)
	if !ok {
		t.Fatal("domain test database is not registered")
	}
	db := dbValue.(*sqlitedb.Store)
	rows, err := db.Query(context.Background(), `EXPLAIN QUERY PLAN SELECT id, domain, registered_at_ms, expires_at_ms
		FROM domain_registrations WHERE domain = ?`, "example.com")
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
	if !strings.Contains(plan, "sqlite_autoindex_domain_registrations_1") {
		t.Fatalf("domain lookup does not use unique index: %s", plan)
	}
}

func TestServerOpensSQLiteForDomainRegistrationAlone(t *testing.T) {
	cfg := config.Config{
		AI:          config.AIConfig{MaxConcurrent: 1},
		Milter:      config.MilterConfig{MaxConnections: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		DomainRegistration: config.DomainRegistrationConfig{
			Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, nil)
	if server.StartupError() != nil || server.database == nil {
		t.Fatalf("domain-only SQLite startup: database=%v, error=%v", server.database, server.StartupError())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledDomainRegistrationDoesNotOpenSQLite(t *testing.T) {
	cfg := config.Config{
		AI:          config.AIConfig{MaxConcurrent: 1},
		Milter:      config.MilterConfig{MaxConnections: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		DomainRegistration: config.DomainRegistrationConfig{
			Enabled: false, Timeout: config.Duration(time.Second), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, nil)
	if server.StartupError() != nil || server.database != nil {
		t.Fatalf("disabled domain registration database=%v, error=%v", server.database, server.StartupError())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}
