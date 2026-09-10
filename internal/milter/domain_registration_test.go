package milter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

type fakeDomainRegistrationLookup struct {
	registered time.Time
	expires    time.Time
	err        error
	calls      atomic.Int32
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
	t.Helper()
	db, err := sqlstore.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlstore.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := newDomainRegistrationStore(config.DomainRegistrationConfig{
		Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10,
	}, db, slog.Default())
	store.now = func() time.Time { return now }
	store.lookup = lookup
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
	if deleted, err := store.cleanup(); err != nil {
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

func TestDomainRegistrationPersistsAndUpsertsInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	db, err := sqlstore.Open(context.Background(), path, sqlstore.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DomainRegistrationConfig{Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10}
	store := newDomainRegistrationStore(cfg, db, nil)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	first := domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(24 * time.Hour)}
	if err := store.put(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	stored, found, err := store.get(context.Background(), "example.com")
	if err != nil || !found {
		t.Fatalf("initial record: found=%v, err=%v", found, err)
	}
	firstID := stored.ID
	updated := domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-730 * 24 * time.Hour), ExpiresAt: now.Add(365 * 24 * time.Hour)}
	if err := store.put(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	stored, found, err = store.get(context.Background(), "example.com")
	if err != nil || !found || stored.ID != firstID || !stored.RegisteredAt.Equal(updated.RegisteredAt) || !stored.ExpiresAt.Equal(updated.ExpiresAt) {
		t.Fatalf("updated record = %+v, found=%v, err=%v", stored, found, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlstore.Open(context.Background(), path, sqlstore.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reloaded := newDomainRegistrationStore(cfg, reopened, nil)
	if record, found, err := reloaded.get(context.Background(), "example.com"); err != nil || !found || record.ID != firstID {
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
	store := newTestDomainRegistrationStore(t, now, &fakeDomainRegistrationLookup{})
	store.maxSize = 2
	for i, domain := range []string{"soon.example", "middle.example", "late.example"} {
		putTestDomainRegistration(t, store, domainRegistrationRecord{Domain: domain, RegisteredAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(time.Duration(i+1) * 24 * time.Hour)})
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
	rows, err := store.db.Query(context.Background(), `EXPLAIN QUERY PLAN SELECT id, domain, registered_at_ms, expires_at_ms
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

func TestRDAPClientReadsRegistrationAndExpirationEvents(t *testing.T) {
	transport := domainRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/domain/example.com" {
			t.Fatalf("unexpected RDAP path %q", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"events":[{"eventAction":"registration","eventDate":"2026-09-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-09-01T00:00:00Z"}]}`))}, nil
	})
	client := newRDAPClient(time.Second)
	client.http.Transport = transport
	client.services = map[string][]string{"com": {"https://rdap.example"}}
	registered, expires, err := client.Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if registered.Format("2006-01-02") != "2026-09-01" || expires.Format("2006-01-02") != "2027-09-01" {
		t.Fatalf("unexpected RDAP dates: registered=%v expires=%v", registered, expires)
	}
}

func TestRDAPClientLoadsBootstrapOnceForConcurrentLookups(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	client := newRDAPClient(time.Second)
	client.http.Transport = domainRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != ianaRDAPBootstrapURL {
			t.Fatalf("unexpected URL %q", r.URL)
		}
		if calls.Load() == 1 {
			close(started)
		}
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"services":[[["com"],["https://rdap.example/"]]]}`))}, nil
	})

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.rdapServices(context.Background())
			errCh <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("bootstrap requests = %d, want 1", got)
	}
}

func TestRDAPClientBootstrapWaitRespectsContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := newRDAPClient(time.Second)
	client.http.Transport = domainRoundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"services":[]}`))}, nil
	})
	leaderDone := make(chan error, 1)
	go func() {
		_, err := client.rdapServices(context.Background())
		leaderDone <- err
	}()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.rdapServices(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting error = %v, want context canceled", err)
	}
	close(release)
	if err := <-leaderDone; err != nil {
		t.Fatal(err)
	}
}

func TestRDAPClientCachesBootstrapFailure(t *testing.T) {
	var calls atomic.Int32
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	client := newRDAPClient(time.Second)
	client.now = func() time.Time { return now }
	client.http.Transport = domainRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("bootstrap unavailable")
	})
	for range 2 {
		if _, err := client.rdapServices(context.Background()); err == nil {
			t.Fatal("bootstrap failure was accepted")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("bootstrap requests during retry interval = %d, want 1", got)
	}
	now = now.Add(domainRegistrationFailureRetry)
	if _, err := client.rdapServices(context.Background()); err == nil {
		t.Fatal("bootstrap retry failure was accepted")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("bootstrap requests after retry interval = %d, want 2", got)
	}
}

func TestRDAPClientRejectsUnsafeRedirectDestinations(t *testing.T) {
	client := newRDAPClient(time.Second)
	client.resolve = func(_ context.Context, hostname string) ([]net.IPAddr, error) {
		addresses := map[string]string{
			"public.example":     "8.8.8.8",
			"private.example":    "10.0.0.1",
			"loopback.example":   "127.0.0.1",
			"link-local.example": "169.254.1.1",
		}
		address, found := addresses[hostname]
		if !found {
			return nil, errors.New("not found")
		}
		return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
	}
	tests := []struct {
		name    string
		target  string
		allowed bool
	}{
		{name: "public HTTPS hostname", target: "https://public.example/domain/example.com", allowed: true},
		{name: "plain HTTP", target: "http://public.example/domain/example.com"},
		{name: "IP literal", target: "https://127.0.0.1/domain/example.com"},
		{name: "private address", target: "https://private.example/domain/example.com"},
		{name: "loopback address", target: "https://loopback.example/domain/example.com"},
		{name: "link-local address", target: "https://link-local.example/domain/example.com"},
		{name: "single-label hostname", target: "https://localhost/domain/example.com"},
		{name: "userinfo", target: "https://user@public.example/domain/example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			err = client.validateRedirect(context.Background(), target)
			if (err == nil) != test.allowed {
				t.Fatalf("validateRedirect(%q) error = %v, allowed = %v", test.target, err, test.allowed)
			}
		})
	}
}

func TestRDAPClientLimitsRedirectCount(t *testing.T) {
	client := newRDAPClient(time.Second)
	target, err := url.Parse("https://public.example/domain/example.com")
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{URL: target}
	if err := client.http.CheckRedirect(request, []*http.Request{{}, {}, {}}); err == nil {
		t.Fatal("fourth RDAP redirect was accepted")
	}
}

type domainRoundTripFunc func(*http.Request) (*http.Response, error)

func (f domainRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
