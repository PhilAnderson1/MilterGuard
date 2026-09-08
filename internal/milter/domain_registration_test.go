package milter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
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
	store := newDomainRegistrationStore(config.DomainRegistrationConfig{
		Enabled: true, Timeout: config.Duration(time.Second), MaxEntries: 10,
		StateFile: t.TempDir() + "/domains.json",
	}, slog.Default())
	store.now = func() time.Time { return now }
	store.lookup = lookup
	return store
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
	if err := store.db.Put(domainRegistrationRecord{Domain: "example.com", RegisteredAt: now.Add(-365 * 24 * time.Hour), ExpiresAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

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
		if err := store.db.Put(record); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, found := store.db.Get("expired.example"); found {
		t.Fatal("record beyond expiry grace was retained")
	}
	if _, found := store.db.Get("grace.example"); !found {
		t.Fatal("record within expiry grace was removed")
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

type domainRoundTripFunc func(*http.Request) (*http.Response, error)

func (f domainRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
