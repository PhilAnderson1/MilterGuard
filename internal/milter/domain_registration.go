package milter

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	"golang.org/x/net/publicsuffix"
)

const (
	domainRegistrationExpiryGrace  = 14 * 24 * time.Hour
	domainRegistrationFailureRetry = time.Hour
)

type domainRegistrationStore struct {
	repository  stores.DomainRegistrationRepository
	maintenance stores.MaintainedRepository
	lookup      domainRegistrationLookup
	timeout     time.Duration
	slots       chan struct{}
	maxSize     int
	now         func() time.Time
	log         *slog.Logger
	mu          sync.Mutex
	failures    map[string]time.Time
	inflight    map[string]chan struct{}
}

type domainRegistrationLookup interface {
	Lookup(context.Context, string) (time.Time, time.Time, error)
}

func newDomainRegistrationStore(cfg config.DomainRegistrationConfig, cache stores.DomainRegistrationCache, lookup domainRegistrationLookup, log *slog.Logger) *domainRegistrationStore {
	store := &domainRegistrationStore{now: time.Now, log: log, timeout: cfg.Timeout.Value(), maxSize: cfg.MaxEntries, failures: make(map[string]time.Time), inflight: make(map[string]chan struct{})}
	if domainRegistrationEnabled(cfg) {
		store.slots = make(chan struct{}, min(8, cfg.MaxEntries))
		store.lookup = lookup
	}
	store.repository, store.maintenance = cache, cache
	return store
}

func domainRegistrationEnabled(cfg config.DomainRegistrationConfig) bool {
	return cfg.Enabled
}

func registrableDomain(domain string) string {
	domain = normalizeDomain(domain)
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return normalizeDomain(registrable)
}

// evidence returns current cached registration evidence or coalesces a bounded
// RDAP refresh for the registrable domain. Failed lookups are suppressed for a
// short interval without replacing an existing cached record.
func (s *domainRegistrationStore) evidence(ctx context.Context, domain string) (message.DomainRegistrationInfo, error) {
	domain = registrableDomain(domain)
	if s == nil || s.repository == nil || s.lookup == nil || domain == "" {
		return message.DomainRegistrationInfo{}, nil
	}
	now := s.now().UTC()
	record, found, err := s.repository.DomainRegistration(ctx, domain)
	if err != nil {
		return message.DomainRegistrationInfo{}, err
	}
	if found && record.ExpiresAt.After(now) {
		return domainRegistrationEvidence(record), nil
	}

	s.mu.Lock()
	if retryAt := s.failures[domain]; retryAt.After(now) {
		s.mu.Unlock()
		return message.DomainRegistrationInfo{}, nil
	}
	if pending, found := s.inflight[domain]; found {
		s.mu.Unlock()
		select {
		case <-pending:
			record, found, err := s.repository.DomainRegistration(ctx, domain)
			if err != nil {
				return message.DomainRegistrationInfo{}, err
			}
			if found && record.ExpiresAt.After(s.now().UTC()) {
				return domainRegistrationEvidence(record), nil
			}
			return message.DomainRegistrationInfo{}, nil
		case <-ctx.Done():
			return message.DomainRegistrationInfo{}, ctx.Err()
		}
	}
	pending := make(chan struct{})
	s.inflight[domain] = pending
	s.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	var registeredAt, expiresAt time.Time
	err = nil
	select {
	case s.slots <- struct{}{}:
		registeredAt, expiresAt, err = s.lookupSafely(lookupCtx, domain)
		<-s.slots
	case <-lookupCtx.Done():
		err = lookupCtx.Err()
	}
	if err == nil && (!registeredAt.Before(expiresAt) || registeredAt.After(now) || !expiresAt.After(now)) {
		err = fmt.Errorf("RDAP returned invalid or expired registration dates for %s", domain)
	}
	refreshed := stores.DomainRegistration{Domain: domain, RegisteredAt: registeredAt.UTC(), ExpiresAt: expiresAt.UTC()}
	if err == nil {
		err = s.repository.PutDomainRegistration(ctx, refreshed)
	}
	s.mu.Lock()
	delete(s.inflight, domain)
	if err != nil {
		s.pruneFailuresLocked(now)
		s.failures[domain] = now.Add(domainRegistrationFailureRetry)
	} else {
		delete(s.failures, domain)
	}
	close(pending)
	s.mu.Unlock()
	if err != nil {
		return message.DomainRegistrationInfo{}, err
	}
	if s.log != nil {
		s.log.DebugContext(ctx, "domain registration cached", "domain", domain, "registered_at", refreshed.RegisteredAt, "expires_at", refreshed.ExpiresAt)
	}
	return domainRegistrationEvidence(refreshed), nil
}

func (s *domainRegistrationStore) Cleanup(ctx context.Context) (int64, error) {
	if s == nil || s.maintenance == nil || s.lookup == nil {
		return 0, nil
	}
	return s.maintenance.Cleanup(ctx)
}

func (s *domainRegistrationStore) Count(ctx context.Context) (int, error) {
	if s == nil || s.maintenance == nil {
		return 0, nil
	}
	return s.maintenance.Count(ctx)
}

// lookupSafely contains a panic from the injected network lookup at the policy
// boundary so one RDAP defect cannot terminate a Milter session.
func (s *domainRegistrationStore) lookupSafely(ctx context.Context, domain string) (registeredAt, expiresAt time.Time, err error) {
	defer func() {
		if panicValue := recover(); panicValue != nil {
			if s.log != nil {
				s.log.ErrorContext(ctx, "MilterGuard worker recovered from panic",
					"worker", "domain registration lookup", "domain", domain,
					"panic", fmt.Sprint(panicValue), "stack", string(debug.Stack()))
			}
			err = fmt.Errorf("domain registration lookup panicked: %v", panicValue)
		}
	}()
	return s.lookup.Lookup(ctx, domain)
}

func (s *domainRegistrationStore) pruneFailuresLocked(now time.Time) {
	for domain, retryAt := range s.failures {
		if !retryAt.After(now) {
			delete(s.failures, domain)
		}
	}
	for len(s.failures) >= s.maxSize && len(s.failures) > 0 {
		for domain := range s.failures {
			delete(s.failures, domain)
			break
		}
	}
}

func domainRegistrationEvidence(record stores.DomainRegistration) message.DomainRegistrationInfo {
	return message.DomainRegistrationInfo{Available: true, Domain: record.Domain, RegisteredAt: record.RegisteredAt}
}
