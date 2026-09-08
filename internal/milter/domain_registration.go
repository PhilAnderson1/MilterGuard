package milter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"golang.org/x/net/publicsuffix"
)

const (
	domainRegistrationFileVersion               = 1
	estimatedDomainRegistrationEntryBytes int64 = 512
	domainRegistrationExpiryGrace               = 14 * 24 * time.Hour
	domainRegistrationFailureRetry              = time.Hour
	ianaRDAPBootstrapURL                        = "https://data.iana.org/rdap/dns.json"
	maxRDAPResponseBytes                  int64 = 1 << 20
)

type domainRegistrationRecord struct {
	ID           uint64    `json:"id"`
	Domain       string    `json:"domain"`
	RegisteredAt time.Time `json:"registered_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type domainRegistrationStore struct {
	db       *jsonstore.Database[string, domainRegistrationRecord]
	lookup   domainRegistrationLookup
	timeout  time.Duration
	slots    chan struct{}
	maxSize  int
	now      func() time.Time
	log      *slog.Logger
	loadErr  error
	mu       sync.Mutex
	failures map[string]time.Time
	inflight map[string]chan struct{}
}

type domainRegistrationLookup interface {
	Lookup(context.Context, string) (time.Time, time.Time, error)
}

func newDomainRegistrationStore(cfg config.DomainRegistrationConfig, log *slog.Logger) *domainRegistrationStore {
	store := &domainRegistrationStore{now: time.Now, log: log, timeout: cfg.Timeout.Value(), maxSize: cfg.MaxEntries, failures: make(map[string]time.Time), inflight: make(map[string]chan struct{})}
	if cfg.Enabled {
		store.slots = make(chan struct{}, min(8, cfg.MaxEntries))
	}
	store.db = jsonstore.New("Domains", cfg.StateFile, domainRegistrationFileVersion, cfg.MaxEntries,
		persistentStoreReadLimit(cfg.MaxEntries, estimatedDomainRegistrationEntryBytes),
		func(record domainRegistrationRecord) string { return record.Domain },
		jsonstore.Identity[domainRegistrationRecord]{
			Get: func(record domainRegistrationRecord) uint64 { return record.ID },
			Set: func(record domainRegistrationRecord, id uint64) domainRegistrationRecord {
				record.ID = id
				return record
			},
		},
		func(record domainRegistrationRecord, now time.Time) bool {
			return record.ExpiresAt.Before(now.Add(-domainRegistrationExpiryGrace))
		},
		func(a, b domainRegistrationRecord) bool { return a.ExpiresAt.Before(b.ExpiresAt) },
		func(a, b domainRegistrationRecord) bool { return a.Domain < b.Domain }, log)
	store.db.Now = func() time.Time { return store.now() }
	if !cfg.Enabled {
		return store
	}
	store.lookup = newRDAPClient(cfg.Timeout.Value())
	if _, err := store.db.Load(func(version int) bool { return version == domainRegistrationFileVersion }, normalizeDomainRegistrationRecord); err != nil && !os.IsNotExist(err) {
		store.loadErr = err
	}
	return store
}

func normalizeDomainRegistrationRecord(record domainRegistrationRecord) (domainRegistrationRecord, bool, bool) {
	normalized := registrableDomain(record.Domain)
	changed := normalized != record.Domain
	record.Domain = normalized
	valid := record.Domain != "" && !record.RegisteredAt.IsZero() && !record.ExpiresAt.IsZero() &&
		!record.ExpiresAt.Before(record.RegisteredAt)
	return record, valid, changed
}

func registrableDomain(domain string) string {
	domain = normalizeDomain(domain)
	registrable, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return ""
	}
	return normalizeDomain(registrable)
}

func (s *domainRegistrationStore) evidence(ctx context.Context, domain string) (message.DomainRegistrationInfo, error) {
	domain = registrableDomain(domain)
	if s == nil || s.lookup == nil || domain == "" {
		return message.DomainRegistrationInfo{}, nil
	}
	now := s.now().UTC()
	if record, found := s.db.Get(domain); found && record.ExpiresAt.After(now) {
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
			if record, found := s.db.Get(domain); found && record.ExpiresAt.After(s.now().UTC()) {
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
	var err error
	select {
	case s.slots <- struct{}{}:
		registeredAt, expiresAt, err = s.lookup.Lookup(lookupCtx, domain)
		<-s.slots
	case <-lookupCtx.Done():
		err = lookupCtx.Err()
	}
	if err == nil && (!registeredAt.Before(expiresAt) || registeredAt.After(now) || !expiresAt.After(now)) {
		err = fmt.Errorf("RDAP returned invalid or expired registration dates for %s", domain)
	}
	record := domainRegistrationRecord{Domain: domain, RegisteredAt: registeredAt.UTC(), ExpiresAt: expiresAt.UTC()}
	if err == nil {
		err = s.db.Put(record)
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
		s.log.DebugContext(ctx, "domain registration cached", "domain", domain, "registered_at", record.RegisteredAt, "expires_at", record.ExpiresAt)
	}
	return domainRegistrationEvidence(record), nil
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

func domainRegistrationEvidence(record domainRegistrationRecord) message.DomainRegistrationInfo {
	return message.DomainRegistrationInfo{Available: true, Domain: record.Domain, RegisteredAt: record.RegisteredAt}
}

type rdapClient struct {
	http     *http.Client
	mu       sync.Mutex
	services map[string][]string
}

func newRDAPClient(timeout time.Duration) *rdapClient {
	client := &http.Client{Timeout: timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" {
			return errors.New("unsafe RDAP redirect")
		}
		return nil
	}
	return &rdapClient{http: client}
}

func (c *rdapClient) Lookup(ctx context.Context, domain string) (time.Time, time.Time, error) {
	services, err := c.rdapServices(ctx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	bases := services[tld]
	if len(bases) == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("no RDAP service for .%s", tld)
	}
	var lastErr error
	for _, base := range bases {
		endpoint := strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(domain)
		var response struct {
			Events []struct {
				Action string    `json:"eventAction"`
				Date   time.Time `json:"eventDate"`
			} `json:"events"`
		}
		if err := c.getJSON(ctx, endpoint, &response); err != nil {
			lastErr = err
			continue
		}
		var registeredAt, expiresAt time.Time
		for _, event := range response.Events {
			switch strings.ToLower(event.Action) {
			case "registration":
				registeredAt = event.Date
			case "expiration":
				expiresAt = event.Date
			}
		}
		if registeredAt.IsZero() || expiresAt.IsZero() {
			lastErr = errors.New("RDAP response lacks registration or expiration event")
			continue
		}
		return registeredAt, expiresAt, nil
	}
	return time.Time{}, time.Time{}, lastErr
}

func (c *rdapClient) rdapServices(ctx context.Context) (map[string][]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.services != nil {
		return c.services, nil
	}
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := c.getJSON(ctx, ianaRDAPBootstrapURL, &bootstrap); err != nil {
		return nil, err
	}
	services := make(map[string][]string)
	for _, entry := range bootstrap.Services {
		if len(entry) != 2 {
			continue
		}
		for _, tld := range entry[0] {
			tld = normalizeDomain(tld)
			for _, base := range entry[1] {
				parsed, err := url.Parse(base)
				if tld != "" && err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil {
					services[tld] = append(services[tld], base)
				}
			}
		}
	}
	c.services = services
	return services, nil
}

func (c *rdapClient) getJSON(ctx context.Context, endpoint string, destination any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "MilterGuard")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("RDAP endpoint returned HTTP %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxRDAPResponseBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}
