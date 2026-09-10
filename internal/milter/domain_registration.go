package milter

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
	"golang.org/x/net/publicsuffix"
)

const (
	domainRegistrationExpiryGrace        = 14 * 24 * time.Hour
	domainRegistrationFailureRetry       = time.Hour
	ianaRDAPBootstrapURL                 = "https://data.iana.org/rdap/dns.json"
	maxRDAPResponseBytes           int64 = 1 << 20
)

type domainRegistrationRecord struct {
	ID           uint64
	Domain       string
	RegisteredAt time.Time
	ExpiresAt    time.Time
}

type domainRegistrationStore struct {
	db       *sqlstore.Store
	lookup   domainRegistrationLookup
	timeout  time.Duration
	slots    chan struct{}
	maxSize  int
	now      func() time.Time
	log      *slog.Logger
	mu       sync.Mutex
	failures map[string]time.Time
	inflight map[string]chan struct{}
}

type domainRegistrationLookup interface {
	Lookup(context.Context, string) (time.Time, time.Time, error)
}

func newDomainRegistrationStore(cfg config.DomainRegistrationConfig, db *sqlstore.Store, log *slog.Logger) *domainRegistrationStore {
	store := &domainRegistrationStore{now: time.Now, log: log, timeout: cfg.Timeout.Value(), maxSize: cfg.MaxEntries, failures: make(map[string]time.Time), inflight: make(map[string]chan struct{})}
	if cfg.Enabled {
		store.slots = make(chan struct{}, min(8, cfg.MaxEntries))
		store.lookup = newRDAPClient(cfg.Timeout.Value())
	}
	store.db = db
	return store
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
	if s == nil || s.db == nil || s.lookup == nil || domain == "" {
		return message.DomainRegistrationInfo{}, nil
	}
	now := s.now().UTC()
	record, found, err := s.get(ctx, domain)
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
			record, found, err := s.get(ctx, domain)
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
	refreshed := domainRegistrationRecord{Domain: domain, RegisteredAt: registeredAt.UTC(), ExpiresAt: expiresAt.UTC()}
	if err == nil {
		err = s.put(ctx, refreshed)
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

func (s *domainRegistrationStore) get(ctx context.Context, domain string) (domainRegistrationRecord, bool, error) {
	var record domainRegistrationRecord
	var id, registeredAt, expiresAt int64
	err := s.db.QueryRow(ctx, `SELECT id, domain, registered_at_ms, expires_at_ms
		FROM domain_registrations WHERE domain = ?`, domain).Scan(&id, &record.Domain, &registeredAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domainRegistrationRecord{}, false, nil
	}
	if err != nil {
		return domainRegistrationRecord{}, false, err
	}
	record.ID = uint64(id)
	record.RegisteredAt = time.UnixMilli(registeredAt).UTC()
	record.ExpiresAt = time.UnixMilli(expiresAt).UTC()
	return record, true, nil
}

func (s *domainRegistrationStore) put(ctx context.Context, record domainRegistrationRecord) error {
	return s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO domain_registrations
			(domain, registered_at_ms, expires_at_ms) VALUES (?, ?, ?)
			ON CONFLICT(domain) DO UPDATE SET registered_at_ms = excluded.registered_at_ms,
				expires_at_ms = excluded.expires_at_ms`, record.Domain,
			unixMillis(record.RegisteredAt), unixMillis(record.ExpiresAt)); err != nil {
			return err
		}
		if err := s.enforceCapacityTx(ctx, tx); err != nil {
			return err
		}
		var retained int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM domain_registrations WHERE domain = ?)`, record.Domain).Scan(&retained); err != nil {
			return err
		}
		if retained == 0 {
			return errors.New("new domain registration was removed by capacity enforcement")
		}
		return nil
	})
}

func (s *domainRegistrationStore) enforceCapacityTx(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM domain_registrations WHERE id IN (
		SELECT id FROM domain_registrations ORDER BY expires_at_ms DESC, id DESC LIMIT -1 OFFSET ?
	)`, s.maxSize)
	return err
}

func (s *domainRegistrationStore) cleanup() (int64, error) {
	if s == nil || s.db == nil || s.lookup == nil {
		return 0, nil
	}
	ctx := context.Background()
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM domain_registrations WHERE expires_at_ms < ?`,
			unixMillis(s.now().UTC().Add(-domainRegistrationExpiryGrace)))
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err == nil {
			deleted += n
		}
		result, err = tx.ExecContext(ctx, `DELETE FROM domain_registrations WHERE id IN (
			SELECT id FROM domain_registrations ORDER BY expires_at_ms DESC, id DESC LIMIT -1 OFFSET ?
		)`, s.maxSize)
		if err != nil {
			return err
		}
		if n, err := result.RowsAffected(); err == nil {
			deleted += n
		}
		return nil
	})
	return deleted, err
}

func (s *domainRegistrationStore) size() int {
	if s == nil || s.db == nil {
		return 0
	}
	var count int
	if err := s.db.QueryRow(context.Background(), `SELECT COUNT(*) FROM domain_registrations`).Scan(&count); err != nil {
		return 0
	}
	return count
}

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

func domainRegistrationEvidence(record domainRegistrationRecord) message.DomainRegistrationInfo {
	return message.DomainRegistrationInfo{Available: true, Domain: record.Domain, RegisteredAt: record.RegisteredAt}
}

type rdapClient struct {
	http              *http.Client
	resolve           func(context.Context, string) ([]net.IPAddr, error)
	now               func() time.Time
	bootstrapURL      string
	mu                sync.Mutex
	services          map[string][]string
	bootstrapInflight chan struct{}
	bootstrapErr      error
	bootstrapRetryAt  time.Time
}

func newRDAPClient(timeout time.Duration) *rdapClient {
	rdap := &rdapClient{
		resolve:      net.DefaultResolver.LookupIPAddr,
		now:          time.Now,
		bootstrapURL: ianaRDAPBootstrapURL,
	}
	rdap.http = &http.Client{Timeout: timeout}
	rdap.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many RDAP redirects")
		}
		return rdap.validateRedirect(req.Context(), req.URL)
	}
	return rdap
}

func (c *rdapClient) validateRedirect(ctx context.Context, destination *url.URL) error {
	if destination == nil || destination.Scheme != "https" || destination.User != nil {
		return errors.New("unsafe RDAP redirect destination")
	}
	hostname := safeDNSHostname(destination.Hostname())
	if hostname == "" || !strings.Contains(hostname, ".") || net.ParseIP(hostname) != nil {
		return errors.New("unsafe RDAP redirect hostname")
	}
	addresses, err := c.resolve(ctx, hostname)
	if err != nil {
		return fmt.Errorf("cannot validate RDAP redirect hostname %q: %w", hostname, err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("cannot validate RDAP redirect hostname %q: no addresses", hostname)
	}
	for _, resolved := range addresses {
		address, ok := netip.AddrFromSlice(resolved.IP)
		if !ok || !connectionAddressRoutable(address) {
			return fmt.Errorf("unsafe RDAP redirect address for %q", hostname)
		}
	}
	return nil
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
	for {
		c.mu.Lock()
		if c.services != nil {
			services := c.services
			c.mu.Unlock()
			return services, nil
		}
		if c.bootstrapRetryAt.After(c.now()) {
			err := c.bootstrapErr
			c.mu.Unlock()
			return nil, err
		}
		if pending := c.bootstrapInflight; pending != nil {
			c.mu.Unlock()
			select {
			case <-pending:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		pending := make(chan struct{})
		c.bootstrapInflight = pending
		c.mu.Unlock()

		services, err := c.fetchRDAPServices(ctx)
		c.mu.Lock()
		if err == nil {
			c.services = services
			c.bootstrapErr = nil
			c.bootstrapRetryAt = time.Time{}
		} else if !errors.Is(err, context.Canceled) {
			c.bootstrapErr = err
			c.bootstrapRetryAt = c.now().Add(domainRegistrationFailureRetry)
		}
		c.bootstrapInflight = nil
		close(pending)
		c.mu.Unlock()
		return services, err
	}
}

func (c *rdapClient) fetchRDAPServices(ctx context.Context) (map[string][]string, error) {
	var bootstrap struct {
		Services [][][]string `json:"services"`
	}
	if err := c.getJSON(ctx, c.bootstrapURL, &bootstrap); err != nil {
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
