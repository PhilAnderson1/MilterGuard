package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

const (
	bootstrapURL               = "https://data.iana.org/rdap/dns.json"
	maximumResponseBytes int64 = 1 << 20
	failureRetry               = time.Hour
)

// Client is safe for concurrent domain lookups.
type Client struct {
	http              *http.Client
	resolve           func(context.Context, string) ([]net.IPAddr, error)
	dial              func(context.Context, string, string) (net.Conn, error)
	now               func() time.Time
	bootstrapURL      string
	mu                sync.Mutex
	services          map[string][]string
	bootstrapInflight chan struct{}
	bootstrapErr      error
	bootstrapRetryAt  time.Time
}

// New creates a concurrency-safe RDAP client with proxy use disabled and each
// complete HTTP operation bounded by timeout.
func New(timeout time.Duration) *Client {
	dialer := &net.Dialer{}
	client := &Client{
		resolve:      net.DefaultResolver.LookupIPAddr,
		dial:         dialer.DialContext,
		now:          time.Now,
		bootstrapURL: bootstrapURL,
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = client.dialContext
	client.http = &http.Client{Timeout: timeout, Transport: transport}
	client.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("too many RDAP redirects")
		}
		return client.validateRedirect(req.URL)
	}
	return client
}

func (c *Client) validateRedirect(destination *url.URL) error {
	if destination == nil || destination.Scheme != "https" || destination.User != nil {
		return errors.New("unsafe RDAP redirect destination")
	}
	hostname := netsafety.DNSHostname(destination.Hostname())
	if hostname == "" || !strings.Contains(hostname, ".") || net.ParseIP(hostname) != nil {
		return errors.New("unsafe RDAP redirect hostname")
	}
	return nil
}

// dialContext resolves, validates, and dials an RDAP endpoint in one operation.
// Dialing the selected address directly prevents a second DNS lookup from
// rebinding an already validated public hostname to an internal service.
func (c *Client) dialContext(ctx context.Context, network, endpoint string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid RDAP endpoint %q: %w", endpoint, err)
	}
	hostname := netsafety.DNSHostname(host)
	if hostname == "" || !strings.Contains(hostname, ".") || net.ParseIP(hostname) != nil {
		return nil, fmt.Errorf("unsafe RDAP endpoint hostname %q", host)
	}
	addresses, err := c.resolve(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve RDAP endpoint hostname %q: %w", hostname, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("cannot resolve RDAP endpoint hostname %q: no addresses", hostname)
	}
	validated := make([]netip.Addr, 0, len(addresses))
	for _, resolved := range addresses {
		address, ok := netip.AddrFromSlice(resolved.IP)
		if !ok || !netsafety.AddressRoutable(address) {
			return nil, fmt.Errorf("unsafe RDAP endpoint address for %q", hostname)
		}
		validated = append(validated, address.Unmap())
	}
	var dialErrors []error
	for _, address := range validated {
		conn, err := c.dial(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, err)
	}
	return nil, fmt.Errorf("cannot connect to RDAP endpoint %q: %w", hostname, errors.Join(dialErrors...))
}

// Lookup discovers the authoritative RDAP services for domain and returns its
// registration and expiration events.
func (c *Client) Lookup(ctx context.Context, domain string) (time.Time, time.Time, error) {
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

func (c *Client) rdapServices(ctx context.Context) (map[string][]string, error) {
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
			c.bootstrapRetryAt = c.now().Add(failureRetry)
		}
		c.bootstrapInflight = nil
		close(pending)
		c.mu.Unlock()
		return services, err
	}
}

func (c *Client) fetchRDAPServices(ctx context.Context) (map[string][]string, error) {
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
			tld = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(tld)), ".")
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

func (c *Client) getJSON(ctx context.Context, endpoint string, destination any) error {
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
	limited := io.LimitReader(resp.Body, maximumResponseBytes+1)
	decoder := json.NewDecoder(limited)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return nil
}
