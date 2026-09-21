package rdap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientReadsRegistrationAndExpirationEvents(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/domain/example.com" {
			t.Fatalf("unexpected RDAP path %q", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/rdap+json, application/json" || r.Header.Get("User-Agent") != "MilterGuard" {
			t.Fatalf("unexpected request headers: %v", r.Header)
		}
		return response(http.StatusOK, `{"events":[{"eventAction":"registration","eventDate":"2026-09-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2027-09-01T00:00:00Z"}]}`), nil
	})
	client := New(time.Second)
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

func TestClientAcceptsRegistrationWithoutExpirationEvent(t *testing.T) {
	client := New(time.Second)
	client.services = map[string][]string{"com": {"https://rdap.example"}}
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{"events":[{"eventAction":"registration","eventDate":"2026-09-01T00:00:00Z"}]}`), nil
	})
	registered, expires, err := client.Lookup(context.Background(), "example.com")
	if err != nil || registered.Format("2006-01-02") != "2026-09-01" || !expires.IsZero() {
		t.Fatalf("RDAP dates = %v, %v, %v; want registration and no expiry", registered, expires, err)
	}
}

func TestClientTriesServicesAndReportsInvalidResponses(t *testing.T) {
	var calls atomic.Int32
	client := New(time.Second)
	client.services = map[string][]string{"com": {"https://first.example", "https://second.example"}}
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Host == "first.example" {
			return nil, errors.New("first unavailable")
		}
		return response(http.StatusOK, `{"events":[]}`), nil
	})
	if _, _, err := client.Lookup(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "lacks registration") {
		t.Fatalf("lookup error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("service calls = %d, want 2", calls.Load())
	}
	if _, _, err := client.Lookup(context.Background(), "example.net"); err == nil || !strings.Contains(err.Error(), "no RDAP service") {
		t.Fatalf("missing-service error = %v", err)
	}
}

func TestClientLoadsBootstrapOnceForConcurrentLookups(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	client := New(time.Second)
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.String() != bootstrapURL {
			t.Fatalf("unexpected URL %q", r.URL)
		}
		if calls.Load() == 1 {
			close(started)
		}
		<-release
		return response(http.StatusOK, `{"services":[[["com"],["https://rdap.example/"]]]}`), nil
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

func TestClientBootstrapWaitRespectsContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	client := New(time.Second)
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return response(http.StatusOK, `{"services":[]}`), nil
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

func TestClientCachesBootstrapFailure(t *testing.T) {
	var calls atomic.Int32
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	client := New(time.Second)
	client.now = func() time.Time { return now }
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
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
	now = now.Add(failureRetry)
	if _, err := client.rdapServices(context.Background()); err == nil {
		t.Fatal("bootstrap retry failure was accepted")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("bootstrap requests after retry interval = %d, want 2", got)
	}
}

func TestClientRetriesTimedOutBootstrapAfterShortCooldown(t *testing.T) {
	var calls atomic.Int32
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	client := New(time.Second)
	client.now = func() time.Time { return now }
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})
	for range 2 {
		if _, err := client.rdapServices(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("bootstrap error = %v, want deadline exceeded", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("bootstrap requests during short cooldown = %d, want 1", got)
	}
	now = now.Add(deadlineRetry)
	if _, err := client.rdapServices(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap retry error = %v, want deadline exceeded", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("bootstrap requests after short cooldown = %d, want 2", got)
	}
}

func TestClientDoesNotCacheCanceledBootstrap(t *testing.T) {
	var calls atomic.Int32
	client := New(time.Second)
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.rdapServices(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled bootstrap error = %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := client.rdapServices(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("second canceled bootstrap error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("canceled bootstrap requests = %d, want 2", calls.Load())
	}
}

func TestClientRejectsUnsafeRedirectDestinations(t *testing.T) {
	client := New(time.Second)
	tests := []struct {
		name    string
		target  string
		allowed bool
	}{
		{name: "public HTTPS hostname", target: "https://public.example/domain/example.com", allowed: true},
		{name: "plain HTTP", target: "http://public.example/domain/example.com"},
		{name: "IP literal", target: "https://127.0.0.1/domain/example.com"},
		{name: "single-label hostname", target: "https://localhost/domain/example.com"},
		{name: "userinfo", target: "https://user@public.example/domain/example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse(test.target)
			if err != nil {
				t.Fatal(err)
			}
			err = client.validateRedirect(target)
			if (err == nil) != test.allowed {
				t.Fatalf("validateRedirect(%q) error = %v, allowed = %v", test.target, err, test.allowed)
			}
		})
	}
}

func TestDialRejectsNonPublicAddresses(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "::1", "2001:db8::1"} {
		t.Run(address, func(t *testing.T) {
			client := New(time.Second)
			client.resolve = func(context.Context, string) ([]net.IPAddr, error) {
				return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
			}
			dialed := false
			client.dial = func(context.Context, string, string) (net.Conn, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			}
			if _, err := client.dialContext(context.Background(), "tcp", "rdap.example:443"); err == nil {
				t.Fatal("unsafe RDAP address was accepted")
			}
			if dialed {
				t.Fatal("unsafe RDAP address was dialed")
			}
		})
	}
}

func TestDialRejectsMixedSafeAndUnsafeAnswers(t *testing.T) {
	client := New(time.Second)
	client.resolve = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	}
	dialed := false
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unexpected dial")
	}
	if _, err := client.dialContext(context.Background(), "tcp", "rdap.example:443"); err == nil || dialed {
		t.Fatalf("mixed DNS response: error=%v dialed=%v", err, dialed)
	}
}

func TestDialPinsValidatedAddress(t *testing.T) {
	client := New(time.Second)
	resolveCalls := 0
	client.resolve = func(context.Context, string) ([]net.IPAddr, error) {
		resolveCalls++
		if resolveCalls == 1 {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	var dialed string
	client.dial = func(_ context.Context, _, endpoint string) (net.Conn, error) {
		dialed = endpoint
		clientSide, serverSide := net.Pipe()
		_ = serverSide.Close()
		return clientSide, nil
	}
	conn, err := client.dialContext(context.Background(), "tcp", "rdap.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if resolveCalls != 1 {
		t.Fatalf("DNS resolutions = %d, want 1", resolveCalls)
	}
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed endpoint = %q, want pinned public address", dialed)
	}
}

func TestDialTriesAllValidatedAddresses(t *testing.T) {
	client := New(time.Second)
	client.resolve = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("1.1.1.1")}}, nil
	}
	var endpoints []string
	client.dial = func(_ context.Context, _, endpoint string) (net.Conn, error) {
		endpoints = append(endpoints, endpoint)
		if strings.HasPrefix(endpoint, "8.8.8.8") {
			return nil, errors.New("first failed")
		}
		clientSide, serverSide := net.Pipe()
		_ = serverSide.Close()
		return clientSide, nil
	}
	conn, err := client.dialContext(context.Background(), "tcp", "rdap.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if len(endpoints) != 2 {
		t.Fatalf("dialed endpoints = %v", endpoints)
	}
}

func TestClientLimitsRedirectCount(t *testing.T) {
	client := New(time.Second)
	target, err := url.Parse("https://public.example/domain/example.com")
	if err != nil {
		t.Fatal(err)
	}
	request := &http.Request{URL: target}
	if err := client.http.CheckRedirect(request, []*http.Request{{}, {}, {}}); err == nil {
		t.Fatal("fourth RDAP redirect was accepted")
	}
}

func TestGetJSONRejectsHTTPAndMalformedJSON(t *testing.T) {
	client := New(time.Second)
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusServiceUnavailable, "unavailable"), nil
	})
	if err := client.getJSON(context.Background(), "https://rdap.example", &struct{}{}); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("HTTP error = %v", err)
	}
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{"), nil
	})
	if err := client.getJSON(context.Background(), "https://rdap.example", &struct{}{}); err == nil {
		t.Fatal("malformed JSON was accepted")
	}
}

func TestGetJSONBoundsResponseReading(t *testing.T) {
	client := New(time.Second)
	client.http.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.Repeat(" ", int(maximumResponseBytes+1))+`{"services":[]}`), nil
	})
	if err := client.getJSON(context.Background(), "https://rdap.example", &struct{}{}); err == nil {
		t.Fatal("JSON beyond the response limit was accepted")
	}
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
