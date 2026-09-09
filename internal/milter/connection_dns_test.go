package milter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type connectionTestResolver struct {
	ptr          []string
	ptrErr       error
	forward      map[string][]net.IPAddr
	forwardErr   map[string]error
	ptrCalls     atomic.Int32
	forwardCalls atomic.Int32
}

type blockingDNSResolver struct{}

type panickingDNSResolver struct{}

func (panickingDNSResolver) LookupAddr(context.Context, string) ([]string, error) {
	panic("test DNS panic")
}

func (panickingDNSResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	panic("test DNS panic")
}

func (blockingDNSResolver) LookupAddr(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingDNSResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *connectionTestResolver) LookupAddr(context.Context, string) ([]string, error) {
	r.ptrCalls.Add(1)
	return r.ptr, r.ptrErr
}

func (r *connectionTestResolver) LookupIPAddr(_ context.Context, hostname string) ([]net.IPAddr, error) {
	r.forwardCalls.Add(1)
	return r.forward[hostname], r.forwardErr[hostname]
}

func TestResolveConnectionDNSOutcomes(t *testing.T) {
	addr := netip.MustParseAddr("8.8.8.8")
	tests := []struct {
		name       string
		resolver   *connectionTestResolver
		wantStatus string
		wantNames  []message.ReverseDNSName
	}{
		{
			name: "forward confirmed and unconfirmed",
			resolver: &connectionTestResolver{
				ptr: []string{"DNS.Google.", "other.example."},
				forward: map[string][]net.IPAddr{
					"dns.google":    {{IP: net.ParseIP("8.8.8.8")}},
					"other.example": {{IP: net.ParseIP("8.8.4.4")}},
				},
				forwardErr: map[string]error{},
			},
			wantStatus: message.ReverseDNSAvailable,
			wantNames: []message.ReverseDNSName{
				{Hostname: "dns.google", Confirmation: message.ForwardConfirmed},
				{Hostname: "other.example", Confirmation: message.ForwardUnconfirmed},
			},
		},
		{
			name:       "no PTR records",
			resolver:   &connectionTestResolver{forward: map[string][]net.IPAddr{}, forwardErr: map[string]error{}},
			wantStatus: message.ReverseDNSAbsent,
		},
		{
			name:       "PTR failure",
			resolver:   &connectionTestResolver{ptrErr: errors.New("resolver unavailable")},
			wantStatus: message.ReverseDNSLookupFailed,
		},
		{
			name: "forward failure",
			resolver: &connectionTestResolver{
				ptr: []string{"dns.google."}, forward: map[string][]net.IPAddr{},
				forwardErr: map[string]error{"dns.google": errors.New("timeout")},
			},
			wantStatus: message.ReverseDNSAvailable,
			wantNames:  []message.ReverseDNSName{{Hostname: "dns.google", Confirmation: message.ForwardLookupFailed}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveConnectionDNS(context.Background(), test.resolver, addr, time.Second)
			if got.status != test.wantStatus {
				t.Fatalf("status = %q, want %q", got.status, test.wantStatus)
			}
			if len(got.names) != len(test.wantNames) {
				t.Fatalf("names = %#v, want %#v", got.names, test.wantNames)
			}
			for i := range test.wantNames {
				if got.names[i] != test.wantNames[i] {
					t.Errorf("name %d = %#v, want %#v", i, got.names[i], test.wantNames[i])
				}
			}
		})
	}
}

func TestResolveConnectionDNSSkipsNonRoutableAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "192.0.2.1", "::1", "2001:db8::1"} {
		resolver := &connectionTestResolver{}
		got := resolveConnectionDNS(context.Background(), resolver, netip.MustParseAddr(value), time.Second)
		if got.status != message.ReverseDNSNotApplicable || resolver.ptrCalls.Load() != 0 {
			t.Errorf("%s: result=%#v PTR calls=%d", value, got, resolver.ptrCalls.Load())
		}
	}
}

func TestResolveConnectionDNSTimeoutIsLookupFailure(t *testing.T) {
	started := time.Now()
	got := resolveConnectionDNS(context.Background(), blockingDNSResolver{}, netip.MustParseAddr("8.8.8.8"), 10*time.Millisecond)
	if got.status != message.ReverseDNSLookupFailed {
		t.Fatalf("timeout status = %q, want lookup failure", got.status)
	}
	if time.Since(started) > time.Second {
		t.Fatal("DNS timeout was not bounded")
	}
}

func TestConnectionDNSPanicIsRecoveredAsLookupFailure(t *testing.T) {
	var logOutput strings.Builder
	server := &Server{log: slog.New(slog.NewJSONHandler(&logOutput, nil))}
	got := server.resolveConnectionDNSSafely(context.Background(), panickingDNSResolver{}, netip.MustParseAddr("8.8.8.8"), time.Second)
	if got.status != message.ReverseDNSLookupFailed {
		t.Fatalf("panic status = %q, want lookup failure", got.status)
	}
	logs := logOutput.String()
	if !strings.Contains(logs, `"worker":"connection DNS lookup"`) || !strings.Contains(logs, "test DNS panic") {
		t.Fatalf("panic was not logged: %s", logs)
	}
}

func TestResolveConnectionDNSBoundsAndSanitizesPTRNames(t *testing.T) {
	resolver := &connectionTestResolver{
		ptr:     []string{"valid.example.", "VALID.EXAMPLE.", "bad\nname.example."},
		forward: map[string][]net.IPAddr{}, forwardErr: map[string]error{},
	}
	for i := 0; i < 10; i++ {
		resolver.ptr = append(resolver.ptr, fmt.Sprintf("host-%d.example.", i))
	}
	got := resolveConnectionDNS(context.Background(), resolver, netip.MustParseAddr("8.8.8.8"), time.Second)
	if len(got.names) != maxConnectionPTRNames || got.names[0].Hostname != "valid.example" {
		t.Fatalf("sanitized names = %#v", got.names)
	}
}
