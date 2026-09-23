package milter

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

const maxConnectionPTRNames = 5

type dnsResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type connectionDNSResult struct {
	status string
	names  []message.ReverseDNSName
}

// start begins one eligible connection lookup and returns its buffered result
// channel. Per-connection ownership and waiting remain with the session.
func (s *connectionDNSService) start(ctx context.Context, addr netip.Addr) <-chan connectionDNSResult {
	if s == nil || s.resolver == nil || s.timeout <= 0 || !netsafety.AddressRoutable(addr) {
		return nil
	}
	pending := make(chan connectionDNSResult, 1)
	go func() {
		pending <- s.resolveSafely(ctx, addr)
	}()
	return pending
}

func (s *connectionDNSService) resolveSafely(ctx context.Context, addr netip.Addr) (result connectionDNSResult) {
	result = connectionDNSResult{status: message.ReverseDNSLookupFailed}
	defer func() {
		if panicValue := recover(); panicValue != nil {
			logRecoveredWorkerPanic(s.log, ctx, "connection DNS lookup", panicValue, "remote_ip", addr.String())
		}
	}()
	return resolveConnectionDNS(ctx, s.resolver, addr, s.timeout)
}

// resolveConnectionDNS obtains bounded PTR names and confirms each against the
// connecting address. Filtering and IP exclusions consume the resulting facts.
func resolveConnectionDNS(parent context.Context, resolver dnsResolver, addr netip.Addr, timeout time.Duration) connectionDNSResult {
	if resolver == nil || timeout <= 0 || !netsafety.AddressRoutable(addr) {
		return connectionDNSResult{status: message.ReverseDNSNotApplicable}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	ptrNames, err := resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		return connectionDNSResult{status: message.ReverseDNSLookupFailed}
	}
	if len(ptrNames) == 0 {
		return connectionDNSResult{status: message.ReverseDNSAbsent}
	}

	seen := make(map[string]bool)
	result := connectionDNSResult{status: message.ReverseDNSAvailable}
	for _, candidate := range ptrNames {
		hostname := netsafety.DNSHostname(candidate)
		if hostname == "" || seen[hostname] {
			continue
		}
		seen[hostname] = true
		entry := message.ReverseDNSName{Hostname: hostname, Confirmation: message.ForwardUnconfirmed}
		forward, err := resolver.LookupIPAddr(ctx, hostname)
		if err != nil {
			entry.Confirmation = message.ForwardLookupFailed
		} else {
			for _, resolved := range forward {
				confirmed, ok := netip.AddrFromSlice(resolved.IP)
				if ok && confirmed.Unmap() == addr.Unmap() {
					entry.Confirmation = message.ForwardConfirmed
					break
				}
			}
		}
		result.names = append(result.names, entry)
		if len(result.names) >= maxConnectionPTRNames {
			break
		}
	}
	if len(result.names) == 0 {
		return connectionDNSResult{status: message.ReverseDNSAbsent}
	}
	return result
}
