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
