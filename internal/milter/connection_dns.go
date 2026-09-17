package milter

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const maxConnectionPTRNames = 5

type dnsResolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

var nonRoutablePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

type connectionDNSResult struct {
	status string
	names  []message.ReverseDNSName
}

func resolveConnectionDNS(parent context.Context, resolver dnsResolver, addr netip.Addr, timeout time.Duration) connectionDNSResult {
	if resolver == nil || timeout <= 0 || !connectionAddressRoutable(addr) {
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
		hostname := safeDNSHostname(candidate)
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

func connectionAddressRoutable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, prefix := range nonRoutablePrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func safeDNSHostname(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return value
}
