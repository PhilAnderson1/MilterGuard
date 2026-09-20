package netsafety

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCanonicalIP(t *testing.T) {
	tests := []struct {
		name  string
		input netip.Addr
		want  netip.Addr
	}{
		{name: "IPv4", input: netip.MustParseAddr("192.0.2.1"), want: netip.MustParseAddr("192.0.2.1")},
		{name: "mapped IPv4", input: netip.MustParseAddr("::ffff:192.0.2.1"), want: netip.MustParseAddr("192.0.2.1")},
		{name: "zoned IPv6", input: netip.MustParseAddr("fe80::1%submission"), want: netip.MustParseAddr("fe80::1")},
		{name: "IPv6", input: netip.MustParseAddr("2001:db8::1"), want: netip.MustParseAddr("2001:db8::1")},
		{name: "invalid", input: netip.Addr{}, want: netip.Addr{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := CanonicalIP(test.input); got != test.want {
				t.Fatalf("CanonicalIP(%v) = %v, want %v", test.input, got, test.want)
			}
		})
	}
}

func TestAddressRoutable(t *testing.T) {
	tests := map[string]bool{
		"8.8.8.8": true, "2001:4860:4860::8888": true,
		"127.0.0.1": false, "10.0.0.1": false, "169.254.1.1": false,
		"192.0.2.1": false, "100.64.0.1": false, "198.18.0.1": false,
		"224.0.0.1": false, "::1": false, "2001:db8::1": false, "fe80::1": false,
	}
	for value, want := range tests {
		if got := AddressRoutable(netip.MustParseAddr(value)); got != want {
			t.Errorf("AddressRoutable(%q) = %v, want %v", value, got, want)
		}
	}
	if AddressRoutable(netip.Addr{}) {
		t.Fatal("invalid address is routable")
	}
}

func TestDNSHostname(t *testing.T) {
	tests := map[string]string{
		"Example.COM.":   "example.com",
		" host.example ": "host.example",
		"":               "", ".": "", "bad name.example": "", "_smtp.example": "",
		"-bad.example": "", "bad-.example": "", "bad..example": "",
		strings.Repeat("a", 64) + ".example": "",
		strings.Repeat("a", 254):             "",
	}
	for input, want := range tests {
		if got := DNSHostname(input); got != want {
			t.Errorf("DNSHostname(%q) = %q, want %q", input, got, want)
		}
	}
}
