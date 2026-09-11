package milter

import (
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

func TestTrustedSenderAuthenticationAlignment(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		domain    string
		trust     []string
		wantDKIM  bool
		wantDMARC bool
	}{
		{
			name:   "aligned DKIM",
			header: "nl.invades.net; dkim=pass header.d=mail.example.com header.i=@example.com",
			domain: "example.com", trust: []string{"nl.invades.net"}, wantDKIM: true,
		},
		{
			name:   "aligned DMARC",
			header: "nl.invades.net; dmarc=pass header.from=example.co.uk",
			domain: "news.example.co.uk", trust: []string{"nl.invades.net"}, wantDMARC: true,
		},
		{
			name:   "untrusted authserv",
			header: "attacker.example; dkim=pass header.d=example.com",
			domain: "example.com", trust: []string{"nl.invades.net"},
		},
		{
			name:   "unaligned DKIM",
			header: "nl.invades.net; dkim=pass header.d=attacker.example",
			domain: "example.com", trust: []string{"nl.invades.net"},
		},
		{
			name:   "failed result",
			header: "nl.invades.net; dkim=fail header.d=example.com; dmarc=fail header.from=example.com",
			domain: "example.com", trust: []string{"nl.invades.net"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := message.New(100)
			msg.AddHeader("Authentication-Results", test.header)
			got := trustedSenderAuthentication(msg, test.trust, test.domain)
			if got.DKIMAligned != test.wantDKIM || got.DMARCAligned != test.wantDMARC {
				t.Fatalf("authentication evidence = %#v, want DKIM=%v DMARC=%v", got, test.wantDKIM, test.wantDMARC)
			}
		})
	}
}
