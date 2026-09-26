package milter

import (
	"errors"
	"net"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
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
		{
			name:   "quoted semicolon cannot manufacture a pass",
			header: `nl.invades.net; dkim=fail reason="bad; dmarc=pass header.from=example.com" header.d=example.com`,
			domain: "example.com", trust: []string{"nl.invades.net"},
		},
		{
			name:   "SPF is not sufficient for correspondent authentication",
			header: "nl.invades.net; spf=pass smtp.mailfrom=example.com",
			domain: "example.com", trust: []string{"nl.invades.net"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := message.New(100)
			msg.AddHeader("Authentication-Results", test.header)
			authentication, err := (mailauth.HeaderVerifier{}).Verify(t.Context(), mailauth.Transaction{
				AuthenticationResults: msg.Headers["authentication-results"],
				TrustedAuthservIDs:    test.trust, VisibleFromDomain: test.domain,
			})
			if err != nil {
				t.Fatal(err)
			}
			got := trustedSenderAuthentication(authentication)
			if got.DKIMAligned != test.wantDKIM || got.DMARCAligned != test.wantDMARC {
				t.Fatalf("authentication evidence = %#v, want DKIM=%v DMARC=%v", got, test.wantDKIM, test.wantDMARC)
			}
		})
	}
}

func TestAuthenticationHeaderReplacementUsesUntruncatedOccurrenceCounts(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	msg := message.New(1 << 20)
	for range 3 {
		msg.AddHeader("Authentication-Results", "mx.example; dkim=pass header.d=example.com")
	}
	for range 2 {
		msg.AddHeader("Received-SPF", "pass receiver=mx.example")
	}
	ss := &session{conn: serverConn, message: msg, negotiatedActions: actionAddHeaders | actionChangeHeaders}
	done := make(chan error, 1)
	go func() {
		done <- ss.replaceAuthenticationHeaders([][2]string{{"Authentication-Results", "local.example; dkim=none"}}, true)
	}()
	for index := range 6 {
		frame, err := readFrame(clientConn)
		if err != nil {
			t.Fatal(err)
		}
		if index < 5 && (len(frame) == 0 || frame[0] != responseChangeHeader) {
			t.Fatalf("frame %d = %q, want header deletion", index, frame)
		}
		if index == 5 && (len(frame) == 0 || frame[0] != responseAddHeader) {
			t.Fatalf("frame %d = %q, want header addition", index, frame)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticationHeaderReplacementRequiresCapabilitiesInInternalMode(t *testing.T) {
	msg := message.New(1024)
	msg.AddHeader("Authentication-Results", "forged.example; dkim=pass")
	ss := &session{message: msg}
	if err := ss.replaceAuthenticationHeaders(nil, true); !errors.Is(err, ErrAuthenticationHeaderCapabilities) {
		t.Fatalf("missing change-header error = %v", err)
	}
	msg = message.New(1024)
	ss = &session{message: msg, negotiatedActions: actionChangeHeaders}
	if err := ss.replaceAuthenticationHeaders([][2]string{{"Authentication-Results", "local.example; dkim=none"}}, true); !errors.Is(err, ErrAuthenticationHeaderCapabilities) {
		t.Fatalf("missing add-header error = %v", err)
	}
}
