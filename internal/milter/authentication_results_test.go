package milter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth/moxverify"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type fixedAuthenticationVerifier struct {
	evidence mailauth.Evidence
	err      error
	calls    atomic.Int32
}

func (v *fixedAuthenticationVerifier) Verify(context.Context, mailauth.Transaction) (mailauth.Evidence, error) {
	v.calls.Add(1)
	return v.evidence, v.err
}

func TestAlignedSenderAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		domain    string
		trust     []string
		wantDKIM  bool
		wantSPF   bool
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
			name:   "aligned SPF",
			header: "nl.invades.net; spf=pass smtp.mailfrom=example.com",
			domain: "example.com", trust: []string{"nl.invades.net"}, wantSPF: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg := message.New(100)
			msg.AddHeader("Authentication-Results", test.header)
			authentication, err := (mailauth.HeaderVerifier{}).Verify(t.Context(), mailauth.Transaction{
				AuthenticationResults: msg.HeaderValues("Authentication-Results"),
				TrustedAuthservIDs:    test.trust, VisibleFromDomain: test.domain,
			})
			if err != nil {
				t.Fatal(err)
			}
			if authentication.DKIMAligned != test.wantDKIM || authentication.SPFAligned != test.wantSPF || authentication.DMARCAligned != test.wantDMARC {
				t.Fatalf("authentication evidence = %#v, want DKIM=%v SPF=%v DMARC=%v", authentication, test.wantDKIM, test.wantSPF, test.wantDMARC)
			}
		})
	}
}

func TestSenderAuthenticationTrustRequirements(t *testing.T) {
	tests := []struct {
		name        string
		evidence    mailauth.Evidence
		requirement string
		want        bool
	}{
		{name: "DKIM accepts DKIM", evidence: mailauth.Evidence{DKIMAligned: true}, requirement: config.AuthenticationTrustDKIM, want: true},
		{name: "DKIM rejects SPF", evidence: mailauth.Evidence{SPFAligned: true}, requirement: config.AuthenticationTrustDKIM},
		{name: "SPF accepts SPF", evidence: mailauth.Evidence{SPFAligned: true}, requirement: config.AuthenticationTrustSPF, want: true},
		{name: "either accepts DKIM", evidence: mailauth.Evidence{DKIMAligned: true}, requirement: config.AuthenticationTrustEither, want: true},
		{name: "either accepts SPF", evidence: mailauth.Evidence{SPFAligned: true}, requirement: config.AuthenticationTrustEither, want: true},
		{name: "both rejects DKIM alone", evidence: mailauth.Evidence{DKIMAligned: true}, requirement: config.AuthenticationTrustBoth},
		{name: "both accepts both", evidence: mailauth.Evidence{DKIMAligned: true, SPFAligned: true}, requirement: config.AuthenticationTrustBoth, want: true},
		{name: "DMARC is not an independent option", evidence: mailauth.Evidence{DMARCAligned: true}, requirement: config.AuthenticationTrustEither},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := meetsTrustRequirement(test.evidence, test.requirement); got != test.want {
				t.Fatalf("trust result = %v, want %v", got, test.want)
			}
		})
	}
}

func TestInternalAuthenticationRuntimeComposition(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	trusted := buildRuntime(config.Config{Authentication: config.AuthenticationConfig{
		Mode: config.AuthenticationModeTrustedHeaders,
	}}, fixedAnalyzer{}, log)
	if _, ok := trusted.sessions.authentication.(mailauth.HeaderVerifier); !ok || trusted.sessions.authenticationMode != config.AuthenticationModeTrustedHeaders {
		t.Fatalf("default authentication provider = %T mode=%q", trusted.sessions.authentication, trusted.sessions.authenticationMode)
	}

	internal := buildRuntime(config.Config{Authentication: config.AuthenticationConfig{
		Mode: config.AuthenticationModeInternal, Timeout: config.Duration(time.Second), MaxConcurrent: 2, MessageStorage: "file",
	}}, fixedAnalyzer{}, log)
	if internal.err != nil {
		t.Fatal(internal.err)
	}
	if _, ok := internal.sessions.authentication.(*moxverify.Verifier); !ok || internal.sessions.authenticationMode != config.AuthenticationModeInternal || internal.sessions.protocol.exactStorage != "file" {
		t.Fatalf("internal authentication provider = %T mode=%q storage=%q", internal.sessions.authentication, internal.sessions.authenticationMode, internal.sessions.protocol.exactStorage)
	}
}

func TestExactMessageCaptureMatchesAuthenticationProviderNeeds(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want bool
	}{
		{name: "trusted headers", mode: config.AuthenticationModeTrustedHeaders},
		{name: "internal", mode: config.AuthenticationModeInternal, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			created := false
			ss := &session{deps: &sessionDependencies{
				authenticationMode: test.mode,
				protocol:           protocolOptions{maxMessageSize: 1024, exactStorage: "memory"},
				newExactMessage: func(string, int64) (mailauth.ExactMessage, error) {
					created = true
					return mailauth.NewExactMessage("memory", 1024)
				},
			}}
			ss.resetMessage(phaseEnvelope)
			defer ss.closeExactMessage()
			if created != test.want {
				t.Fatalf("exact-message store created = %t, want %t", created, test.want)
			}
		})
	}
}

func TestInternalModeIgnoresAuthenticationHeadersWithoutMutatingThem(t *testing.T) {
	verifier := &recordingVerifier{observations: make(chan authenticationObservation, 1)}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	if err := writeFrame(conn, macroFrame(commandConnect, "j", "mx.example.net", "{daemon_addr}", "192.0.2.25")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "198.51.100.9"),
		append([]byte{commandHelo}, []byte("helo.example.net\x00")...),
		envelopeFrame(commandMail, "bounce@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("Authentication-Results", "forged-one.example; dkim=pass header.d=example.com"),
		headerFrame("Authentication-Results", "forged-two.example; dmarc=pass header.from=example.com"),
		headerFrame("Received-SPF", "pass receiver=forged.example"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("body\r\n")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	observation := <-verifier.observations
	if len(observation.transaction.AuthenticationResults) != 0 || len(observation.transaction.ReceivedSPF) != 0 || len(observation.transaction.TrustedAuthservIDs) != 0 {
		t.Fatalf("internal verifier received authentication headers: %#v", observation.transaction)
	}
	for _, want := range []string{"Authentication-Results: forged-one.example", "Authentication-Results: forged-two.example", "Received-SPF: pass receiver=forged.example"} {
		if !strings.Contains(string(observation.message), want) {
			t.Fatalf("byte-exact DKIM input missing preserved header %q: %q", want, observation.message)
		}
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestInternalModeAuthenticatedSubmissionSkipsVerificationAndPreservesResults(t *testing.T) {
	verifier := &fixedAuthenticationVerifier{}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "alice@example.net")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "alice@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("Authentication-Results", "forged.example; dkim=pass header.d=example.net"),
		headerFrame("From", "Alice <alice@example.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if verifier.calls.Load() != 0 {
		t.Fatalf("authenticated submission verifier calls = %d", verifier.calls.Load())
	}
}

func TestInternalModeDoesNotPublishProviderFailure(t *testing.T) {
	verifier := &fixedAuthenticationVerifier{err: errors.New("verification deadline exceeded")}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	if err := writeFrame(conn, macroFrame(commandConnect, "j", "mx.example.net", "{daemon_addr}", "192.0.2.25")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "198.51.100.9"),
		envelopeFrame(commandMail, "bounce@example.net"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
}
