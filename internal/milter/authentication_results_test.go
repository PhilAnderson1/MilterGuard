package milter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
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

func TestInternalAuthenticationRuntimeComposition(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	trusted := buildRuntime(config.Config{}, fixedAnalyzer{}, log)
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

func TestInternalModeReplacesAllSuppliedAuthenticationHeaders(t *testing.T) {
	evidence := mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodSPF, Outcome: mailauth.OutcomePass, Domain: "bounce.example.net", SPFIdentity: "mailfrom"},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "example.com", Selector: "selector", Algorithm: "rsa-sha256"},
		{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomePass, Domain: "example.com"},
	}, "example.com")
	verifier := &fixedAuthenticationVerifier{evidence: evidence}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
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
	for range 2 {
		expectFrame(t, conn, string(deleteHeaderResponse("Authentication-Results")))
	}
	expectFrame(t, conn, string(deleteHeaderResponse("Received-SPF")))
	value, err := mailauth.RenderAuthenticationResults("mx.example.net", evidence)
	if err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(addHeaderResponse("Authentication-Results", value)))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if verifier.calls.Load() != 1 {
		t.Fatalf("authentication verifier calls = %d", verifier.calls.Load())
	}
}

func TestInternalModeTempfailsUnsafeAuthenticationHeaderConfiguration(t *testing.T) {
	for _, test := range []struct {
		name        string
		actions     uint32
		mtaHostname string
	}{
		{name: "missing add-header capability", actions: actionChangeHeaders, mtaHostname: "mx.example.net"},
		{name: "missing change-header capability", actions: actionAddHeaders, mtaHostname: "mx.example.net"},
		{name: "missing MTA hostname", actions: resultHeaderActions},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier := &fixedAuthenticationVerifier{evidence: mailauth.Evidence{}}
			server, conn, done := testServer(t, fixedAnalyzer{})
			server.sessions.authenticationMode = config.AuthenticationModeInternal
			server.sessions.authentication = verifier
			defer func() { _ = conn.Close(); <-done }()

			negotiateWithExpectedActions(t, conn, test.actions, test.actions)
			if test.mtaHostname != "" {
				if err := writeFrame(conn, macroFrame(commandConnect, "j", test.mtaHostname, "{daemon_addr}", "192.0.2.25")); err != nil {
					t.Fatal(err)
				}
				expectNoFrame(t, conn)
			}
			frames := [][]byte{
				connectFrame('4', "198.51.100.9"),
				envelopeFrame(commandMail, "bounce@example.net"),
				headerFrame("From", "Sender <sender@example.com>"),
			}
			frames = append(frames, []byte{commandEndHeaders})
			sendContinueFrames(t, conn, frames...)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseTempfail}))
		})
	}
}

func TestInternalModeAuthenticatedSubmissionSkipsVerificationAndOnlyStripsResults(t *testing.T) {
	verifier := &fixedAuthenticationVerifier{}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
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
	expectFrame(t, conn, string(deleteHeaderResponse("Authentication-Results")))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if verifier.calls.Load() != 0 {
		t.Fatalf("authenticated submission verifier calls = %d", verifier.calls.Load())
	}
}

func TestInternalModeRendersProviderFailureAsUnavailable(t *testing.T) {
	verifier := &fixedAuthenticationVerifier{err: errors.New("verification deadline exceeded")}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
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
	want := "mx.example.net;\r\n\tspf=temperror;\r\n\tdkim=temperror;\r\n\tdmarc=temperror header.from=example.com"
	expectFrame(t, conn, string(addHeaderResponse("Authentication-Results", want)))
	expectFrame(t, conn, string([]byte{responseAccept}))
}
