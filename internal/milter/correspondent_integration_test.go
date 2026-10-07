package milter

import (
	"context"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedMessagesCanBypassAndAuthenticationPersists(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	for i := 0; i < 2; i++ {
		sendContinueFrames(t, conn,
			[]byte{commandMail},
			[]byte{commandEndHeaders},
			append([]byte{commandBody}, []byte("outbound message")...),
		)
		if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseAccept}))
	}
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}

	if err := writeFrame(conn, []byte{commandQuitSMTPConnection}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls after a new unauthenticated connection = %d, want 1", got)
	}
}

func TestExplicitEmptyAuthenticationMacroClearsAuthentication(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls for authenticated message = %d, want 0", got)
	}

	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls after explicit authentication clear = %d, want 1", got)
	}
}

func TestAuthenticatedMessagesAreScannedWhenEnabled(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "auth_authen", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	select {
	case input := <-analyzer.inputs:
		if !strings.Contains(input.Text, "Authenticated SMTP submission: yes") {
			t.Fatalf("authenticated submission context missing from AI input:\n%s", input.Text)
		}
		if strings.Contains(input.Text, "CONNECTION INFORMATION:") {
			t.Fatalf("authenticated submission includes client connection information:\n%s", input.Text)
		}
		if strings.Contains(input.Text, "DKIM: no trusted local result") ||
			strings.Contains(input.Text, "SPF: no trusted local result") ||
			strings.Contains(input.Text, "DMARC: no trusted local result") {
			t.Fatalf("authenticated submission includes unavailable inbound authentication results:\n%s", input.Text)
		}
	default:
		t.Fatal("AI analysis was not called")
	}
}

func TestSenderDomainAllowlistBypassPolicy(t *testing.T) {
	for _, test := range []struct {
		name                  string
		from                  string
		authentication        string
		requireAuthentication bool
		trustRequirement      string
		wantAICalls           int32
	}{
		{name: "exact domain without authentication requirement", from: "Orders <orders@amazon.com>", wantAICalls: 0},
		{name: "subdomain match", from: "Orders <orders@mail.amazon.com>", wantAICalls: 0},
		{name: "unrelated domain", from: "Orders <orders@amazon.example>", wantAICalls: 1},
		{name: "aligned trusted DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=amazon.com", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 0},
		{name: "aligned trusted SPF", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; spf=pass smtp.mailfrom=bounce.amazon.com", requireAuthentication: true, trustRequirement: "spf", wantAICalls: 0},
		{name: "either accepts SPF", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; spf=pass smtp.mailfrom=bounce.amazon.com", requireAuthentication: true, trustRequirement: "either", wantAICalls: 0},
		{name: "both rejects DKIM alone", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=amazon.com", requireAuthentication: true, trustRequirement: "both", wantAICalls: 1},
		{name: "both accepts SPF and DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=amazon.com; spf=pass smtp.mailfrom=bounce.amazon.com", requireAuthentication: true, trustRequirement: "both", wantAICalls: 0},
		{name: "missing authentication", from: "Orders <orders@amazon.com>", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
		{name: "unaligned DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=attacker.example", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
		{name: "untrusted authentication results", from: "Orders <orders@amazon.com>", authentication: "attacker.example; dkim=pass header.d=amazon.com", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
		{name: "DMARC alone is insufficient", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dmarc=pass header.from=amazon.com", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlist = []string{"amazon.com"} })
			setTestFiltering(server, func(cfg *config.FilteringConfig) {
				cfg.SenderDomainAllowlistRequireAuthentication = test.requireAuthentication
			})
			if test.trustRequirement != "" {
				server.sessions.policy.trustRequirement = test.trustRequirement
			}
			server.sessions.policy.correspondentCfg.TrustedAuthservIDs = []string{"nl.invades.net"}
			defer func() {
				_ = conn.Close()
				<-done
			}()

			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "sender@example.com"),
				envelopeFrame(commandRecipient, "recipient@example.net"),
				headerFrame("From", test.from),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestAuthenticatedAcceptedMessageLearnsEnvelopeRecipients(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	deadline := time.Now().Add(time.Second)
	for {
		match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"})
		if match.Known && match.AllRecipientsMatched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("authenticated recipient was not learned: %#v", match)
		}
		time.Sleep(time.Millisecond)
	}
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestAbortedAuthenticatedMessageDoesNotLearnRecipients(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, _ := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
	)
	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"}); match.Known {
		t.Fatalf("aborted recipient was learned: %#v", match)
	}
}

func TestEndOfBodyPayloadIsIncludedInAnalysis(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	_, conn, done := testServer(t, analyzer)
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("Content-Type", "text/plain; charset=UTF-8"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("first body section ")...),
	)
	if err := writeFrame(conn, append([]byte{commandEndBody}, []byte("final body section")...)); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	input := <-analyzer.inputs
	if !strings.Contains(input.Text, "SMTP envelope sender: sender@example.net") {
		t.Fatalf("AI input missing SMTP envelope sender:\n%s", input.Text)
	}
	first := strings.Index(input.Text, "first body section")
	final := strings.Index(input.Text, "final body section")
	if first < 0 || final <= first {
		t.Fatalf("AI input does not contain the complete ordered body:\n%s", input.Text)
	}
}

func TestNullEnvelopeSenderIsSuppliedAsAIEvidence(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	_, conn, done := testServer(t, analyzer)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, ""),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if input := <-analyzer.inputs; !strings.Contains(input.Text, "SMTP envelope sender: <>") {
		t.Fatalf("AI input missing null SMTP envelope sender:\n%s", input.Text)
	}
}

func TestKnownCorrespondentIsSuppliedAsAIEvidence(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "alice@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "Alice <alice@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	input := <-analyzer.inputs
	for _, want := range []string{
		"CORRESPONDENT INFORMATION:",
		"Sender found in known correspondent database: yes",
		"Basis: The visible From address was previously emailed from a relevant local address.",
		"Sender authentication: no trusted aligned SPF, DKIM, or DMARC result is available.",
	} {
		if !strings.Contains(input.Text, want) {
			t.Errorf("AI input missing %q:\n%s", want, input.Text)
		}
	}
}

func TestMultipleFromHeadersCannotBypassOrTeachSenderTrust(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true,
		UseAllowlist: true, BypassAI: true, Scope: "per_sender", RecipientMatch: "all",
		LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99,
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	setTestFiltering(server, func(cfg *config.FilteringConfig) {
		cfg.SenderDomainAllowlist = []string{"example.com"}
	})
	if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "alice@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "Alice <alice@example.com>"),
		headerFrame("From", "Bob <bob@example.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	_ = conn.Close()
	<-done
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("ambiguous sender AI analyses = %d, want 1", got)
	}
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "bob@example.net", []string{"philip@invades.net"}); match.Known {
		t.Fatal("ambiguous sender was learned as a correspondent")
	}
	if got := len(server.sessions.policy.correspondents.(*correspondentStore).snapshot()); got != 1 {
		t.Fatalf("correspondent records after ambiguous sender = %d, want the original record only", got)
	}
}

func TestKnownCorrespondentBypassAuthenticationPolicy(t *testing.T) {
	for _, test := range []struct {
		name                  string
		authentication        string
		secondRecipient       string
		recipientMatch        string
		requireAuthentication bool
		trustRequirement      string
		wantAICalls           int32
	}{
		{name: "trusted aligned DKIM", authentication: "nl.invades.net; dkim=pass header.d=example.com", recipientMatch: "all", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 0},
		{name: "trusted aligned SPF", authentication: "nl.invades.net; spf=pass smtp.mailfrom=bounce.example.com", recipientMatch: "all", requireAuthentication: true, trustRequirement: "spf", wantAICalls: 0},
		{name: "both rejects SPF alone", authentication: "nl.invades.net; spf=pass smtp.mailfrom=bounce.example.com", recipientMatch: "all", requireAuthentication: true, trustRequirement: "both", wantAICalls: 1},
		{name: "untrusted DKIM", authentication: "attacker.example; dkim=pass header.d=example.com", recipientMatch: "all", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
		{name: "unaligned SPF", authentication: "nl.invades.net; spf=pass smtp.mailfrom=attacker.example", recipientMatch: "all", requireAuthentication: true, trustRequirement: "spf", wantAICalls: 1},
		{name: "DMARC alone is insufficient", authentication: "nl.invades.net; dmarc=pass header.from=example.com", recipientMatch: "all", requireAuthentication: true, trustRequirement: "dkim", wantAICalls: 1},
		{name: "no authentication required", authentication: "", recipientMatch: "all", requireAuthentication: false, wantAICalls: 0},
		{name: "partial match requiring all", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "all", requireAuthentication: false, wantAICalls: 1},
		{name: "partial match requiring any", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "any", requireAuthentication: false, wantAICalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: test.recipientMatch, BypassAI: true,
				RequireAuthenticationForBypass: test.requireAuthentication,
				MaxEntries:                     100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if test.trustRequirement != "" {
				server.sessions.policy.trustRequirement = test.trustRequirement
			}
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = conn.Close()
				<-done
			}()
			negotiate(t, conn)
			frames := [][]byte{
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
			}
			if test.secondRecipient != "" {
				frames = append(frames, envelopeFrame(commandRecipient, test.secondRecipient))
			}
			frames = append(frames,
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			sendContinueFrames(t, conn, frames...)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestMTAHostnameMacroExpandsTrustedAuthenticationService(t *testing.T) {
	for _, test := range []struct {
		name        string
		mtaHostname string
		wantAICalls int32
	}{
		{name: "matching MTA hostname", mtaHostname: "NL.Invades.Net.", wantAICalls: 0},
		{name: "missing MTA hostname", wantAICalls: 1},
		{name: "invalid MTA hostname", mtaHostname: "not a hostname!", wantAICalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				BypassAI: true, RequireAuthenticationForBypass: true,
				MaxEntries: 100, TrustedAuthservIDs: []string{config.MTAHostnameAuthservID},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = conn.Close()
				<-done
			}()
			negotiate(t, conn)
			if test.mtaHostname != "" {
				if err := writeFrame(conn, macroFrame(commandConnect, "j", test.mtaHostname)); err != nil {
					t.Fatal(err)
				}
				expectNoFrame(t, conn)
			}
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", "nl.invades.net; dkim=pass header.d=example.com"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestBypassedInboundActivityRequiresConfiguredAuthentication(t *testing.T) {
	for _, test := range []struct {
		name                        string
		authentication              string
		requireAuthentication       bool
		trustRequirement            string
		allowedDomain               string
		domainRequireAuthentication bool
		wantRefresh                 bool
	}{
		{name: "unauthenticated bypass is not refreshed", requireAuthentication: false},
		{name: "trusted DKIM bypass is refreshed", authentication: "nl.invades.net; dkim=pass header.d=example.com", requireAuthentication: true, trustRequirement: "dkim", wantRefresh: true},
		{name: "trusted SPF bypass is refreshed", authentication: "nl.invades.net; spf=pass smtp.mailfrom=example.com", requireAuthentication: true, trustRequirement: "spf", wantRefresh: true},
		{name: "DKIM sender-domain bypass refreshes known correspondent", authentication: "nl.invades.net; dkim=pass header.d=example.com", requireAuthentication: true, trustRequirement: "dkim", allowedDomain: "example.com", domainRequireAuthentication: true, wantRefresh: true},
		{name: "SPF sender-domain bypass refreshes known correspondent", authentication: "nl.invades.net; spf=pass smtp.mailfrom=example.com", requireAuthentication: true, trustRequirement: "spf", allowedDomain: "example.com", domainRequireAuthentication: true, wantRefresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				BypassAI: true, RequireAuthenticationForBypass: test.requireAuthentication,
				MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if test.trustRequirement != "" {
				server.sessions.policy.trustRequirement = test.trustRequirement
			}
			if test.allowedDomain != "" {
				setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlist = []string{test.allowedDomain} })
				setTestFiltering(server, func(cfg *config.FilteringConfig) {
					cfg.SenderDomainAllowlistRequireAuthentication = test.domainRequireAuthentication
				})
			}
			learnedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			server.sessions.policy.correspondents.(*correspondentStore).now = func() time.Time { return learnedAt }
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			activityAt := learnedAt.Add(time.Hour)
			server.sessions.policy.correspondents.(*correspondentStore).now = func() time.Time { return activityAt }
			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			_ = conn.Close()
			<-done
			activity := server.sessions.policy.correspondents.(*correspondentStore).snapshot()["philip@invades.net\x00alice@example.com"].LastActivityAt
			want := learnedAt
			if test.wantRefresh {
				want = activityAt
			}
			if !activity.Equal(want) {
				t.Fatalf("last activity = %s, want %s", activity, want)
			}
			if got := analyzer.calls.Load(); got != 0 {
				t.Fatalf("AI analysis calls = %d, want bypass", got)
			}
		})
	}
}

func TestAIResultLearnsInboundSender(t *testing.T) {
	for _, test := range []struct {
		name           string
		authentication string
	}{
		{name: "aligned DKIM", authentication: "nl.invades.net; dkim=pass header.d=example.com"},
		{name: "aligned SPF", authentication: "nl.invades.net; spf=pass smtp.mailfrom=example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99, LegitimateSenderRequireAuthentication: true,
				MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if test.name == "aligned SPF" {
				server.sessions.policy.trustRequirement = config.AuthenticationTrustSPF
			}

			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "news@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "News <news@example.com>"),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if err := writeFrame(conn, []byte{commandQuitMilterConnection}); err != nil {
				t.Fatal(err)
			}
			<-done
			_ = conn.Close()
			if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "news@example.com", []string{"philip@invades.net"}); !match.Known {
				t.Fatal("qualifying AI result did not create a known correspondent")
			}
		})
	}
}

func TestAcceptModeDoesNotLearnFromAIResultsOrDecayIPReputation(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestMode(server, "accept")
	correspondentCfg := config.CorrespondentsConfig{
		LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99, LegitimateSenderRequireAuthentication: true,
		MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
	}
	setTestCorrespondents(server, correspondentCfg, newTestCorrespondentStore(t, correspondentCfg, server.log))
	ipCfg := config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), RepeatThreshold: 3, RepeatWindow: config.Duration(24 * time.Hour), LegitimatePerStrike: 1,
		MaxEntries: 100,
	}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("192.0.2.90")
	server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{})

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', addr.String()),
		envelopeFrame(commandMail, "news@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "News <news@example.com>"),
		headerFrame("Authentication-Results", "nl.invades.net; dkim=pass header.d=example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	_ = conn.Close()
	<-done

	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "news@example.com", []string{"philip@invades.net"}); match.Known {
		t.Fatal("accept mode learned an inbound correspondent")
	}
	strikes := len(server.sessions.policy.ipReputation.snapshot()[addr].Strikes)
	if strikes != 1 {
		t.Fatalf("accept mode changed IP strike count to %d", strikes)
	}
}

func TestAcceptModeDoesNotLearnAuthenticatedRecipients(t *testing.T) {
	server, conn, done := testServer(t, &countingAnalyzer{})
	setTestMode(server, "accept")
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	correspondentCfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestCorrespondents(server, correspondentCfg, newTestCorrespondentStore(t, correspondentCfg, server.log))

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	_ = conn.Close()
	<-done
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"}); match.Known {
		t.Fatal("accept mode learned an authenticated recipient")
	}
}

func TestRejectedIPBypassesSecondAIAnalysis(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	ipCfg := config.IPReputationConfig{
		RejectMessage: "sending IP blocked", BlockDuration: config.Duration(15 * time.Minute), MaxEntries: 100,
	}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.25"))
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("first scam")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 sending IP blocked\x00")
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}

	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	if err := writeFrame(conn, []byte{commandQuitMilterConnection}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}
