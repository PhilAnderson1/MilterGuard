package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConnectionIdentityAndDNSAreSuppliedOncePerConnection(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 2)}
	server, conn, done := testServer(t, analyzer)
	resolver := &connectionTestResolver{
		ptr:        []string{"dns.google."},
		forward:    map[string][]net.IPAddr{"dns.google": {{IP: net.ParseIP("8.8.8.8")}}},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	server.sessions.dns.timeout = time.Second
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrameWithHostname("mta-claimed.example", '4', "8.8.8.8"),
		append([]byte{commandHelo}, []byte("helo-claimed.example\x00")...),
	)
	for i := 0; i < 2; i++ {
		sendContinueFrames(t, conn,
			[]byte{commandMail},
			[]byte{commandEndHeaders},
			append([]byte{commandBody}, []byte("test")...),
		)
		if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseAccept}))
		input := <-analyzer.inputs
		for _, want := range []string{
			"Remote IP: 8.8.8.8",
			"MTA-reported client hostname: mta-claimed.example",
			"Reverse DNS: dns.google (forward-confirmed)",
			"Forward-confirmed reverse DNS: yes",
			"SMTP HELO/EHLO identity: helo-claimed.example",
		} {
			if !strings.Contains(input.Text, want) {
				t.Errorf("analysis input missing %q:\n%s", want, input.Text)
			}
		}
	}
	if got := resolver.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want exactly 1 for the SMTP connection", got)
	}
	if got := resolver.forwardCalls.Load(); got != 1 {
		t.Fatalf("forward lookups = %d, want exactly 1 for the SMTP connection", got)
	}
}

func TestAIInputDiagnosticLoggingIsExplicitAndOmitsImageData(t *testing.T) {
	msg := message.New(100)
	msg.AddHeader("Message-ID", "<diagnostic@example.com>")
	input := ai.Input{
		Text:   "SELECTED HEADERS:\nAuthentication-Results: mx.example; dkim=pass",
		Images: []ai.Image{{MediaType: "image/png", Data: []byte("SECRET_IMAGE_BYTES")}},
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := NewServer(config.Config{
		AI:           config.AIConfig{MaxConcurrent: 1},
		IPReputation: config.IPReputationConfig{MaxEntries: 1},
	}, fixedAnalyzer{}, logger)

	server.sessions.analysis.logAIInput(msg, input, server.sessions.logging.IncludeAIInput)
	if output.Len() != 0 {
		t.Fatalf("AI input logged while disabled: %s", output.String())
	}
	server.sessions.logging.IncludeAIInput = true
	server.sessions.analysis.logAIInput(msg, input, server.sessions.logging.IncludeAIInput)
	logged := output.String()
	for _, want := range []string{
		`"msg":"AI analysis input"`,
		`"message_id":"<diagnostic@example.com>"`,
		`"ai_input":"SELECTED HEADERS:\nAuthentication-Results: mx.example; dkim=pass"`,
		`"image_count":1`,
		`"media_type":"image/png"`,
		`"bytes":18`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("diagnostic log missing %s: %s", want, logged)
		}
	}
	if strings.Contains(logged, "SECRET_IMAGE_BYTES") {
		t.Fatalf("diagnostic log exposed image data: %s", logged)
	}
}

func TestRejectedIPDomainAllowlistReusesConnectionDNS(t *testing.T) {
	server, conn, _ := testServer(t, fixedAnalyzer{decision: ai.Decision{
		Classification: "unwanted", Score: 1, Reasons: []string{"test"},
	}})
	server.sessions.dns.timeout = time.Second
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100, DomainAllowlist: []string{"google.com"}}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	resolver := &connectionTestResolver{
		ptr: []string{"smtp.google.com."},
		forward: map[string][]net.IPAddr{
			"smtp.google.com": {{IP: net.ParseIP("8.8.8.8")}},
		},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "8.8.8.8"),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("unwanted")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if _, found := server.sessions.policy.ipReputation.lookup(context.Background(), netip.MustParseAddr("8.8.8.8")); found {
		t.Fatal("forward-confirmed domain-allowlisted IP was added to rejection cache")
	}
	if got := resolver.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want 1", got)
	}
	if got := resolver.forwardCalls.Load(); got != 1 {
		t.Fatalf("forward lookups = %d, want 1", got)
	}
}

func TestForwardConfirmedDomainAllowlistBypassesExistingIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.sessions.dns.timeout = time.Second
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100, DomainAllowlist: []string{"google.com"}}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("8.8.8.8")
	if !server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{status: message.ReverseDNSLookupFailed}) {
		t.Fatal("test IP was not initially blocked")
	}
	resolver := &connectionTestResolver{
		ptr:        []string{"smtp.google.com."},
		forward:    map[string][]net.IPAddr{"smtp.google.com": {{IP: net.ParseIP(addr.String())}}},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', addr.String()),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("legitimate message")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1 after cached block bypass", got)
	}
	if resolver.ptrCalls.Load() != 1 || resolver.forwardCalls.Load() != 1 {
		t.Fatalf("DNS calls = PTR %d, forward %d; want one each", resolver.ptrCalls.Load(), resolver.forwardCalls.Load())
	}
	_, retained := server.sessions.policy.ipReputation.snapshot()[addr]
	if !retained {
		t.Fatal("domain allowlist bypass unexpectedly deleted persisted IP reputation")
	}
}

func TestAuthenticatedSubmissionBypassesExistingIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("192.0.2.25")
	if !server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{}) {
		t.Fatal("test IP was not initially blocked")
	}
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', addr.String()))
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
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
	if _, retained := server.sessions.policy.ipReputation.lookup(context.Background(), addr); !retained {
		t.Fatal("authenticated bypass unexpectedly removed existing IP reputation")
	}
}

func TestRejectedAuthenticatedSubmissionDoesNotCreateIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("192.0.2.26")
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', addr.String()))
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
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if _, blocked := server.sessions.policy.ipReputation.lookup(context.Background(), addr); blocked {
		t.Fatal("authenticated submission created IP reputation block")
	}
}

func TestCommandResponseRequirements(t *testing.T) {
	for _, cmd := range []byte{commandConnect, commandHelo, commandMail, commandRecipient, commandData, commandEndHeaders, commandUnknown} {
		t.Run(string(cmd), func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if cmd != commandConnect {
				sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
			}
			if cmd == commandRecipient || cmd == commandData || cmd == commandEndHeaders {
				if err := writeFrame(conn, []byte{commandMail}); err != nil {
					t.Fatal(err)
				}
				expectFrame(t, conn, "c")
			}
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, "c")
		})
	}
	for _, cmd := range []byte{commandAbort, commandMacro, commandQuitSMTPConnection} {
		t.Run(string(cmd)+"_no_response", func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectNoFrame(t, conn)
		})
	}
}

func TestOptionNegotiationResponse(t *testing.T) {
	_, conn, _ := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 13 || reply[0] != commandOptionNegotiation || binary.BigEndian.Uint32(reply[1:5]) != 6 {
		t.Fatalf("unexpected negotiation response: %q", reply)
	}
}

func TestParseConnectIP(t *testing.T) {
	tests := []struct {
		family  byte
		address string
		want    string
	}{
		{family: '4', address: "192.0.2.25", want: "192.0.2.25"},
		{family: '6', address: "2001:db8::25", want: "2001:db8::25"},
		{family: '6', address: "2001:db8::25%untrusted", want: "2001:db8::25"},
	}
	for _, test := range tests {
		frame := connectFrame(test.family, test.address)
		addr, ok := parseConnectIP(frame[1:])
		if !ok || addr.String() != test.want {
			t.Errorf("parseConnectIP(%q) = %s, %v; want %s", test.address, addr, ok, test.want)
		}
	}
	for _, payload := range [][]byte{
		{},
		[]byte("host\x004\x00\x19not-an-ip\x00"),
		connectFrame('4', "2001:db8::1")[1:],
	} {
		if addr, ok := parseConnectIP(payload); ok {
			t.Errorf("accepted malformed CONNECT address %s", addr)
		}
	}
}

func TestParseAndCleanConnectAndHELOIdentities(t *testing.T) {
	frame := connectFrameWithHostname("claimed.example", '4', "192.0.2.25")
	if got, ok := parseConnectHostname(frame[1:]); !ok || got != "claimed.example" {
		t.Fatalf("CONNECT hostname = %q, %v", got, ok)
	}
	if got, ok := parseSMTPIdentity([]byte("helo.example\x00")); !ok || got != "helo.example" {
		t.Fatalf("HELO identity = %q, %v", got, ok)
	}
	for _, unavailable := range []string{"", "unknown", "[UNKNOWN]", " \tunknown\r\n"} {
		if got := cleanSMTPIdentity(unavailable); got != "" {
			t.Errorf("cleanSMTPIdentity(%q) = %q, want unavailable", unavailable, got)
		}
	}
	if got := cleanSMTPIdentity("mx.example\r\nforged"); got != "mx.exampleforged" {
		t.Errorf("sanitized identity = %q", got)
	}
	if _, ok := parseSMTPIdentity([]byte("embedded\x00value\x00")); ok {
		t.Fatal("accepted HELO identity containing an embedded NUL")
	}
}

func TestParseAuthenticationSessionMacro(t *testing.T) {
	target, values, valid := parseSessionMacros(macroFrame(commandMail,
		"{auth_type}", "PLAIN", "{auth_authen}", "philip@example.com")[1:])
	if !valid || !values.AuthenticationFound || target != commandMail || values.AuthenticationIdentity != "philip@example.com" {
		t.Fatalf("parsed macro = target %q values=%#v valid=%v", target, values, valid)
	}
	for _, payload := range [][]byte{
		{},
		{commandMail, '{', 'a', 'u', 't', 'h', '_', 'a', 'u', 't', 'h', 'e', 'n', '}', 0},
		macroFrame(commandMail, "{auth_authen}", "first", "{auth_authen}", "second")[1:],
	} {
		if _, _, valid := parseSessionMacros(payload); valid {
			t.Errorf("accepted malformed macro payload %q", payload)
		}
	}
}

func TestParseMTAHostnameMacro(t *testing.T) {
	target, values, valid := parseSessionMacros(macroFrame(commandConnect,
		"j", "mx.example.com", "{daemon_name}", "smtp", "{daemon_addr}", "2001:db8::25")[1:])
	if !valid || target != commandConnect || !values.MTAHostnameFound || values.MTAHostname != "mx.example.com" ||
		!values.ReceiverAddressFound || values.ReceiverAddress != "2001:db8::25" {
		t.Fatalf("parsed macro = target %q values=%#v valid=%v", target, values, valid)
	}
	if got := canonicalMacroIP("[IPv6:2001:db8::25]"); got.String() != "2001:db8::25" {
		t.Fatalf("canonical receiver address = %s", got)
	}
	if got := canonicalMacroIP("not-an-address"); got.IsValid() {
		t.Fatalf("invalid receiver address accepted as %s", got)
	}
}
