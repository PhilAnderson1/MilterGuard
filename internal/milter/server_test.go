package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
)

type fixedAnalyzer struct {
	decision ai.Decision
}

type countingAnalyzer struct {
	decision ai.Decision
	calls    atomic.Int32
}

type recordingAnalyzer struct {
	inputs chan ai.Input
}

type failingAnalyzer struct{}

type shortWriter struct {
	max int
	b   strings.Builder
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.b.Write(p)
}

func (a fixedAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	return a.decision, nil
}

func (a *countingAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	a.calls.Add(1)
	return a.decision, nil
}

func (a *recordingAnalyzer) Analyze(_ context.Context, input ai.Input) (ai.Decision, error) {
	a.inputs <- input
	return ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}, nil
}

func (failingAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	return ai.Decision{}, errors.New("endpoint unavailable")
}

func testServer(t *testing.T, analyzer Analyzer) (*Server, net.Conn, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	cfg := config.Config{
		Mode:      "enforce",
		Milter:    config.MilterConfig{Timeout: config.Duration(200 * time.Millisecond), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: 0.9, LegitimateLowConfidenceScore: 0.8, AIErrorAction: "accept", RejectMessage: "blocked"},
	}
	s := NewServer(cfg, analyzer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		s.handle(context.Background(), serverConn)
	}()
	return s, clientConn, done
}

func TestIncompatibleJSONPreventsStartupWithoutOverwritingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rejections.json")
	original := []byte("{\n  \"version\": 1,\n  \"entries\": [{\"id\": \"legacy\", \"sender\": \"bad@example.net\", \"recipient\": \"local@example.com\", \"rejected_at\": \"2026-09-07T00:00:00Z\"}]\n}\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		AI:               config.AIConfig{MaxConcurrent: 1},
		RejectionHistory: config.RejectionHistoryConfig{File: path, Expiry: config.Duration(24 * time.Hour), MaxEntries: 10},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if server.StartupError() == nil {
		t.Fatal("incompatible rejection history did not prevent startup")
	}
	if err := server.Serve(context.Background(), nil); err == nil {
		t.Fatal("Serve accepted incompatible persistent state")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, original) {
		t.Fatalf("incompatible file was modified:\n%s", after)
	}
}

func enableTestRejectedMail(t *testing.T, server *Server) string {
	t.Helper()
	root := t.TempDir()
	server.rejectedMail = rejectedmail.New(rejectedmail.Options{
		Directory: root, Retention: 24 * time.Hour, MaxMessages: 10, MaxTotalBytes: 1 << 20,
	}, server.log)
	return root
}

func archivedMessages(t *testing.T, root string) []string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		matches, err := filepath.Glob(filepath.Join(root, "*", "*", "*", "*.eml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) > 0 || time.Now().After(deadline) {
			return matches
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAIRejectedMessageIsArchived(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test rejection"}}}
	server, conn, done := testServer(t, analyzer)
	root := enableTestRejectedMail(t, server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		headerFrame("From", "sender@example.net"),
		headerFrame("X-Unselected", "archive me"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("rejected body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	files := archivedMessages(t, root)
	if len(files) != 1 {
		t.Fatalf("archived files = %v", files)
	}
	content, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"From: sender@example.net", "X-Unselected: archive me", "rejected body"} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("archive missing %q: %q", want, content)
		}
	}
}

func TestRejectedMessageArchiveUsesRejectionRecordIDs(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		AI: config.AIConfig{MaxConcurrent: 1},
		RejectionHistory: config.RejectionHistoryConfig{
			File: filepath.Join(root, "rejections.json"), Expiry: config.Duration(24 * time.Hour), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	archiveRoot := enableTestRejectedMail(t, server)
	msg := message.New(1024)
	msg.AddHeader("From", "Sender <sender@example.net>")
	msg.AddHeader("Message-ID", "<archive-id-test@example.net>")
	_, _ = msg.Body.WriteString("rejected body")

	server.recordRejection(context.Background(), msg, "bounce@example.net", []string{"one@example.com", "two@example.com"}, []string{"unwanted"}, "ai")

	entries := server.rejectionHistory.list("*")
	if len(entries) != 1 {
		t.Fatalf("rejection entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if len(entry.Recipients) != 2 {
		t.Fatalf("stored recipients = %#v", entry.Recipients)
	}
	path := filepath.Join(archiveRoot, time.Now().UTC().Format("2006"), time.Now().UTC().Format("01"), time.Now().UTC().Format("02"), fmt.Sprintf("%d.eml", entry.ID))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive for rejection ID %d: %v", entry.ID, err)
	}
}

func expectNoFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := readFrame(conn)
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected no response, got %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func expectFrame(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	got, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func negotiate(t *testing.T, conn net.Conn) {
	negotiateWithActions(t, conn, 0)
}

func negotiateWithActions(t *testing.T, conn net.Conn, actions uint32) {
	t.Helper()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	binary.BigEndian.PutUint32(payload[5:9], actions)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil || len(reply) != 13 || reply[0] != commandOptionNegotiation {
		t.Fatalf("option negotiation failed: reply=%q err=%v", reply, err)
	}
	wantActions := uint32(0)
	if actions&resultHeaderActions == resultHeaderActions {
		wantActions = resultHeaderActions
	}
	if got := binary.BigEndian.Uint32(reply[5:9]); got != wantActions {
		t.Fatalf("negotiated actions = %#x, want %#x", got, wantActions)
	}
}

func sendContinueFrames(t *testing.T, conn net.Conn, frames ...[]byte) {
	t.Helper()
	for _, frame := range frames {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseContinue}))
	}
}

func connectFrame(family byte, address string) []byte {
	return connectFrameWithHostname("mail.example", family, address)
}

func connectFrameWithHostname(hostname string, family byte, address string) []byte {
	payload := []byte{commandConnect}
	payload = append(payload, []byte(hostname+"\x00")...)
	payload = append(payload, family, 0, 25)
	payload = append(payload, []byte(address)...)
	return append(payload, 0)
}

func macroFrame(target byte, pairs ...string) []byte {
	payload := []byte{commandMacro, target}
	for _, value := range pairs {
		payload = append(payload, []byte(value)...)
		payload = append(payload, 0)
	}
	return payload
}

func envelopeFrame(command byte, address string) []byte {
	return append(append([]byte{command}, []byte("<"+address+">")...), 0)
}

func headerFrame(name, value string) []byte {
	payload := append([]byte{commandHeader}, []byte(name)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(value)...)
	return append(payload, 0)
}

func TestBelowThresholdUnwantedAddsTrustedResultHeaders(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 0.85, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.cfg.Filtering.AddEmailHeaders = true
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "legitimate"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unwanted")))
	expectFrame(t, conn, string(addHeaderResponse(scoreHeader, "0.85")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "low")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-below-threshold")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestAcceptedLegitimateAddsTrustedResultHeaders(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0.79, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.cfg.Filtering.AddEmailHeaders = true
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "legitimate")))
	expectFrame(t, conn, string(addHeaderResponse(scoreHeader, "0.79")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "low")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestTagModeAddsHeadersForEveryAIClassification(t *testing.T) {
	for _, test := range []struct {
		decision       ai.Decision
		wantScore      string
		wantConfidence string
	}{
		{ai.Decision{Classification: "legitimate", Score: 0.8, Reasons: []string{"test"}}, "0.8", "high"},
		{ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}, "1", "high"},
	} {
		t.Run(test.decision.Classification, func(t *testing.T) {
			server, conn, done := testServer(t, fixedAnalyzer{decision: test.decision})
			server.cfg.Mode = "tag"
			defer func() { _ = conn.Close(); <-done }()

			negotiateWithActions(t, conn, resultHeaderActions)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "sender@example.com"),
				envelopeFrame(commandRecipient, "recipient@example.net"),
				headerFrame("From", "Sender <sender@example.com>"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string(addHeaderResponse(classificationHeader, test.decision.Classification)))
			expectFrame(t, conn, string(addHeaderResponse(scoreHeader, test.wantScore)))
			expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, test.wantConfidence)))
			expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-tag-mode")))
			expectFrame(t, conn, string([]byte{responseAccept}))
		})
	}
}

func TestAcceptedAIErrorAddsDiagnosticHeadersWithoutScore(t *testing.T) {
	server, conn, done := testServer(t, failingAnalyzer{})
	server.cfg.Filtering.AddEmailHeaders = true
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "forged"),
		headerFrame(scoreHeader, "1"),
		headerFrame(confidenceHeader, "high"),
		headerFrame(actionHeader, "reject"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	for _, name := range resultHeaderNames {
		expectFrame(t, conn, string(deleteHeaderResponse(name)))
	}
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-ai-error")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestResultHeadersDoNotAffectDeliveryWithoutMTASupport(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 0.85, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.cfg.Filtering.AddEmailHeaders = true
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestConnectionIdentityAndDNSAreSuppliedOncePerConnection(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 2)}
	server, conn, done := testServer(t, analyzer)
	resolver := &connectionTestResolver{
		ptr:        []string{"dns.google."},
		forward:    map[string][]net.IPAddr{"dns.google": {{IP: net.ParseIP("8.8.8.8")}}},
		forwardErr: map[string]error{},
	}
	server.resolver = resolver
	server.cfg.Milter.ConnectionDNSTimeout = config.Duration(time.Second)
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

	server.logAIInput(msg, input)
	if output.Len() != 0 {
		t.Fatalf("AI input logged while disabled: %s", output.String())
	}
	server.cfg.Logging.IncludeAIInput = true
	server.logAIInput(msg, input)
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
	server.cfg.Milter.ConnectionDNSTimeout = config.Duration(time.Second)
	server.cfg.IPReputation.BlockDuration = config.Duration(time.Hour)
	server.cfg.IPReputation.MaxEntries = 100
	server.cfg.IPReputation.DomainAllowlist = []string{"google.com"}
	server.ipReputation = newIPReputationStore(server.cfg.IPReputation, server.log)
	resolver := &connectionTestResolver{
		ptr: []string{"smtp.google.com."},
		forward: map[string][]net.IPAddr{
			"smtp.google.com": {{IP: net.ParseIP("8.8.8.8")}},
		},
		forwardErr: map[string]error{},
	}
	server.resolver = resolver
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
	if _, found := server.ipReputation.lookup(netip.MustParseAddr("8.8.8.8")); found {
		t.Fatal("forward-confirmed domain-allowlisted IP was added to rejection cache")
	}
	if got := resolver.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want 1", got)
	}
	if got := resolver.forwardCalls.Load(); got != 1 {
		t.Fatalf("forward lookups = %d, want 1", got)
	}
}

func TestCommandResponseRequirements(t *testing.T) {
	for _, cmd := range []byte{commandConnect, commandHelo, commandMail, commandRecipient, commandData, commandEndHeaders, commandUnknown} {
		t.Run(string(cmd), func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
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
	for _, cmd := range []byte{commandAbort, commandMacro, commandQuitConnection} {
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

func TestParseAuthenticationMacro(t *testing.T) {
	target, identity, found, valid := parseAuthenticationMacro(macroFrame(commandMail,
		"{auth_type}", "PLAIN", "{auth_authen}", "philip@example.com")[1:])
	if !valid || !found || target != commandMail || identity != "philip@example.com" {
		t.Fatalf("parsed macro = target %q identity %q found=%v valid=%v", target, identity, found, valid)
	}
	for _, payload := range [][]byte{
		{},
		{commandMail, '{', 'a', 'u', 't', 'h', '_', 'a', 'u', 't', 'h', 'e', 'n', '}', 0},
		macroFrame(commandMail, "{auth_authen}", "first", "{auth_authen}", "second")[1:],
	} {
		if _, _, _, valid := parseAuthenticationMacro(payload); valid {
			t.Errorf("accepted malformed macro payload %q", payload)
		}
	}
}

func TestParseMTAHostnameMacro(t *testing.T) {
	target, values, valid := parseSessionMacros(macroFrame(commandConnect,
		"j", "mx.example.com", "{daemon_name}", "smtp")[1:])
	if !valid || target != commandConnect || !values.MTAHostnameFound || values.MTAHostname != "mx.example.com" {
		t.Fatalf("parsed macro = target %q values=%#v valid=%v", target, values, valid)
	}
}

func TestAuthenticatedMessagesCanBypassAndAuthenticationPersists(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	server.cfg.Filtering.ScanAuthenticated = false
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

	if err := writeFrame(conn, []byte{commandQuitConnection}); err != nil {
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

func TestAuthenticatedMessagesAreScannedWhenEnabled(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	server.cfg.Filtering.ScanAuthenticated = true
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
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestSenderDomainAllowlistBypassPolicy(t *testing.T) {
	for _, test := range []struct {
		name           string
		from           string
		authentication string
		requireDKIM    bool
		wantAICalls    int32
	}{
		{name: "exact domain without authentication requirement", from: "Orders <orders@amazon.com>", wantAICalls: 0},
		{name: "subdomain match", from: "Orders <orders@mail.amazon.com>", wantAICalls: 0},
		{name: "unrelated domain", from: "Orders <orders@amazon.example>", wantAICalls: 1},
		{name: "aligned trusted DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=amazon.com", requireDKIM: true, wantAICalls: 0},
		{name: "missing DKIM", from: "Orders <orders@amazon.com>", requireDKIM: true, wantAICalls: 1},
		{name: "unaligned DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=attacker.example", requireDKIM: true, wantAICalls: 1},
		{name: "untrusted authentication results", from: "Orders <orders@amazon.com>", authentication: "attacker.example; dkim=pass header.d=amazon.com", requireDKIM: true, wantAICalls: 1},
		{name: "DMARC alone is insufficient", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dmarc=pass header.from=amazon.com", requireDKIM: true, wantAICalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			server.cfg.Filtering.SenderDomainAllowlist = []string{"amazon.com"}
			server.cfg.Filtering.SenderDomainAllowlistRequireDKIM = test.requireDKIM
			server.cfg.Correspondents.TrustedAuthservIDs = []string{"nl.invades.net"}
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
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 100,
	}
	server.cfg.Filtering.ScanAuthenticated = false
	server.cfg.Correspondents = cfg
	server.correspondents = newCorrespondentStore(cfg, server.log)
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
		match := server.correspondents.match("alice@example.com", []string{"philip@invades.net"})
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
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 100,
	}
	server.cfg.Correspondents = cfg
	server.correspondents = newCorrespondentStore(cfg, server.log)
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
	if match := server.correspondents.match("alice@example.com", []string{"philip@invades.net"}); match.Known {
		t.Fatalf("aborted recipient was learned: %#v", match)
	}
}

func TestKnownCorrespondentIsSuppliedAsAIEvidence(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 100,
	}
	server.cfg.Correspondents = cfg
	server.correspondents = newCorrespondentStore(cfg, server.log)
	if err := server.correspondents.learn("philip@invades.net", []string{"alice@example.com"}); err != nil {
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
		"Sender authentication: no trusted aligned DKIM or DMARC result is available.",
	} {
		if !strings.Contains(input.Text, want) {
			t.Errorf("AI input missing %q:\n%s", want, input.Text)
		}
	}
}

func TestKnownCorrespondentBypassAuthenticationPolicy(t *testing.T) {
	for _, test := range []struct {
		name            string
		authentication  string
		secondRecipient string
		recipientMatch  string
		requireDKIM     bool
		wantAICalls     int32
	}{
		{name: "trusted aligned DKIM required", authentication: "nl.invades.net; dkim=pass header.d=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 0},
		{name: "untrusted DKIM required", authentication: "attacker.example; dkim=pass header.d=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 1},
		{name: "DMARC is insufficient when DKIM required", authentication: "nl.invades.net; dmarc=pass header.from=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 1},
		{name: "no authentication required", authentication: "", recipientMatch: "all", requireDKIM: false, wantAICalls: 0},
		{name: "partial match requiring all", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "all", requireDKIM: false, wantAICalls: 1},
		{name: "partial match requiring any", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "any", requireDKIM: false, wantAICalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: test.recipientMatch, BypassAI: true,
				RequireDKIMForBypass: test.requireDKIM,
				File:                 filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			server.cfg.Correspondents = cfg
			server.correspondents = newCorrespondentStore(cfg, server.log)
			if err := server.correspondents.learn("philip@invades.net", []string{"alice@example.com"}); err != nil {
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
				BypassAI: true, RequireDKIMForBypass: true, File: filepath.Join(t.TempDir(), "allowlist.json"),
				MaxEntries: 100, TrustedAuthservIDs: []string{config.MTAHostnameAuthservID},
			}
			server.cfg.Correspondents = cfg
			server.correspondents = newCorrespondentStore(cfg, server.log)
			if err := server.correspondents.learn("philip@invades.net", []string{"alice@example.com"}); err != nil {
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

func TestBypassedInboundActivityRequiresTrustedDKIM(t *testing.T) {
	for _, test := range []struct {
		name           string
		authentication string
		requireDKIM    bool
		wantRefresh    bool
	}{
		{name: "unauthenticated bypass is not refreshed", requireDKIM: false},
		{name: "trusted DKIM bypass is refreshed", authentication: "nl.invades.net; dkim=pass header.d=example.com", requireDKIM: true, wantRefresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				BypassAI: true, RequireDKIMForBypass: test.requireDKIM, File: filepath.Join(t.TempDir(), "allowlist.json"),
				MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			server.cfg.Correspondents = cfg
			server.correspondents = newCorrespondentStore(cfg, server.log)
			learnedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			server.correspondents.now = func() time.Time { return learnedAt }
			if err := server.correspondents.learn("philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			activityAt := learnedAt.Add(time.Hour)
			server.correspondents.now = func() time.Time { return activityAt }
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
			server.correspondents.mu.RLock()
			activity := server.correspondents.entries[server.correspondents.key("philip@invades.net", "alice@example.com")].LastActivityAt
			server.correspondents.mu.RUnlock()
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
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99, LegitimateSenderRequireDKIM: true,
		File: filepath.Join(t.TempDir(), "allowlist.json"), MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
	}
	server.cfg.Correspondents = cfg
	server.correspondents = newCorrespondentStore(cfg, server.log)

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
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
	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	<-done
	_ = conn.Close()
	if match := server.correspondents.match("news@example.com", []string{"philip@invades.net"}); !match.Known {
		t.Fatal("qualifying AI result did not create a known correspondent")
	}
}

func TestRejectedIPBypassesSecondAIAnalysis(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.cfg.IPReputation.BlockDuration = config.Duration(15 * time.Minute)
	server.cfg.IPReputation.MaxEntries = 100
	server.ipReputation = newIPReputationStore(server.cfg.IPReputation, server.log)
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
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}

	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestAnalysisTimeoutUsesAITimeoutWithResponseMargin(t *testing.T) {
	s := &Server{cfg: config.Config{
		Milter: config.MilterConfig{Timeout: config.Duration(30 * time.Second)},
		AI:     config.AIConfig{Timeout: config.Duration(60 * time.Second)},
	}}
	if got, want := s.analysisTimeout(), 65*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutIncludesRetryAttempts(t *testing.T) {
	s := &Server{cfg: config.Config{
		Milter: config.MilterConfig{Timeout: config.Duration(30 * time.Second)},
		AI:     config.AIConfig{Timeout: config.Duration(60 * time.Second), Retries: 2},
	}}
	if got, want := s.analysisTimeout(), 185*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutPreservesLongerMilterTimeout(t *testing.T) {
	s := &Server{cfg: config.Config{
		Milter: config.MilterConfig{Timeout: config.Duration(90 * time.Second)},
		AI:     config.AIConfig{Timeout: config.Duration(60 * time.Second)},
	}}
	if got, want := s.analysisTimeout(), 90*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestReplyCodeWireFormat(t *testing.T) {
	got := replyCode("550", "5.7.1", "Message rejected: 100% spam\ntry again")
	want := []byte("y550 5.7.1 Message rejected: 100%% spam try again\x00")
	if string(got) != string(want) {
		t.Fatalf("reply code = %q, want %q", got, want)
	}
}

func TestReplyCodeLimitsSMTPLineAndPreservesUTF8(t *testing.T) {
	got := replyCode("550", "5.7.1", strings.Repeat("é", 600))
	line := got[1 : len(got)-1]
	smtpLine := strings.ReplaceAll(string(line), "%%", "%")
	if len(smtpLine) > maxSMTPReplyBytes {
		t.Fatalf("SMTP reply is %d bytes, limit is %d", len(smtpLine), maxSMTPReplyBytes)
	}
	if !utf8.ValidString(smtpLine) {
		t.Fatal("SMTP reply was truncated inside a UTF-8 sequence")
	}
}

func TestParseHeaderPreservesEmptyValue(t *testing.T) {
	name, value, ok := parseHeader([]byte("X-Empty\x00\x00"))
	if !ok || name != "X-Empty" || value != "" {
		t.Fatalf("parseHeader = %q, %q, %v", name, value, ok)
	}
}

func TestParseHeaderRejectsTrailingData(t *testing.T) {
	if _, _, ok := parseHeader([]byte("Subject\x00test\x00extra")); ok {
		t.Fatal("accepted header payload with trailing data")
	}
}

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 2}
	if err := writeFrame(w, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	want := "\x00\x00\x00\x05hello"
	if w.b.String() != want {
		t.Fatalf("framed output = %q, want %q", w.b.String(), want)
	}
}
