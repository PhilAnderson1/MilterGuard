package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
)

type fakeReplySender struct {
	messages chan smtpreply.Message
	err      error
	panic    bool
}

type synchronizedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (s *fakeReplySender) Send(_ context.Context, message smtpreply.Message) error {
	if s.messages != nil {
		s.messages <- message
	}
	if s.panic {
		panic("test reply sender panic")
	}
	return s.err
}

func commandTestServer(t *testing.T, allowUsers bool, administrators []string) (*Server, *countingAnalyzer, net.Conn, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	cfg := config.Config{
		Mode:           "enforce",
		Milter:         config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 64 << 10},
		AI:             config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering:      config.FilteringConfig{RejectScore: .9, ScanAuthenticated: false},
		EmailCommands:  config.EmailCommandsConfig{Enabled: true, Recipient: "milterguard@example.com", AllowAuthenticatedUsers: allowUsers, Administrators: administrators, SendReplies: false, MaxMessageBytes: 8192},
		Correspondents: config.CorrespondentsConfig{UseAllowlist: true, MaxEntries: 100, Scope: "per_sender", RecipientMatch: "all"},
		IPReputation:   config.IPReputationConfig{MaxEntries: 100},
		Persistence:    config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
	}
	server := NewServer(cfg, analyzer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() { defer close(done); defer serverConn.Close(); server.handle(context.Background(), serverConn) }()
	return server, analyzer, clientConn, done
}

func submitCommand(t *testing.T, conn net.Conn, identity, from string, recipients []string, body string) []byte {
	t.Helper()
	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.10"))
	if identity != "" {
		if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", identity)); err != nil {
			t.Fatal(err)
		}
	}
	frames := [][]byte{envelopeFrame(commandMail, from)}
	for _, recipient := range recipients {
		frames = append(frames, envelopeFrame(commandRecipient, recipient))
	}
	frames = append(frames, headerFrame("Content-Type", "text/plain; charset=UTF-8"), []byte{commandEndHeaders}, append([]byte{commandBody}, []byte(body)...))
	sendContinueFrames(t, conn, frames...)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	response, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestAuthenticatedUserEmailCommandAddsOwnRelationshipAndDiscards(t *testing.T) {
	server, analyzer, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done }()
	response := submitCommand(t, conn, "philip", "phil@example.com", []string{"milterguard@example.com"}, "WHITELIST ADD news@example.net")
	if len(response) != 1 || response[0] != responseDiscard {
		t.Fatalf("response = %q, want discard", response)
	}
	if analyzer.calls.Load() != 0 {
		t.Fatal("command message was sent to AI")
	}
	match := testCorrespondentMatch(server.sessions.policy.correspondents, context.Background(), "news@example.net", []string{"phil@example.com"})
	if !match.Known {
		t.Fatal("command did not add live correspondent relationship")
	}
}

func TestEmailCommandBatchRunsSequentiallyAndStopsAtText(t *testing.T) {
	server, analyzer, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done }()
	body := "WHITELIST ADD old@example.net\nWHITELIST DELETE old@example.net\nWHITELIST ADD current@example.net\nThanks"
	response := submitCommand(t, conn, "philip", "phil@example.com", []string{"milterguard@example.com"}, body)
	if len(response) != 1 || response[0] != responseDiscard {
		t.Fatalf("response = %q, want discard", response)
	}
	if analyzer.calls.Load() != 0 {
		t.Fatal("command message was sent to AI")
	}
	if testCorrespondentMatch(server.sessions.policy.correspondents, context.Background(), "old@example.net", []string{"phil@example.com"}).Known {
		t.Fatal("deleted batch entry remains")
	}
	if !testCorrespondentMatch(server.sessions.policy.correspondents, context.Background(), "current@example.net", []string{"phil@example.com"}).Known {
		t.Fatal("later batch command was not executed")
	}
}

func TestUnauthenticatedCommandRecipientIsContinuedAtRCPTAndRejectedAtEOM(t *testing.T) {
	_, analyzer, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done }()
	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.10"), envelopeFrame(commandMail, "outsider@example.net"))
	sendContinueFrames(t, conn,
		envelopeFrame(commandRecipient, "milterguard@example.com"),
		headerFrame("Content-Type", "text/plain; charset=UTF-8"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("HELP")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	response, err := readFrame(conn)
	if err != nil || len(response) == 0 || response[0] != responseReply {
		t.Fatalf("EOM response = %q, err = %v; want SMTP rejection", response, err)
	}
	if !strings.Contains(string(response), "authentication required") {
		t.Fatalf("response does not explain authentication failure: %q", response)
	}
	if analyzer.calls.Load() != 0 {
		t.Fatal("rejected command was sent to AI")
	}
}

func TestMixedRecipientCommandIsRejectedWithoutExecution(t *testing.T) {
	_, analyzer, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done }()
	response := submitCommand(t, conn, "philip", "phil@example.com", []string{"milterguard@example.com", "other@example.com"}, "WHITELIST ADD news@example.net")
	if len(response) == 0 || response[0] != responseReply {
		t.Fatalf("response = %q, want SMTP rejection", response)
	}
	if analyzer.calls.Load() != 0 {
		t.Fatal("rejected command was sent to AI")
	}
}

func TestCommandReplyMessageIncludesMarkerAndAttachment(t *testing.T) {
	original := []byte("From: sender@example.net\r\nTo: local@example.com\r\nSubject: Original\r\n\r\nOriginal body\r\n")
	message := commandReplyMessage(
		"milterguard@example.com", "local@example.com", "MilterGuard command results",
		"Sun, 13 Sep 2026 07:00:00 +0000", "token",
		commandReplyContent{
			Text: "Rejection details\n",
			Attachments: []smtpreply.Attachment{{
				Filename: "rejection-12.eml", MediaType: "application/octet-stream", Contents: original,
			}},
		},
	)
	if len(message.Headers) != 1 || message.Headers[0].Name != internalMessageHeader || message.Headers[0].Value != "token" {
		t.Fatalf("internal headers = %#v", message.Headers)
	}
	if len(message.Attachments) != 1 || !bytes.Equal(message.Attachments[0].Contents, original) {
		t.Fatalf("attachments = %#v", message.Attachments)
	}
}

func TestBoundedCommandReplyPayloadOmitsOversizedAttachment(t *testing.T) {
	reply, err := buildBoundedCommandReplyMessage(
		"milterguard@example.com", "local@example.com", "Results", "date", "token",
		commandReplyContent{
			Text: "Rejection details\n",
			Attachments: []smtpreply.Attachment{{
				Filename: "rejection-12.eml", MediaType: "application/octet-stream", Contents: bytes.Repeat([]byte("x"), 1024),
			}},
		}, 512,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := smtpreply.Build(reply)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(message.Header.Get("Content-Type"), "multipart/") {
		t.Fatalf("oversized reply remained multipart: %s", message.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(message.Body)
	if err != nil || !strings.Contains(string(body), "too large to attach") {
		t.Fatalf("fallback body = %q, err=%v", body, err)
	}
}

func TestBoundedCommandReplyPayloadLimitsPlainText(t *testing.T) {
	reply, err := buildBoundedCommandReplyMessage(
		"milterguard@example.com", "local@example.com", "Results", "date", "token",
		commandReplyContent{Text: strings.Repeat("x", admincmd.MaxResponseBytes+1024)}, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := smtpreply.Build(reply)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(message.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > admincmd.MaxResponseBytes {
		t.Fatalf("reply body length = %d, want at most %d", len(body), admincmd.MaxResponseBytes)
	}
	if !strings.Contains(string(body), "Command reply was truncated at 1 MiB.") {
		t.Fatal("bounded reply does not report truncation")
	}
}

func TestBoundedCommandReplyTextPreservesUTF8(t *testing.T) {
	text := strings.Repeat("é", admincmd.MaxResponseBytes)
	bounded := boundedCommandReplyText(text)
	if len(bounded) > admincmd.MaxResponseBytes {
		t.Fatalf("bounded text length = %d", len(bounded))
	}
	if !utf8.ValidString(bounded) {
		t.Fatal("bounded text is not valid UTF-8")
	}
}

func TestBoundedCommandReplyAddsNoticeAfterExistingFullText(t *testing.T) {
	var body strings.Builder
	body.WriteString(strings.Repeat("x", admincmd.MaxResponseBytes))
	if admincmd.AppendBoundedResponse(&body, "more") {
		t.Fatal("append unexpectedly succeeded")
	}
	if body.Len() > admincmd.MaxResponseBytes {
		t.Fatalf("reply length = %d", body.Len())
	}
	if !strings.HasSuffix(body.String(), "\nCommand reply was truncated at 1 MiB.\n") {
		t.Fatal("full reply was not shortened to include the truncation notice")
	}
}

func TestEmailCommandReplyRenderingIsDeferredToWorker(t *testing.T) {
	sender := &fakeReplySender{messages: make(chan smtpreply.Message, 1)}
	service := &emailCommandService{
		cfg:           config.EmailCommandsConfig{SendReplies: true, Recipient: "milterguard@example.com"},
		internalToken: "token", replySlots: make(chan struct{}, 1), sender: sender,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), maxMessageSize: 4096,
	}
	release := make(chan struct{})
	queued := service.queueReplyContentFunc("recipient@example.com", "Results", func() commandReplyContent {
		<-release
		return commandReplyContent{Text: "deferred result"}
	})
	if !queued {
		t.Fatal("reply was not queued")
	}
	select {
	case <-sender.messages:
		t.Fatal("reply content was rendered synchronously")
	default:
	}
	close(release)
	select {
	case message := <-sender.messages:
		if message.To != "recipient@example.com" || message.Subject != "Results" || message.Text != "deferred result" {
			t.Fatalf("reply message = %#v", message)
		}
		if len(message.Headers) != 1 || message.Headers[0].Value != "token" {
			t.Fatalf("reply headers = %#v", message.Headers)
		}
	case <-time.After(time.Second):
		t.Fatal("deferred reply was not delivered")
	}
}

func TestEmailCommandReplyQueueLimit(t *testing.T) {
	sender := &fakeReplySender{messages: make(chan smtpreply.Message, 1)}
	service := &emailCommandService{
		cfg: config.EmailCommandsConfig{SendReplies: true}, replySlots: make(chan struct{}, 1),
		sender: sender, log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	service.replySlots <- struct{}{}
	if service.queueReply("recipient@example.com", "Results", "body") {
		t.Fatal("reply was queued despite a full worker queue")
	}
	select {
	case <-sender.messages:
		t.Fatal("sender was called despite a full worker queue")
	default:
	}
}

func TestEmailCommandReplyWorkerContainsSenderPanicAndReleasesSlot(t *testing.T) {
	panicking := &fakeReplySender{messages: make(chan smtpreply.Message, 1), panic: true}
	service := &emailCommandService{
		cfg: config.EmailCommandsConfig{SendReplies: true}, replySlots: make(chan struct{}, 1),
		sender: panicking, log: slog.New(slog.NewTextHandler(io.Discard, nil)), maxMessageSize: 4096,
	}
	if !service.queueReply("recipient@example.com", "Results", "body") {
		t.Fatal("reply was not queued")
	}
	select {
	case <-panicking.messages:
	case <-time.After(time.Second):
		t.Fatal("panicking sender was not called")
	}
	deadline := time.Now().Add(time.Second)
	for len(service.replySlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(service.replySlots) != 0 {
		t.Fatal("reply slot was not released after panic")
	}
	replacement := &fakeReplySender{messages: make(chan smtpreply.Message, 1), err: errors.New("test delivery failure")}
	service.sender = replacement
	if !service.queueReply("recipient@example.com", "Results", "body") {
		t.Fatal("reply slot could not be reused")
	}
	select {
	case <-replacement.messages:
	case <-time.After(time.Second):
		t.Fatal("replacement sender was not called")
	}
}

func TestEmailCommandReplyDeliveryFailureIsLogged(t *testing.T) {
	var output synchronizedBuffer
	sender := &fakeReplySender{messages: make(chan smtpreply.Message, 1), err: errors.New("test delivery failure")}
	service := &emailCommandService{
		cfg:        config.EmailCommandsConfig{SendReplies: true, SMTPHost: "smtp.example:25"},
		replySlots: make(chan struct{}, 1), sender: sender,
		log: slog.New(slog.NewTextHandler(&output, nil)), maxMessageSize: 4096,
	}
	if !service.queueReply("recipient@example.com", "Results", "body") {
		t.Fatal("reply was not queued")
	}
	select {
	case <-sender.messages:
	case <-time.After(time.Second):
		t.Fatal("failing sender was not called")
	}
	deadline := time.Now().Add(time.Second)
	for len(service.replySlots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	logged := output.String()
	if !strings.Contains(logged, "cannot send email command confirmation") ||
		!strings.Contains(logged, "test delivery failure") || !strings.Contains(logged, "smtp.example:25") {
		t.Fatalf("delivery failure log = %q", logged)
	}
}

func TestCommandMessageRequiresSmallPlainTextBody(t *testing.T) {
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/plain; charset=UTF-8")
	msg.AddHeader("Content-Transfer-Encoding", "quoted-printable")
	msg.AddBody([]byte("WHITELIST ADD news=40example.net\n\nQuoted reply and signature"))
	lines, err := commandMessageLines(msg, 1024)
	if err != nil || len(lines) != 2 || lines[0] != "WHITELIST ADD news@example.net" {
		t.Fatalf("decoded commands = %q, %v", lines, err)
	}
	msg = message.New(1024)
	msg.AddHeader("Content-Type", "multipart/mixed; boundary=x")
	msg.AddBody([]byte("--x"))
	if _, err := commandMessageLines(msg, 1024); err == nil {
		t.Fatal("multipart command message was accepted")
	}
	msg = message.New(4096)
	msg.AddHeader("Content-Type", "text/html; charset=UTF-8")
	msg.AddBody([]byte("<html><body><p>WHITELIST DELETE news@example.net</p><blockquote>Old reply text</blockquote></body></html>"))
	lines, err = commandMessageLines(msg, 4096)
	if err != nil || len(lines) == 0 || lines[0] != "WHITELIST DELETE news@example.net" {
		t.Fatalf("HTML commands = %q, %v", lines, err)
	}
	msg = message.New(4096)
	msg.AddHeader("Content-Type", "multipart/alternative; boundary=x")
	msg.AddBody([]byte("--x\r\nContent-Type: text/plain\r\n\r\nWHITELIST ADD old@example.net\r\n--x\r\nContent-Type: text/html\r\n\r\n<div>WHITELIST ADD news@example.net</div><div>Previous message</div>\r\n--x--\r\n"))
	lines, err = commandMessageLines(msg, 4096)
	if err != nil || len(lines) == 0 || lines[0] != "WHITELIST ADD news@example.net" {
		t.Fatalf("multipart HTML commands = %q, %v", lines, err)
	}
}

func TestCommandMessageTrimsOversizedReplyInsteadOfRejecting(t *testing.T) {
	msg := message.New(96)
	msg.AddHeader("Content-Type", "text/plain; charset=UTF-8")
	msg.AddBody([]byte("WHITELIST ADD news@example.net\n\nOn an earlier date someone wrote:\n" + strings.Repeat("quoted history ", 20)))
	if !msg.BodyTruncated {
		t.Fatal("test message was not truncated by the Milter retention limit")
	}
	lines, err := commandMessageLines(msg, 64)
	if err != nil {
		t.Fatalf("oversized command reply rejected: %v", err)
	}
	if len(lines) == 0 || lines[0] != "WHITELIST ADD news@example.net" {
		t.Fatalf("decoded lines = %q", lines)
	}
}

func TestSenderOwnershipViaAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases")
	if err := os.WriteFile(path, []byte("phil.anderson: philip\nphilip: pamail\nshared: pamail, other\nprogram: |/bin/false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sender := range []string{"pamail@invades.net", "phil.anderson@invades.net"} {
		if err := senderOwnedViaAliases(path, sender, "pamail", "milterguard@invades.net"); err != nil {
			t.Errorf("%s should be owned: %v", sender, err)
		}
	}
	for _, sender := range []string{"shared@invades.net", "program@invades.net", "phil.anderson@example.net", "unknown@invades.net"} {
		if err := senderOwnedViaAliases(path, sender, "pamail", "milterguard@invades.net"); err == nil {
			t.Errorf("%s unexpectedly accepted", sender)
		}
	}
	for _, sender := range []string{"broken <>", "not an address"} {
		if err := senderOwnedViaAliases(path, sender, "pamail", "milterguard@invades.net"); err == nil {
			t.Errorf("malformed sender %q unexpectedly accepted", sender)
		}
	}
	if err := senderOwnedViaAliases(path, "pamail@invades.net", "pamail", "broken <>"); err == nil {
		t.Error("malformed command recipient unexpectedly accepted")
	}
}
