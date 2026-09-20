package milter

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

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

func TestSMTPTLSDecision(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		host       string
		advertised bool
		wantTLS    bool
		wantError  bool
	}{
		{name: "required advertised", mode: "required", host: "mail.example.com", advertised: true, wantTLS: true},
		{name: "required unavailable", mode: "required", host: "mail.example.com", wantError: true},
		{name: "opportunistic remote", mode: "opportunistic", host: "mail.example.com", advertised: true, wantTLS: true},
		{name: "opportunistic loopback", mode: "opportunistic", host: "127.0.0.1", advertised: true},
		{name: "opportunistic unavailable", mode: "opportunistic", host: "mail.example.com"},
		{name: "off", mode: "off", host: "mail.example.com", advertised: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := smtpTLSDecision(test.mode, test.host, test.advertised)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %v", err, test.wantError)
			}
			if got != test.wantTLS {
				t.Fatalf("use TLS = %v, want %v", got, test.wantTLS)
			}
		})
	}
}

func TestSMTPHostIsLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LOCALHOST."} {
		if !smtpHostIsLoopback(host) {
			t.Errorf("%q was not recognized as loopback", host)
		}
	}
	for _, host := range []string{"192.0.2.1", "mail.example.com"} {
		if smtpHostIsLoopback(host) {
			t.Errorf("%q was incorrectly recognized as loopback", host)
		}
	}
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

func TestCommandReplyPayloadAttachesOriginalMessage(t *testing.T) {
	original := []byte("From: sender@example.net\r\nTo: local@example.com\r\nSubject: Original\r\n\r\nOriginal body\r\n")
	payload, err := buildCommandReplyPayload(
		"milterguard@example.com", "local@example.com", "MilterGuard command results",
		"Sun, 13 Sep 2026 07:00:00 +0000", "token",
		commandReplyContent{
			Text: "Rejection details\n",
			Attachments: []commandReplyAttachment{{
				Filename: "rejection-12.eml", MediaType: "application/octet-stream", Contents: original,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, params=%v, err=%v", mediaType, params, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	textPart, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	textBody, err := io.ReadAll(textPart)
	if err != nil || !strings.Contains(string(textBody), "Rejection details") {
		t.Fatalf("text part = %q, err=%v", textBody, err)
	}
	attachment, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if attachment.FileName() != "rejection-12.eml" || attachment.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("attachment headers = %#v", attachment.Header)
	}
	attachmentType, _, err := mime.ParseMediaType(attachment.Header.Get("Content-Type"))
	if err != nil || attachmentType != "application/octet-stream" {
		t.Fatalf("attachment Content-Type = %q, err=%v", attachmentType, err)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, attachment))
	if err != nil || !bytes.Equal(decoded, original) {
		t.Fatalf("decoded attachment = %q, err=%v", decoded, err)
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatalf("unexpected extra MIME part: %v", err)
	}
}

func TestBoundedCommandReplyPayloadOmitsOversizedAttachment(t *testing.T) {
	payload, err := buildBoundedCommandReplyPayload(
		"milterguard@example.com", "local@example.com", "Results", "date", "token",
		commandReplyContent{
			Text: "Rejection details\n",
			Attachments: []commandReplyAttachment{{
				Filename: "rejection-12.eml", MediaType: "application/octet-stream", Contents: bytes.Repeat([]byte("x"), 1024),
			}},
		}, 512,
	)
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
	payload, err := buildBoundedCommandReplyPayload(
		"milterguard@example.com", "local@example.com", "Results", "date", "token",
		commandReplyContent{Text: strings.Repeat("x", maxEmailCommandReplyBytes+1024)}, 0,
	)
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
	if len(body) > maxEmailCommandReplyBytes {
		t.Fatalf("reply body length = %d, want at most %d", len(body), maxEmailCommandReplyBytes)
	}
	if !strings.Contains(string(body), strings.TrimSpace(commandReplyTruncatedNotice)) {
		t.Fatal("bounded reply does not report truncation")
	}
}

func TestBoundedCommandReplyTextPreservesUTF8(t *testing.T) {
	text := strings.Repeat("é", maxEmailCommandReplyBytes)
	bounded := boundedCommandReplyText(text)
	if len(bounded) > maxEmailCommandReplyBytes {
		t.Fatalf("bounded text length = %d", len(bounded))
	}
	if !utf8.ValidString(bounded) {
		t.Fatal("bounded text is not valid UTF-8")
	}
}

func TestBoundedCommandReplyAddsNoticeAfterExistingFullText(t *testing.T) {
	var body strings.Builder
	body.WriteString(strings.Repeat("x", maxEmailCommandReplyBytes))
	if appendBoundedCommandReply(&body, "more") {
		t.Fatal("append unexpectedly succeeded")
	}
	if body.Len() > maxEmailCommandReplyBytes {
		t.Fatalf("reply length = %d", body.Len())
	}
	if !strings.HasSuffix(body.String(), commandReplyTruncatedNotice) {
		t.Fatal("full reply was not shortened to include the truncation notice")
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
}
