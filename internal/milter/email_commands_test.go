package milter

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
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
	match := testCorrespondentMatch(server.correspondents, context.Background(), "news@example.net", []string{"phil@example.com"})
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
	if testCorrespondentMatch(server.correspondents, context.Background(), "old@example.net", []string{"phil@example.com"}).Known {
		t.Fatal("deleted batch entry remains")
	}
	if !testCorrespondentMatch(server.correspondents, context.Background(), "current@example.net", []string{"phil@example.com"}).Known {
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

func TestWildcardDeletionIsAdministratorOnly(t *testing.T) {
	if _, _, err := parseEmailCommand("WHITELIST DELETE news@example.net *", "phil@example.com", false); err == nil {
		t.Fatal("ordinary user could use wildcard")
	}
	command, _, err := parseEmailCommand("WHITELIST DELETE news@example.net *", "phil@example.com", true)
	if err != nil || command.recipient != "*" {
		t.Fatalf("administrator wildcard = %#v, %v", command, err)
	}
}

func TestRejectionHistoryCommandAuthorization(t *testing.T) {
	command, _, err := parseEmailCommand("REJECTIONS", "phil@example.com", false)
	if err != nil || command.kind != "rejections" || command.recipient != "phil@example.com" {
		t.Fatalf("own history command = %#v, %v", command, err)
	}
	if _, _, err := parseEmailCommand("REJECTIONS *", "phil@example.com", false); err == nil {
		t.Fatal("ordinary user could list all rejection history")
	}
	command, _, err = parseEmailCommand("REJECTIONS *", "phil@example.com", true)
	if err != nil || command.recipient != "*" {
		t.Fatalf("administrator history command = %#v, %v", command, err)
	}
}

func TestAllowlistListCommandAuthorization(t *testing.T) {
	command, _, err := parseEmailCommand("WHITELIST LIST", "phil@example.com", false)
	if err != nil || command.kind != "whitelist_list" || command.recipient != "phil@example.com" {
		t.Fatalf("own allowlist command = %#v, %v", command, err)
	}
	if _, _, err := parseEmailCommand("WHITELIST LIST other@example.com", "phil@example.com", false); err == nil {
		t.Fatal("ordinary user could list another recipient's allowlist")
	}
	command, _, err = parseEmailCommand("WHITELIST LIST *", "phil@example.com", true)
	if err != nil || command.recipient != "*" {
		t.Fatalf("administrator allowlist command = %#v, %v", command, err)
	}
}

func TestAllowlistFormattingIncludesRecipientsOnlyForAdministrators(t *testing.T) {
	entries := []correspondentEntry{{Correspondent: "news@example.net", LocalAddress: "phil@example.com", WhitelistType: whitelistRepeatedLegitimate}}
	if got := formatAllowlist(entries, false, false); got != "Sender: news@example.net\nAdded: learned from repeated legitimate inbound emails\n\n" {
		t.Fatalf("ordinary-user output = %q", got)
	}
	if got := formatAllowlist(entries, true, false); got != "Sender: news@example.net\nRecipient: phil@example.com\nAdded: learned from repeated legitimate inbound emails\n\n" {
		t.Fatalf("administrator output = %q", got)
	}
}

func TestEmailCommandListFormattingLimitsRows(t *testing.T) {
	entries := make([]correspondentEntry, maxEmailCommandListRows+1)
	for i := range entries {
		entries[i] = correspondentEntry{
			Correspondent: fmt.Sprintf("sender-%04d@example.net", i),
			WhitelistType: whitelistManual,
		}
	}
	formatted := formatAllowlist(entries, false, false)
	if strings.Contains(formatted, "sender-1000@example.net") {
		t.Fatal("allowlist output contains a record beyond the hard limit")
	}
	if !strings.Contains(formatted, commandListTruncatedNotice) {
		t.Fatal("allowlist output does not report row truncation")
	}
}

func TestAllowlistListIncludesRecipientOnlyForAdministratorWildcard(t *testing.T) {
	tests := []struct {
		name      string
		admin     bool
		recipient string
		want      bool
	}{
		{name: "ordinary user", admin: false, recipient: "phil@example.com", want: false},
		{name: "administrator specific recipient", admin: true, recipient: "phil@example.com", want: false},
		{name: "administrator wildcard", admin: true, recipient: "*", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := includeAllowlistRecipient(test.admin, test.recipient)
			if got != test.want {
				t.Fatalf("include recipient = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAllowlistAddedDescriptions(t *testing.T) {
	tests := map[stores.CorrespondentKind]string{
		whitelistManual:                "manually",
		whitelistAuthenticatedOutbound: "learned from authenticated outbound email",
		whitelistRepeatedLegitimate:    "learned from repeated legitimate inbound emails",
		"invalid":                      "unknown",
	}
	for whitelistType, want := range tests {
		if got := allowlistAddedDescription(whitelistType); got != want {
			t.Errorf("allowlistAddedDescription(%q) = %q, want %q", whitelistType, got, want)
		}
	}
}

func TestAdministratorHelpShowsWildcardPeriodOrder(t *testing.T) {
	help := commandHelp(true)
	for _, example := range []string{"WHITELIST LIST * month", "REJECTIONS * year"} {
		if !strings.Contains(help, example) {
			t.Errorf("administrator help does not contain %q", example)
		}
	}
	if strings.Contains(commandHelp(false), "WHITELIST LIST * month") {
		t.Fatal("ordinary-user help contains administrator wildcard example")
	}
}

func TestIPCommandsAreAdministratorOnly(t *testing.T) {
	for _, text := range []string{"IP LIST", "IP LIST LOOKUP", "IP ADD 192.0.2.10", "IP DELETE 2001:db8::1"} {
		if _, _, err := parseEmailCommand(text, "phil@example.com", false); err == nil {
			t.Fatalf("ordinary user could issue %q", text)
		}
	}
	command, _, err := parseEmailCommand("IP ADD ::ffff:192.0.2.10", "phil@example.com", true)
	if err != nil || command.kind != "ip_add" || command.ip.String() != "192.0.2.10" {
		t.Fatalf("administrator IP command = %#v, %v", command, err)
	}
	command, _, err = parseEmailCommand("IP LIST LOOKUP", "phil@example.com", true)
	if err != nil || command.kind != "ip_list_lookup" {
		t.Fatalf("administrator lookup command = %#v, %v", command, err)
	}
	if _, _, err := parseEmailCommand("IP ADD not-an-ip", "phil@example.com", true); err == nil {
		t.Fatal("invalid IP address accepted")
	}
}

func TestListingCommandPeriods(t *testing.T) {
	tests := []struct {
		text      string
		admin     bool
		kind      string
		period    commandPeriod
		recipient string
	}{
		{text: "WHITELIST LIST", kind: "whitelist_list", period: periodWeek, recipient: "phil@example.com"},
		{text: "WHITELIST LIST month", kind: "whitelist_list", period: periodMonth, recipient: "phil@example.com"},
		{text: "WHITELIST LIST * all", admin: true, kind: "whitelist_list", period: periodAll, recipient: "*"},
		{text: "REJECTIONS day", kind: "rejections", period: periodDay, recipient: "phil@example.com"},
		{text: "REJECTIONS other@example.com year", admin: true, kind: "rejections", period: periodYear, recipient: "other@example.com"},
		{text: "IP LIST week", admin: true, kind: "ip_list", period: periodWeek},
		{text: "IP LIST LOOKUP month", admin: true, kind: "ip_list_lookup", period: periodMonth},
	}
	for _, test := range tests {
		command, _, err := parseEmailCommand(test.text, "phil@example.com", test.admin)
		if err != nil || command.kind != test.kind || command.period != test.period || command.recipient != test.recipient {
			t.Errorf("parse %q = %#v, %v", test.text, command, err)
		}
	}
	for _, invalid := range []string{"IP LIST fortnight", "IP LIST LOOKUP day extra", "REJECTIONS * week extra", "WHITELIST LIST * month extra"} {
		if _, _, err := parseEmailCommand(invalid, "phil@example.com", true); err == nil {
			t.Errorf("invalid listing command %q was accepted", invalid)
		}
	}
}

func TestRejectionDetailCommandRequiresPositiveID(t *testing.T) {
	command, _, err := parseEmailCommand("REJECTION 123", "phil@example.com", false)
	if err != nil || command.kind != "rejection" || command.rejectionID != 123 {
		t.Fatalf("rejection detail command = %#v, %v", command, err)
	}
	for _, invalid := range []string{"REJECTION", "REJECTION 0", "REJECTION -1", "REJECTION invalid", "REJECTION 9223372036854775808", "REJECTION 1 extra"} {
		if _, _, err := parseEmailCommand(invalid, "phil@example.com", false); err == nil {
			t.Errorf("invalid command %q was accepted", invalid)
		}
	}
}

func TestRejectionDetailFormattingContainsOnlyStoredMetadataAndBody(t *testing.T) {
	entry := rejectionHistoryEntry{ID: 12, Sender: "sender@example.net", Recipients: []string{"local@example.com"},
		Subject: "Example", RejectedAt: time.Date(2026, 9, 13, 5, 30, 0, 0, time.UTC), Reason: "Unwanted"}
	formatted := formatRejectionDetail(entry, "Cleaned body")
	for _, want := range []string{"Rejection ID: 12", "From: sender@example.net", "To: local@example.com", "Subject: Example", "Date: 2026-09-13 05:30:00 UTC", "Reason for rejection: Unwanted", "Processed email body text:\nCleaned body"} {
		if !strings.Contains(formatted, want) {
			t.Errorf("detail missing %q: %s", want, formatted)
		}
	}
	for _, unwanted := range []string{"CONNECTION INFORMATION", "AUTHENTICATION INFORMATION", "CORRESPONDENT INFORMATION"} {
		if strings.Contains(formatted, unwanted) {
			t.Errorf("detail contains analysis section %q", unwanted)
		}
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

func TestCommandPeriodCutoffs(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	if got := periodDay.cutoff(now); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Fatalf("day cutoff = %v", got)
	}
	if got := periodWeek.cutoff(now); !got.Equal(now.Add(-7 * 24 * time.Hour)) {
		t.Fatalf("week cutoff = %v", got)
	}
	if got := periodMonth.cutoff(now); !got.Equal(now.AddDate(0, -1, 0)) {
		t.Fatalf("month cutoff = %v", got)
	}
	if got := periodYear.cutoff(now); !got.Equal(now.AddDate(-1, 0, 0)) {
		t.Fatalf("year cutoff = %v", got)
	}
	if got := periodAll.cutoff(now); !got.IsZero() {
		t.Fatalf("all cutoff = %v", got)
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
