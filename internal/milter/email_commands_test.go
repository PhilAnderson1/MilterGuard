package milter

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	match := server.correspondents.match("news@example.net", []string{"phil@example.com"})
	if !match.Known {
		t.Fatal("command did not add live correspondent relationship")
	}
}

func TestUnauthenticatedCommandRecipientIsRejectedAtRCPT(t *testing.T) {
	_, analyzer, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done }()
	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.10"), envelopeFrame(commandMail, "outsider@example.net"))
	if err := writeFrame(conn, envelopeFrame(commandRecipient, "milterguard@example.com")); err != nil {
		t.Fatal(err)
	}
	response, err := readFrame(conn)
	if err != nil || len(response) == 0 || response[0] != responseReply {
		t.Fatalf("response = %q, err = %v; want SMTP rejection", response, err)
	}
	if !strings.Contains(string(response), "SMTP authentication is required") {
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
	if got := formatAllowlist(entries, false); got != "Sender: news@example.net\nAdded: learned from repeated legitimate inbound emails\n\n" {
		t.Fatalf("ordinary-user output = %q", got)
	}
	if got := formatAllowlist(entries, true); got != "Sender: news@example.net\nRecipient: phil@example.com\nAdded: learned from repeated legitimate inbound emails\n\n" {
		t.Fatalf("administrator output = %q", got)
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
	tests := map[string]string{
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

func TestCommandMessageRequiresSmallPlainTextBody(t *testing.T) {
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/plain; charset=UTF-8")
	msg.AddHeader("Content-Transfer-Encoding", "quoted-printable")
	msg.AddBody([]byte("WHITELIST ADD news=40example.net\n\nQuoted reply and signature"))
	text, err := commandMessageText(msg, 1024)
	if err != nil || text != "WHITELIST ADD news@example.net" {
		t.Fatalf("decoded command = %q, %v", text, err)
	}
	msg = message.New(1024)
	msg.AddHeader("Content-Type", "multipart/mixed; boundary=x")
	msg.AddBody([]byte("--x"))
	if _, err := commandMessageText(msg, 1024); err == nil {
		t.Fatal("multipart command message was accepted")
	}
	msg = message.New(4096)
	msg.AddHeader("Content-Type", "text/html; charset=UTF-8")
	msg.AddBody([]byte("<html><body><p>WHITELIST DELETE news@example.net</p><blockquote>Old reply text</blockquote></body></html>"))
	text, err = commandMessageText(msg, 4096)
	if err != nil || text != "WHITELIST DELETE news@example.net" {
		t.Fatalf("HTML command = %q, %v", text, err)
	}
	msg = message.New(4096)
	msg.AddHeader("Content-Type", "multipart/alternative; boundary=x")
	msg.AddBody([]byte("--x\r\nContent-Type: text/plain\r\n\r\nWHITELIST ADD old@example.net\r\n--x\r\nContent-Type: text/html\r\n\r\n<div>WHITELIST ADD news@example.net</div><div>Previous message</div>\r\n--x--\r\n"))
	text, err = commandMessageText(msg, 4096)
	if err != nil || text != "WHITELIST ADD news@example.net" {
		t.Fatalf("multipart HTML command = %q, %v", text, err)
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
