package milter

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerUsesUnifiedRejectionHistoryArchiveSettings(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rejected-mail")
	cfg := config.Config{
		Milter:      config.MilterConfig{MaxConnections: 1},
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10, SaveMessages: true,
			MessageDirectory: root, MessageMaxTotalBytes: 1 << 20,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = server.Close() })
	if server.sessions.policy.archive == nil {
		t.Fatal("unified rejection-history settings did not enable the message archive")
	}
	now := time.Now().UTC()
	if _, err := server.sessions.policy.archive.SaveWithRecordIDAt([]byte("test"), 7, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, now.Format("2006"), now.Format("01"), now.Format("02"), "7.eml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive does not use configured message directory: %v", err)
	}
}

func TestRejectionCommandRetrievesProcessedArchivedMessage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rejected-mail")
	cfg := config.Config{
		Milter:      config.MilterConfig{MaxConnections: 1, MaxMessageSize: 1 << 20},
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10, SaveMessages: true,
			MessageDirectory: root, MessageMaxTotalBytes: 1 << 20,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = server.Close() })
	msg := message.New(cfg.Milter.MaxMessageSize)
	msg.AddHeader("From", "Sender <sender@example.net>")
	msg.AddHeader("Subject", "Archived subject")
	msg.AddHeader("Content-Type", "text/html; charset=UTF-8")
	msg.AddBody([]byte(`<p>Review <a href="https://example.net/account">account</a></p>`))
	server.sessions.policy.recordRejection(context.Background(), msg, "sender@example.net", "", []string{"owner@example.com"}, []string{"test reason"}, "ai")
	entries := rejectionEntries(t, server.sessions.policy.rejectionHistory, "owner@example.com")
	if len(entries) != 1 {
		t.Fatalf("rejection history = %#v", entries)
	}
	command := fmt.Sprintf("REJECTION %d", entries[0].ID)
	body, err := server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	result := body
	for _, want := range []string{"Archived subject", "test reason", "Visible email body text:\nReview account"} {
		if !strings.Contains(result.Text, want) {
			t.Errorf("retrieved message missing %q: %s", want, result.Text)
		}
	}
	if strings.Contains(result.Text, "https://example.net/account") {
		t.Fatalf("recipient-visible body included link metadata: %s", result.Text)
	}
	if len(result.Attachments) != 1 || result.Attachments[0].Filename != fmt.Sprintf("rejection-%d.eml", entries[0].ID) ||
		result.Attachments[0].MediaType != "application/octet-stream" || !bytes.Contains(result.Attachments[0].Contents, []byte("Review")) ||
		!bytes.Contains(result.Attachments[0].Contents, []byte("https://example.net/account")) {
		t.Fatalf("retrieved attachment = %#v", result.Attachments)
	}
	archivePath := filepath.Join(root, entries[0].RejectedAt.UTC().Format("2006"), entries[0].RejectedAt.UTC().Format("01"), entries[0].RejectedAt.UTC().Format("02"), fmt.Sprintf("%d.eml", entries[0].ID))
	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	body, err = server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "owner@example.com"})
	missing := body
	if err != nil || !strings.Contains(missing.Text, "Saved message is not available") || len(missing.Attachments) != 0 {
		t.Fatalf("missing archive result = %#v, %v", missing, err)
	}
	body, err = server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "other@example.com"})
	unauthorized := body
	if err != nil || unauthorized.Text != "Rejection record not found.\n" || len(unauthorized.Attachments) != 0 {
		t.Fatalf("unauthorized result = %#v, %v", unauthorized, err)
	}
}

func TestAIRejectedMessageIsArchived(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test rejection"}}}
	server, conn, done := testServer(t, analyzer)
	root := enableTestRejectedMail(t, server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
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
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(root, "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	archiveRoot := enableTestRejectedMail(t, server)
	msg := message.New(1024)
	msg.AddHeader("From", "Sender <sender@example.net>")
	msg.AddHeader("Subject", "=?UTF-8?B?44Oc44O844OK44K544KS4oCN5Y+X44GR5Y+W44Gj44Gm44GP4oCN44Gg44GV44GE?=")
	msg.AddHeader("Message-ID", "<archive-id-test@example.net>")
	msg.AddBody([]byte("rejected body"))

	server.sessions.policy.recordRejection(context.Background(), msg, "sender@example.net", "bounce@example.net", []string{"one@example.com", "two@example.com"}, []string{"unwanted"}, "ai")

	entries := rejectionEntries(t, server.sessions.policy.rejectionHistory, "*")
	if len(entries) != 1 {
		t.Fatalf("rejection entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if len(entry.Recipients) != 2 {
		t.Fatalf("stored recipients = %#v", entry.Recipients)
	}
	if entry.Subject != "ボーナスを‍受け取ってく‍ださい" {
		t.Fatalf("stored subject = %q", entry.Subject)
	}
	path := filepath.Join(archiveRoot, time.Now().UTC().Format("2006"), time.Now().UTC().Format("01"), time.Now().UTC().Format("02"), fmt.Sprintf("%d.eml", entry.ID))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive for rejection ID %d: %v", entry.ID, err)
	}
}
