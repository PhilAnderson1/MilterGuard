package milter

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type observedCommandArchive struct {
	commandArchiveSource
	loaded []uint64
	limits []int64
}

func (s *observedCommandArchive) ReadWithRecordID(id uint64, date time.Time, limit int64) (admincmd.ArchivedMessage, error) {
	s.limits = append(s.limits, limit)
	message, err := s.commandArchiveSource.ReadWithRecordID(id, date, limit)
	if err == nil {
		s.loaded = append(s.loaded, id)
	}
	return message, err
}

func TestEmailCommandBatchBudgetsArchivesBeforeReading(t *testing.T) {
	server, _, conn, done := commandTestServer(t, true, nil)
	defer func() { _ = conn.Close(); <-done; _ = server.Close() }()
	enableTestRejectedMail(t, server)
	repository := newRejectionRepository(config.RejectionHistoryConfig{Expiry: config.Duration(24 * time.Hour), MaxEntries: 100}, server.database, time.Now, server.log)
	source := &observedCommandArchive{commandArchiveSource: commandArchiveSource{server.sessions.policy.archive}}
	server.sessions.commands.processor = admincmd.New(admincmd.Dependencies{
		Rejections: repository, MessageSource: source, MaxMessageSize: 64 << 10,
	})
	sender := &fakeReplySender{messages: make(chan smtpreply.Message, 1)}
	server.sessions.commands.cfg.SendReplies = true
	server.sessions.commands.sender = sender
	now := time.Now().UTC()
	var ids []uint64
	for _, size := range []int{40000, 8000, 8000, 8000} {
		id, err := repository.AddRejection(context.Background(), stores.NewRejection{
			VisibleSender: "sender@example.net", Recipients: []string{"user@example.com"}, RejectedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		raw := append([]byte("Content-Type: application/octet-stream\r\n\r\n"), bytes.Repeat([]byte("x"), size)...)
		if _, err := server.sessions.policy.archive.SaveWithRecordIDAt(raw, id, now); err != nil {
			t.Fatal(err)
		}
	}
	commands := fmt.Sprintf("REJECTION %d\nREJECTION %d\nREJECTION %d\nREJECTION %d\nREJECTION %d", ids[0], ids[1], ids[1], ids[2], ids[3])
	response := submitCommand(t, conn, "user", "user@example.com", []string{"milterguard@example.com"}, commands)
	if len(response) != 1 || response[0] != responseDiscard {
		t.Fatalf("response=%q", response)
	}
	select {
	case reply := <-sender.messages:
		if len(source.loaded) != 2 || source.loaded[0] != ids[1] || source.loaded[1] != ids[2] || len(source.limits) != 4 {
			t.Fatalf("unexpected archive reads: loaded=%v limits=%v", source.loaded, source.limits)
		}
		if len(reply.Attachments) != 2 {
			t.Fatalf("attachments=%d", len(reply.Attachments))
		}
		for index, id := range ids[1:3] {
			if reply.Attachments[index].Filename != fmt.Sprintf("rejection-%d.eml", id) {
				t.Fatal("attachment order changed")
			}
		}
		if !strings.Contains(reply.Text, fmt.Sprintf("(rejection IDs): %d, %d.", ids[0], ids[3])) {
			t.Fatalf("omitted IDs missing from reply: %s", reply.Text)
		}
		payload, err := smtpreply.Build(reply)
		if err != nil || len(payload) > 64<<10 || reply.MaxBytes != 64<<10 {
			t.Fatalf("encoded reply bytes=%d error=%v", len(payload), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command reply not sent")
	}
}
