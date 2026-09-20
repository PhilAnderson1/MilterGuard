package admincmd

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type rejectionRepositoryStub struct {
	entry     stores.Rejection
	listQuery stores.RejectionListQuery
	getScope  stores.RecipientScope
}

func (*rejectionRepositoryStub) AddRejection(context.Context, stores.NewRejection) (uint64, error) {
	return 0, nil
}
func (r *rejectionRepositoryStub) ListRejections(_ context.Context, q stores.RejectionListQuery) (stores.RejectionPage, error) {
	r.listQuery = q
	return stores.RejectionPage{Entries: []stores.Rejection{r.entry}}, nil
}
func (r *rejectionRepositoryStub) RejectionByID(_ context.Context, _ uint64, s stores.RecipientScope) (stores.Rejection, bool, error) {
	r.getScope = s
	return r.entry, true, nil
}

type messageSourceStub struct {
	reads    int
	contents []byte
	err      error
}

func (s *messageSourceStub) ReadWithRecordID(uint64, time.Time, int64) (ArchivedMessage, error) {
	s.reads++
	return ArchivedMessage{Contents: s.contents, Path: "/archive/2026/09/20/7.eml"}, s.err
}

func TestExecuteBuildsScopedQueries(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	repository := &rejectionRepositoryStub{}
	p := New(Dependencies{Rejections: repository, Now: func() time.Time { return now }})
	if _, err := p.ExecuteLine(context.Background(), "REJECTIONS", Actor{DefaultRecipient: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	if repository.listQuery.Recipients.Address != "user@example.com" || repository.listQuery.Recipients.All || repository.listQuery.Limit != MaxListRows || !repository.listQuery.RejectedSince.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("query=%+v", repository.listQuery)
	}
	if _, err := p.ExecuteLine(context.Background(), "REJECTION 7", Actor{Administrator: true, DefaultRecipient: "admin@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !repository.getScope.All || repository.getScope.Address != "" {
		t.Fatalf("admin scope=%+v", repository.getScope)
	}
}

func TestRejectionArchiveReadIsDeferred(t *testing.T) {
	entry := stores.Rejection{ID: 7, Sender: "sender@example.net", Recipients: []string{"user@example.com"}, RejectedAt: time.Now()}
	repository := &rejectionRepositoryStub{entry: entry}
	source := &messageSourceStub{contents: []byte("From: sender@example.net\r\nContent-Type: text/plain\r\n\r\nBody text\r\n")}
	p := New(Dependencies{Rejections: repository, MessageSource: source, MaxMessageSize: 1 << 20})
	command, err := p.Parse("REJECTION 7", Actor{DefaultRecipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := p.Execute(context.Background(), command, Actor{DefaultRecipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if source.reads != 0 {
		t.Fatal("archive was read on command execution hot path")
	}
	response := deferred()
	if source.reads != 1 || !strings.Contains(response.Text, "Body text") || len(response.Attachments) != 1 || response.Attachments[0].SourcePath != "/archive/2026/09/20/7.eml" {
		t.Fatalf("response=%#v reads=%d", response, source.reads)
	}
}

func TestMissingArchiveIsNotAnError(t *testing.T) {
	repository := &rejectionRepositoryStub{entry: stores.Rejection{ID: 8, Recipients: []string{"user@example.com"}}}
	source := &messageSourceStub{err: fs.ErrNotExist}
	p := New(Dependencies{Rejections: repository, MessageSource: source})
	response, err := p.ExecuteLine(context.Background(), "REJECTION 8", Actor{DefaultRecipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Text, "Saved message is not available") || len(response.Attachments) != 0 {
		t.Fatalf("response=%#v", response)
	}
}
