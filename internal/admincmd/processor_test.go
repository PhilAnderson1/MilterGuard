package admincmd

import (
	"context"
	"errors"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type rejectionRepositoryStub struct {
	entry     stores.Rejection
	listQuery stores.RejectionListQuery
	getScope  stores.RecipientScope
	listErr   error
}

type correspondentAdminRepositoryStub struct {
	addSender, addRecipient string
	deleteSender            string
	deleteScope             stores.RecipientScope
	created                 bool
	removed                 int
	err                     error
}

func (*correspondentAdminRepositoryStub) ListCorrespondents(context.Context, stores.CorrespondentListQuery) (stores.CorrespondentPage, error) {
	return stores.CorrespondentPage{}, nil
}
func (r *correspondentAdminRepositoryStub) AddManual(_ context.Context, sender, recipient string) (bool, error) {
	r.addSender, r.addRecipient = sender, recipient
	return r.created, r.err
}
func (r *correspondentAdminRepositoryStub) DeleteCorrespondent(_ context.Context, sender string, scope stores.RecipientScope) (int, error) {
	r.deleteSender, r.deleteScope = sender, scope
	return r.removed, r.err
}

type ipReputationRepositoryStub struct {
	address netip.Addr
	block   stores.IPBlock
	removed bool
	err     error
}

func (*ipReputationRepositoryStub) RecordRejection(context.Context, netip.Addr) (stores.IPBlock, error) {
	return stores.IPBlock{}, nil
}
func (*ipReputationRepositoryStub) RecordLegitimate(context.Context, netip.Addr) error { return nil }
func (*ipReputationRepositoryStub) ActiveBlock(context.Context, netip.Addr) (stores.IPBlock, bool, error) {
	return stores.IPBlock{}, false, nil
}
func (r *ipReputationRepositoryStub) AddManualBlock(_ context.Context, address netip.Addr) (stores.IPBlock, error) {
	r.address = address
	return r.block, r.err
}
func (r *ipReputationRepositoryStub) Delete(_ context.Context, address netip.Addr) (bool, error) {
	r.address = address
	return r.removed, r.err
}
func (*ipReputationRepositoryStub) ListActiveBlocks(context.Context, stores.IPBlockListQuery) (stores.IPBlockPage, error) {
	return stores.IPBlockPage{}, nil
}

func (*rejectionRepositoryStub) AddRejection(context.Context, stores.NewRejection) (uint64, error) {
	return 0, nil
}
func (r *rejectionRepositoryStub) ListRejections(_ context.Context, q stores.RejectionListQuery) (stores.RejectionPage, error) {
	r.listQuery = q
	return stores.RejectionPage{Entries: []stores.Rejection{r.entry}}, r.listErr
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

func TestRejectionDetailWarnsWhenSavedMessageWasTruncated(t *testing.T) {
	entry := stores.Rejection{ID: 7, Sender: "sender@example.net", Recipients: []string{"user@example.com"}, RejectedAt: time.Now()}
	repository := &rejectionRepositoryStub{entry: entry}
	source := &messageSourceStub{contents: []byte("X-MilterGuard-Archive-Truncated: yes\r\nContent-Type: text/plain\r\n\r\nPartial body\r\n")}
	p := New(Dependencies{Rejections: repository, MessageSource: source, MaxMessageSize: 1 << 20})

	response, err := p.ExecuteLine(context.Background(), "REJECTION 7", Actor{DefaultRecipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Saved message was truncated during archiving", "Partial body"} {
		if !strings.Contains(response.Text, want) {
			t.Fatalf("response missing %q: %s", want, response.Text)
		}
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

func TestMalformedArchiveRemainsAttached(t *testing.T) {
	repository := &rejectionRepositoryStub{entry: stores.Rejection{ID: 7, Recipients: []string{"user@example.com"}}}
	source := &messageSourceStub{contents: []byte("not a valid header\r\n\r\nbody")}
	p := New(Dependencies{Rejections: repository, MessageSource: source, MaxMessageSize: 1 << 20})
	response, err := p.ExecuteLine(context.Background(), "REJECTION 7", Actor{DefaultRecipient: "user@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(response.Text, "Saved message is attached, but its body could not be processed") ||
		strings.Contains(response.Text, "Saved message is not available") || len(response.Attachments) != 1 {
		t.Fatalf("response=%#v", response)
	}
}

func TestExecuteWhitelistMutations(t *testing.T) {
	repository := &correspondentAdminRepositoryStub{created: true, removed: 2}
	p := New(Dependencies{Correspondents: repository})
	actor := Actor{Administrator: true, DefaultRecipient: "admin@example.com"}

	response, err := p.ExecuteLine(context.Background(), "WHITELIST ADD News@Example.NET Owner@Example.COM", actor)
	if err != nil || response.Text != "allowlist entry added.\n" {
		t.Fatalf("add response=%#v err=%v", response, err)
	}
	if repository.addSender != "news@example.net" || repository.addRecipient != "owner@example.com" {
		t.Fatalf("add arguments=%q, %q", repository.addSender, repository.addRecipient)
	}

	repository.created = false
	response, err = p.ExecuteLine(context.Background(), "WHITELIST ADD news@example.net owner@example.com", actor)
	if err != nil || response.Text != "allowlist entry already existed and was refreshed.\n" {
		t.Fatalf("refresh response=%#v err=%v", response, err)
	}

	response, err = p.ExecuteLine(context.Background(), "WHITELIST DELETE News@Example.NET Owner@Example.COM", actor)
	if err != nil || response.Text != "removed 2 allowlist entries.\n" {
		t.Fatalf("recipient-scoped delete response=%#v err=%v", response, err)
	}
	if repository.deleteSender != "news@example.net" || repository.deleteScope.All || repository.deleteScope.Address != "owner@example.com" {
		t.Fatalf("recipient-scoped delete arguments=%q, %+v", repository.deleteSender, repository.deleteScope)
	}

	response, err = p.ExecuteLine(context.Background(), "WHITELIST DELETE news@example.net *", actor)
	if err != nil || response.Text != "removed 2 allowlist entries.\n" {
		t.Fatalf("wildcard delete response=%#v err=%v", response, err)
	}
	if repository.deleteSender != "news@example.net" || !repository.deleteScope.All || repository.deleteScope.Address != "" {
		t.Fatalf("wildcard delete arguments=%q, %+v", repository.deleteSender, repository.deleteScope)
	}
}

func TestExecuteIPMutations(t *testing.T) {
	expires := time.Date(2026, 10, 20, 12, 34, 56, 0, time.UTC)
	address := netip.MustParseAddr("192.0.2.10")
	repository := &ipReputationRepositoryStub{
		block: stores.IPBlock{Address: address, ExpiresAt: expires}, removed: true,
	}
	p := New(Dependencies{IPReputation: repository})
	actor := Actor{Administrator: true, DefaultRecipient: "admin@example.com"}

	response, err := p.ExecuteLine(context.Background(), "IP ADD ::ffff:192.0.2.10", actor)
	if err != nil || response.Text != "blocked 192.0.2.10 until 2026-10-20 12:34:56 UTC.\n" {
		t.Fatalf("add response=%#v err=%v", response, err)
	}
	if repository.address != address {
		t.Fatalf("add address=%v, want %v", repository.address, address)
	}

	response, err = p.ExecuteLine(context.Background(), "IP DELETE 192.0.2.10", actor)
	if err != nil || response.Text != "IP reputation record deleted.\n" {
		t.Fatalf("delete response=%#v err=%v", response, err)
	}
	repository.removed = false
	response, err = p.ExecuteLine(context.Background(), "IP DELETE 192.0.2.10", actor)
	if err != nil || response.Text != "IP address was not present.\n" {
		t.Fatalf("missing delete response=%#v err=%v", response, err)
	}
}

func TestExecuteReturnsNoResponseWhenRepositoryOperationFails(t *testing.T) {
	failure := errors.New("database unavailable")
	actor := Actor{Administrator: true, DefaultRecipient: "admin@example.com"}
	tests := []struct {
		name      string
		line      string
		processor *Processor
	}{
		{
			name: "rejection list", line: "REJECTIONS *",
			processor: New(Dependencies{Rejections: &rejectionRepositoryStub{listErr: failure}}),
		},
		{
			name: "IP add", line: "IP ADD 192.0.2.10",
			processor: New(Dependencies{IPReputation: &ipReputationRepositoryStub{err: failure}}),
		},
		{
			name: "IP delete", line: "IP DELETE 192.0.2.10",
			processor: New(Dependencies{IPReputation: &ipReputationRepositoryStub{err: failure}}),
		},
		{
			name: "allowlist add", line: "WHITELIST ADD sender@example.net recipient@example.com",
			processor: New(Dependencies{Correspondents: &correspondentAdminRepositoryStub{err: failure}}),
		},
		{
			name: "allowlist delete", line: "WHITELIST DELETE sender@example.net *",
			processor: New(Dependencies{Correspondents: &correspondentAdminRepositoryStub{err: failure}}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command, err := test.processor.Parse(test.line, actor)
			if err != nil {
				t.Fatal(err)
			}
			response, err := test.processor.Execute(context.Background(), command, actor)
			if !errors.Is(err, failure) {
				t.Fatalf("operation error = %v, want %v", err, failure)
			}
			if response != nil {
				t.Fatal("repository failure returned a success response renderer")
			}
		})
	}
}

func TestExecuteMutationErrorsAreReturned(t *testing.T) {
	wantErr := errors.New("database unavailable")
	actor := Actor{Administrator: true, DefaultRecipient: "admin@example.com"}
	tests := []struct {
		name string
		line string
		deps Dependencies
	}{
		{"whitelist add", "WHITELIST ADD news@example.net owner@example.com", Dependencies{Correspondents: &correspondentAdminRepositoryStub{err: wantErr}}},
		{"whitelist delete", "WHITELIST DELETE news@example.net owner@example.com", Dependencies{Correspondents: &correspondentAdminRepositoryStub{err: wantErr}}},
		{"IP add", "IP ADD 192.0.2.10", Dependencies{IPReputation: &ipReputationRepositoryStub{err: wantErr}}},
		{"IP delete", "IP DELETE 192.0.2.10", Dependencies{IPReputation: &ipReputationRepositoryStub{err: wantErr}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.deps).ExecuteLine(context.Background(), test.line, actor)
			if !errors.Is(err, wantErr) {
				t.Fatalf("error=%v, want %v", err, wantErr)
			}
		})
	}
}
