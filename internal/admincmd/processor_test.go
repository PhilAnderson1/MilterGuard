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

type activityRepositoryStub struct {
	query   stores.ActivityQuery
	summary stores.ActivitySummary
	status  stores.ServiceStatus
	found   bool
}

func (*activityRepositoryStub) AddActivity(context.Context, stores.ActivityEvent) error { return nil }
func (r *activityRepositoryStub) ActivitySummary(_ context.Context, query stores.ActivityQuery) (stores.ActivitySummary, error) {
	r.query = query
	return r.summary, nil
}
func (*activityRepositoryStub) CleanupActivity(context.Context) (int64, error) { return 0, nil }
func (*activityRepositoryStub) CountActivity(context.Context) (int, error)     { return 0, nil }
func (r *activityRepositoryStub) ServiceStatus(context.Context) (stores.ServiceStatus, bool, error) {
	return r.status, r.found, nil
}
func (*activityRepositoryStub) SetServiceStatus(context.Context, stores.ServiceStatus) error {
	return nil
}
func (*activityRepositoryStub) ClearServiceStatus(context.Context) error { return nil }

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

func TestActivityCommandUsesDefaultPeriodAndFormatsReport(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	repository := &activityRepositoryStub{
		summary: stores.ActivitySummary{
			ScanTotal: 30, ScanRejections: 20, ScanAccepted: 10, AIEvaluationsFailed: 1,
			IPRejections: 2, CorrespondentAccepts: 1, TokenCost: .0197,
		},
		status: stores.ServiceStatus{StartedAt: now.Add(-time.Hour), Mode: stores.ServiceModeAccept}, found: true,
	}
	p := New(Dependencies{Activity: repository, ActivityExpiry: 365 * 24 * time.Hour, Now: func() time.Time { return now }})
	response, err := p.ExecuteLine(context.Background(), "ACTIVITY", Actor{Administrator: true})
	if err != nil {
		t.Fatal(err)
	}
	if !repository.query.Since.Equal(now.Add(-7*24*time.Hour)) || !repository.query.Before.Equal(now) {
		t.Fatalf("activity query = %+v", repository.query)
	}
	for _, want := range []string{
		"MilterGuard is running in accept mode", "This period also contains rejections recorded in enforce mode",
		"Activity: past week", "Retention: 365 days",
		"Service uptime: 1 hour", "Total rejected: 22", "  AI classification: 20", "  IP reputation: 2",
		"  Attachment policy: 0", "  Protected sender-domain policy: 0",
		"Total accepted: 11", "  AI classification: 10", "  Correspondent whitelist: 1", "  Trusted sender domain: 0",
		"Total AI scans: 30", "AI evaluations failed: 1",
		"Token costs are estimates based on endpoint-reported usage and configured prices.",
		"Total token cost: USD 0.0197", "Average cost per message scanned: USD 0.000657",
	} {
		if !strings.Contains(response.Text, want) {
			t.Errorf("activity response missing %q:\n%s", want, response.Text)
		}
	}
	if strings.Contains(response.Text, "Period:") {
		t.Errorf("activity response contains redundant exact period:\n%s", response.Text)
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
