package milter

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type recordingRejectionRepository struct {
	listQuery stores.RejectionListQuery
	getScope  stores.RecipientScope
}

func (r *recordingRejectionRepository) AddRejection(context.Context, stores.NewRejection) (uint64, error) {
	return 0, nil
}

func (r *recordingRejectionRepository) ListRejections(_ context.Context, query stores.RejectionListQuery) (stores.RejectionPage, error) {
	r.listQuery = query
	return stores.RejectionPage{}, nil
}

func (r *recordingRejectionRepository) RejectionByID(_ context.Context, _ uint64, scope stores.RecipientScope) (stores.Rejection, bool, error) {
	r.getScope = scope
	return stores.Rejection{}, false, nil
}

func TestCommandProcessorBuildsRecipientScopedRepositoryQueries(t *testing.T) {
	repository := &recordingRejectionRepository{}
	processor := &CommandProcessor{server: &Server{}, rejections: repository}
	actor := CommandActor{DefaultRecipient: "user@example.com"}

	if _, err := processor.executeCommand(context.Background(), emailCommand{
		kind: "rejections", recipient: "user@example.com", period: periodWeek,
	}, actor); err != nil {
		t.Fatal(err)
	}
	if repository.listQuery.Recipients.All || repository.listQuery.Recipients.Address != "user@example.com" {
		t.Fatalf("list scope = %+v", repository.listQuery.Recipients)
	}
	if repository.listQuery.Limit != maxEmailCommandListRows {
		t.Fatalf("list limit = %d, want %d", repository.listQuery.Limit, maxEmailCommandListRows)
	}

	if _, err := processor.executeCommand(context.Background(), emailCommand{
		kind: "rejection", rejectionID: 42,
	}, actor); err != nil {
		t.Fatal(err)
	}
	if repository.getScope.All || repository.getScope.Address != "user@example.com" {
		t.Fatalf("detail scope = %+v", repository.getScope)
	}
}

func TestCommandProcessorUsesUnrestrictedRejectionScopeOnlyForAdministrator(t *testing.T) {
	repository := &recordingRejectionRepository{}
	processor := &CommandProcessor{server: &Server{}, rejections: repository}
	if _, err := processor.executeCommand(context.Background(), emailCommand{kind: "rejection", rejectionID: 42},
		CommandActor{Administrator: true, DefaultRecipient: "admin@example.com"}); err != nil {
		t.Fatal(err)
	}
	if !repository.getScope.All || repository.getScope.Address != "" {
		t.Fatalf("administrator scope = %+v", repository.getScope)
	}
}

type recordingIPReputationRepository struct {
	stores.IPReputationRepository
	rejections int
}

type cachedDomainRegistrationRepository struct {
	record stores.DomainRegistration
	reads  int
}

func (r *cachedDomainRegistrationRepository) DomainRegistration(context.Context, string) (stores.DomainRegistration, bool, error) {
	r.reads++
	return r.record, true, nil
}

func (r *cachedDomainRegistrationRepository) PutDomainRegistration(context.Context, stores.DomainRegistration) error {
	return nil
}

func (r *recordingIPReputationRepository) RecordRejection(_ context.Context, address netip.Addr) (stores.IPBlock, error) {
	r.rejections++
	return stores.IPBlock{Address: address, Level: stores.IPBlockLevelShort, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestIPAllowlistPreventsRepositoryMutation(t *testing.T) {
	policy := newIPReputationStore(config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), MaxEntries: 10, IPAllowlist: []string{"192.0.2.0/24"},
	}, nil, nil)
	repository := &recordingIPReputationRepository{}
	policy.repository = repository

	if policy.add(context.Background(), netip.MustParseAddr("192.0.2.10"), connectionDNSResult{}) {
		t.Fatal("allowlisted address was blocked")
	}
	if repository.rejections != 0 {
		t.Fatalf("RecordRejection calls = %d, want 0", repository.rejections)
	}
}

func TestDomainRegistrationEvidenceUsesRepositoryCache(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	repository := &cachedDomainRegistrationRepository{record: stores.DomainRegistration{
		Domain: "example.com", RegisteredAt: now.AddDate(-10, 0, 0), ExpiresAt: now.AddDate(1, 0, 0),
	}}
	service := &domainRegistrationStore{
		repository: repository, lookup: &fakeDomainRegistrationLookup{}, now: func() time.Time { return now },
	}

	evidence, err := service.evidence(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Available || evidence.Domain != "example.com" {
		t.Fatalf("evidence = %+v", evidence)
	}
	if repository.reads != 1 {
		t.Fatalf("repository reads = %d, want 1", repository.reads)
	}
}
