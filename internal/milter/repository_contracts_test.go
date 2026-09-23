package milter

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func TestServerOpensSQLiteForRejectionHistoryAlone(t *testing.T) {
	cfg := config.Config{
		AI:          config.AIConfig{MaxConcurrent: 1},
		Milter:      config.MilterConfig{MaxConnections: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(time.Hour), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, nil)
	if server.StartupError() != nil || server.database == nil {
		t.Fatalf("rejection-only SQLite startup: database=%v, error=%v", server.database, server.StartupError())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

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
	processor := admincmd.New(admincmd.Dependencies{Rejections: repository})
	actor := admincmd.Actor{DefaultRecipient: "user@example.com"}

	if _, err := processor.ExecuteLine(context.Background(), "REJECTIONS", actor); err != nil {
		t.Fatal(err)
	}
	if repository.listQuery.Recipients.All || repository.listQuery.Recipients.Address != "user@example.com" {
		t.Fatalf("list scope = %+v", repository.listQuery.Recipients)
	}
	if repository.listQuery.Limit != admincmd.MaxListRows {
		t.Fatalf("list limit = %d, want %d", repository.listQuery.Limit, admincmd.MaxListRows)
	}

	if _, err := processor.ExecuteLine(context.Background(), "REJECTION 42", actor); err != nil {
		t.Fatal(err)
	}
	if repository.getScope.All || repository.getScope.Address != "user@example.com" {
		t.Fatalf("detail scope = %+v", repository.getScope)
	}
}

func TestCommandProcessorUsesUnrestrictedRejectionScopeOnlyForAdministrator(t *testing.T) {
	repository := &recordingRejectionRepository{}
	processor := admincmd.New(admincmd.Dependencies{Rejections: repository})
	if _, err := processor.ExecuteLine(context.Background(), "REJECTION 42",
		admincmd.Actor{Administrator: true, DefaultRecipient: "admin@example.com"}); err != nil {
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
	found  bool
	reads  int
	writes int
}

func (r *cachedDomainRegistrationRepository) DomainRegistration(context.Context, string) (stores.DomainRegistration, bool, error) {
	r.reads++
	return r.record, r.found, nil
}

func (r *cachedDomainRegistrationRepository) PutDomainRegistration(_ context.Context, record stores.DomainRegistration) error {
	r.record, r.found = record, true
	r.writes++
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
	repository := &cachedDomainRegistrationRepository{found: true, record: stores.DomainRegistration{
		Domain: "example.com", RegisteredAt: now.AddDate(-10, 0, 0), ExpiresAt: now.AddDate(1, 0, 0),
	}}
	lookup := &fakeDomainRegistrationLookup{}
	service := &domainRegistrationStore{
		repository: repository, lookup: lookup, now: func() time.Time { return now },
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
	if lookup.calls.Load() != 0 || repository.writes != 0 {
		t.Fatalf("cache hit performed lookup or write: lookups=%d writes=%d", lookup.calls.Load(), repository.writes)
	}
}

func TestDomainRegistrationEvidenceRefreshesRepositoryCacheMiss(t *testing.T) {
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	repository := &cachedDomainRegistrationRepository{}
	lookup := &fakeDomainRegistrationLookup{
		registered: now.AddDate(-10, 0, 0), expires: now.AddDate(1, 0, 0),
	}
	service := &domainRegistrationStore{
		repository: repository, lookup: lookup, timeout: time.Second,
		slots: make(chan struct{}, 1), now: func() time.Time { return now },
		failures: make(map[string]time.Time), inflight: make(map[string]chan struct{}),
	}

	evidence, err := service.evidence(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Available || evidence.Domain != "example.com" {
		t.Fatalf("refreshed evidence = %+v", evidence)
	}
	if lookup.calls.Load() != 1 || repository.writes != 1 || !repository.found || repository.record.Domain != "example.com" {
		t.Fatalf("cache miss handling: lookups=%d writes=%d found=%t record=%+v",
			lookup.calls.Load(), repository.writes, repository.found, repository.record)
	}

	if _, err := service.evidence(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if lookup.calls.Load() != 1 || repository.writes != 1 {
		t.Fatalf("refreshed cache was not reused: lookups=%d writes=%d", lookup.calls.Load(), repository.writes)
	}
}
