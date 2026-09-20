package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func testDomainRepository(t *testing.T, options DomainOptions) (*domainRepository, *sqlitedb.Store) {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewDomains(db, options).(*domainRepository), db
}

func TestDomainRepositoryUpsertsWithoutChangingIdentity(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository, _ := testDomainRepository(t, DomainOptions{MaxEntries: 10, Now: func() time.Time { return now }})
	first := stores.DomainRegistration{Domain: "example.com", RegisteredAt: now.AddDate(-1, 0, 0), ExpiresAt: now.AddDate(0, 0, 1)}
	if err := repository.PutDomainRegistration(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	stored, found, err := repository.DomainRegistration(context.Background(), first.Domain)
	if err != nil || !found || stored.ID == 0 {
		t.Fatalf("initial record = %+v, found=%v, err=%v", stored, found, err)
	}
	id := stored.ID
	updated := stores.DomainRegistration{Domain: first.Domain, RegisteredAt: now.AddDate(-2, 0, 0), ExpiresAt: now.AddDate(1, 0, 0)}
	if err := repository.PutDomainRegistration(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	stored, found, err = repository.DomainRegistration(context.Background(), first.Domain)
	if err != nil || !found || stored.ID != id || !stored.RegisteredAt.Equal(updated.RegisteredAt) || !stored.ExpiresAt.Equal(updated.ExpiresAt) {
		t.Fatalf("updated record = %+v, found=%v, err=%v", stored, found, err)
	}
}

func TestDomainRepositoryCleanupAppliesGraceAndCapacity(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository, _ := testDomainRepository(t, DomainOptions{MaxEntries: 2, ExpiryGrace: 14 * 24 * time.Hour, Now: func() time.Time { return now }})
	for _, record := range []stores.DomainRegistration{
		{Domain: "expired.example", RegisteredAt: now.AddDate(-1, 0, 0), ExpiresAt: now.Add(-15 * 24 * time.Hour)},
		{Domain: "soon.example", RegisteredAt: now.AddDate(-1, 0, 0), ExpiresAt: now.Add(24 * time.Hour)},
		{Domain: "middle.example", RegisteredAt: now.AddDate(-1, 0, 0), ExpiresAt: now.Add(48 * time.Hour)},
		{Domain: "late.example", RegisteredAt: now.AddDate(-1, 0, 0), ExpiresAt: now.Add(72 * time.Hour)},
	} {
		if err := repository.PutDomainRegistration(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := repository.Cleanup(context.Background())
	if err != nil || deleted != 2 {
		t.Fatalf("cleanup deleted %d records, err=%v", deleted, err)
	}
	for domain, want := range map[string]bool{"expired.example": false, "soon.example": false, "middle.example": true, "late.example": true} {
		_, found, err := repository.DomainRegistration(context.Background(), domain)
		if err != nil || found != want {
			t.Fatalf("%s found=%v, want=%v, err=%v", domain, found, want, err)
		}
	}
}
