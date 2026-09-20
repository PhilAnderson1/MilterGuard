package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type domainRepository struct {
	db      *sqlitedb.Store
	options DomainOptions
	now     func() time.Time
}

// NewDomains binds cached domain-registration reads, upserts, and maintenance
// to the shared SQLite database.
func NewDomains(db *sqlitedb.Store, options DomainOptions) stores.DomainRegistrationCache {
	return &domainRepository{db: db, options: options, now: clock(options.Now)}
}

var _ stores.DomainRegistrationCache = (*domainRepository)(nil)

func (r *domainRepository) DomainRegistration(ctx context.Context, domain string) (stores.DomainRegistration, bool, error) {
	if r == nil || r.db == nil {
		return stores.DomainRegistration{}, false, nil
	}
	var record stores.DomainRegistration
	var id, registeredAt, expiresAt int64
	err := r.db.QueryRow(ctx, `SELECT id, domain, registered_at_ms, expires_at_ms
		FROM domain_registrations WHERE domain = ?`, domain).Scan(&id, &record.Domain, &registeredAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return stores.DomainRegistration{}, false, nil
	}
	if err != nil {
		return stores.DomainRegistration{}, false, fmt.Errorf("look up domain registration: %w", err)
	}
	record.ID = uint64(id)
	record.RegisteredAt = timeFromMillis(registeredAt)
	record.ExpiresAt = timeFromMillis(expiresAt)
	return record, true, nil
}

func (r *domainRepository) PutDomainRegistration(ctx context.Context, record stores.DomainRegistration) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("domain registration repository is unavailable")
	}
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO domain_registrations
			(domain, registered_at_ms, expires_at_ms) VALUES (?, ?, ?)
			ON CONFLICT(domain) DO UPDATE SET registered_at_ms = excluded.registered_at_ms,
				expires_at_ms = excluded.expires_at_ms`, record.Domain,
			unixMillis(record.RegisteredAt), unixMillis(record.ExpiresAt))
		return err
	})
	if err != nil {
		return fmt.Errorf("store domain registration: %w", err)
	}
	return nil
}

func (r *domainRepository) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM domain_registrations`, r.options.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM domain_registrations WHERE id IN (
		SELECT id FROM domain_registrations ORDER BY expires_at_ms, id LIMIT ?
	)`, excess)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Cleanup removes records beyond the expiration grace period and trims the
// earliest-expiring remainder to the configured capacity.
func (r *domainRepository) Cleanup(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var deleted int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM domain_registrations WHERE expires_at_ms < ?`,
			unixMillis(r.now().UTC().Add(-r.options.ExpiryGrace)))
		if err != nil {
			return err
		}
		deleted, err = result.RowsAffected()
		if err != nil {
			return err
		}
		capacityDeleted, err := r.enforceCapacityTx(ctx, tx)
		deleted += capacityDeleted
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("clean domain registrations: %w", err)
	}
	return deleted, nil
}

func (r *domainRepository) Count(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var count int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM domain_registrations`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count domain registrations: %w", err)
	}
	return count, nil
}
