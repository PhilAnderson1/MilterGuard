package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func (r *correspondentRepository) AddManual(ctx context.Context, sender, recipient string) (bool, error) {
	if r == nil || r.db == nil || !r.options.UseAllowlist {
		return false, fmt.Errorf("correspondent allowlisting is disabled or unavailable")
	}
	sender = mailaddr.Normalize(sender)
	recipient = mailaddr.Normalize(recipient)
	if sender == "" || recipient == "" {
		return false, fmt.Errorf("sender and recipient must be valid email addresses")
	}
	now := r.now().UTC()
	created := false
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM correspondents
			WHERE local_address = ? AND correspondent = ?)`, recipient, sender).Scan(&exists); err != nil {
			return err
		}
		created = exists == 0
		_, err := tx.ExecContext(ctx, `INSERT INTO correspondents
			(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
			VALUES (?, ?, ?, ?, ?, 0)
			ON CONFLICT(local_address, correspondent) DO UPDATE SET
			last_activity_at_ms = excluded.last_activity_at_ms,
			whitelist_type = excluded.whitelist_type,
			legitimate_email_count = 0`, recipient, sender, unixMillis(now), unixMillis(now), stores.CorrespondentKindManual)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("add manual correspondent: %w", err)
	}
	return created, nil
}

func (r *correspondentRepository) DeleteCorrespondent(ctx context.Context, sender string, scope stores.RecipientScope) (int, error) {
	if r == nil || r.db == nil || !r.options.UseAllowlist {
		return 0, fmt.Errorf("correspondent allowlisting is disabled or unavailable")
	}
	sender = mailaddr.Normalize(sender)
	if sender == "" {
		return 0, fmt.Errorf("sender must be a valid email address")
	}
	query := `DELETE FROM correspondents WHERE correspondent = ?`
	args := []any{sender}
	if err := scope.Validate(); err != nil {
		return 0, err
	}
	if !scope.All {
		recipient := mailaddr.Normalize(scope.Address)
		if recipient == "" {
			return 0, fmt.Errorf("recipient must be a valid email address or *")
		}
		query += " AND local_address = ?"
		args = append(args, recipient)
	}
	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("delete manual correspondent: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted manual correspondents: %w", err)
	}
	return int(removed), nil
}
