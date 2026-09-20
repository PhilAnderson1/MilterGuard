package milter

import (
	"context"
	"database/sql"
	"fmt"
)

func (store *correspondentStore) addManual(ctx context.Context, sender, recipient string) (bool, error) {
	if store == nil || store.db == nil || !store.cfg.UseAllowlist {
		return false, fmt.Errorf("correspondent allowlisting is disabled or unavailable")
	}
	sender = normalizeEmailAddress(sender)
	recipient = normalizeEmailAddress(recipient)
	if sender == "" || recipient == "" {
		return false, fmt.Errorf("sender and recipient must be valid email addresses")
	}
	now := store.now().UTC()
	created := false
	err := store.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
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
			legitimate_email_count = 0`, recipient, sender, unixMillis(now), unixMillis(now), whitelistManual)
		return err
	})
	return created, err
}

func (store *correspondentStore) deleteManual(ctx context.Context, sender, recipient string) (int, error) {
	if store == nil || store.db == nil || !store.cfg.UseAllowlist {
		return 0, fmt.Errorf("correspondent allowlisting is disabled or unavailable")
	}
	sender = normalizeEmailAddress(sender)
	if sender == "" {
		return 0, fmt.Errorf("sender must be a valid email address")
	}
	query := `DELETE FROM correspondents WHERE correspondent = ?`
	args := []any{sender}
	if recipient != "*" {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return 0, fmt.Errorf("recipient must be a valid email address or *")
		}
		query += " AND local_address = ?"
		args = append(args, recipient)
	}
	result, err := store.db.Exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return int(removed), err
}
