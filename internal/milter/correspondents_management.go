package milter

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

// AddManualCorrespondent adds an immediately qualified relationship. The
// caller must ensure the running daemon is stopped while editing its database.
func AddManualCorrespondent(cfg config.Config, sender, recipient string) (bool, error) {
	store, database, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return false, err
	}
	defer database.Close()
	return store.addManual(sender, recipient)
}

func (store *correspondentStore) addManual(sender, recipient string) (bool, error) {
	sender = normalizeEmailAddress(sender)
	recipient = normalizeEmailAddress(recipient)
	if sender == "" || recipient == "" {
		return false, fmt.Errorf("sender and recipient must be valid email addresses")
	}
	now := store.now().UTC()
	created := false
	ctx := context.Background()
	err := store.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		created = false
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
		if err != nil {
			return err
		}
		return store.enforceCapacityTx(ctx, tx)
	})
	return created, err
}

// DeleteCorrespondents deletes an exact relationship, or every relationship
// for sender when recipient is "*". Explicit deletion applies to all types.
func DeleteCorrespondents(cfg config.Config, sender, recipient string) (int, error) {
	store, database, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return 0, err
	}
	defer database.Close()
	return store.deleteManual(sender, recipient)
}

func (store *correspondentStore) deleteManual(sender, recipient string) (int, error) {
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
	result, err := store.db.Exec(context.Background(), query, args...)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	return int(removed), err
}

func openCorrespondentStoreForManagement(cfg config.Config) (*correspondentStore, *sqlstore.Store, error) {
	database, err := sqlstore.Open(context.Background(), cfg.Persistence.DatabaseFile, sqlstore.DefaultOptions())
	if err != nil {
		return nil, nil, err
	}
	return newCorrespondentStore(cfg.Correspondents, database, nil), database, nil
}
