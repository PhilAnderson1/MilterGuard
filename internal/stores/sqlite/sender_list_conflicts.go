package sqlite

import (
	"context"
	"database/sql"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// deleteExactSenderBlocksTx removes only recipient-specific exact-mailbox
// blocks. Broader domain and server-wide rules remain authoritative.
func deleteExactSenderBlocksTx(ctx context.Context, tx *sql.Tx, recipient string, senders []string) error {
	if len(senders) == 0 {
		return nil
	}
	query := `DELETE FROM sender_blocklist WHERE recipient=? AND sender_kind=? AND sender_value IN (` + placeholders(len(senders)) + `)`
	args := make([]any, 0, len(senders)+2)
	args = append(args, recipient, stores.SenderBlockExactMailbox)
	for _, sender := range senders {
		args = append(args, sender)
	}
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}

// deleteCorrespondentsForExactBlockTx removes trust relationships contradicted
// by a newly added exact-mailbox block. A server-wide exact block applies to
// every local address, so it removes every relationship with that mailbox.
func deleteCorrespondentsForExactBlockTx(ctx context.Context, tx *sql.Tx, recipient, sender string) error {
	query := `DELETE FROM correspondents WHERE correspondent=?`
	args := []any{sender}
	if recipient != "*" {
		query += ` AND local_address=?`
		args = append(args, recipient)
	}
	_, err := tx.ExecContext(ctx, query, args...)
	return err
}
