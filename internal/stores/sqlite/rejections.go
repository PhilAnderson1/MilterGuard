package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	maxRejectionSubjectRunes = 1000
	maxRejectionReasonRunes  = 1000
	maxRejectionRecipients   = 100
)

type rejectionRepository struct {
	options RejectionOptions
	db      *sqlitedb.Store
	now     func() time.Time
	log     *slog.Logger
}

func NewRejections(db *sqlitedb.Store, options RejectionOptions, log *slog.Logger) stores.RejectionHistoryRepository {
	return &rejectionRepository{options: options, db: db, now: clock(options.Now), log: log}
}

var _ stores.RejectionHistoryRepository = (*rejectionRepository)(nil)

func (r *rejectionRepository) enabled() bool { return r != nil && r.db != nil && r.options.Expiry > 0 }

func (r *rejectionRepository) AddRejection(ctx context.Context, input stores.NewRejection) (uint64, error) {
	if !r.enabled() {
		return 0, nil
	}
	rejectedAt := input.RejectedAt
	if rejectedAt.IsZero() {
		rejectedAt = r.now().UTC()
	}
	sender := message.NormalizeEmailAddress(input.VisibleSender)
	if sender == "" {
		sender = message.NormalizeEmailAddress(input.EnvelopeSender)
	}
	if sender == "" {
		return 0, nil
	}
	unique := normalizedAddressSet(input.Recipients, maxRejectionRecipients)
	if len(unique) == 0 {
		return 0, nil
	}
	recipients := sortedSet(unique)
	subject := rejectionSingleLine(input.Subject, maxRejectionSubjectRunes)
	reason := rejectionReason(input.Reasons)
	query := `INSERT INTO rejection_recipients (rejection_id, recipient) VALUES ` + valuePlaceholders(len(recipients), 2)

	var id int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `INSERT INTO rejections
			(sender, subject, rejected_at_ms, reason) VALUES (?, ?, ?, ?)`,
			sender, subject, unixMillis(rejectedAt), reason)
		if err != nil {
			return err
		}
		id, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read rejection ID: %w", err)
		}
		args := make([]any, 0, len(recipients)*2)
		for _, recipient := range recipients {
			args = append(args, id, recipient)
		}
		_, err = tx.ExecContext(ctx, query, args...)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("add rejection history record: %w", err)
	}
	if r.log != nil {
		r.log.Debug("rejection history updated", "new_entries", 1, "recipient_count", len(recipients))
	}
	return uint64(id), nil
}

func rejectionReason(reasons []string) string {
	cleaned := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if reason = rejectionSingleLine(reason, maxRejectionReasonRunes); reason != "" {
			cleaned = append(cleaned, reason)
		}
	}
	return rejectionSingleLine(strings.Join(cleaned, "; "), maxRejectionReasonRunes)
}

func rejectionSingleLine(value string, maximum int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(value, "�"))
	value = strings.Join(strings.Fields(value), " ")
	if utf8.RuneCountInString(value) <= maximum {
		return value
	}
	return string([]rune(value)[:maximum]) + "…"
}

func (r *rejectionRepository) ListRejections(ctx context.Context, query stores.RejectionListQuery) (stores.RejectionPage, error) {
	if !r.enabled() {
		return stores.RejectionPage{}, nil
	}
	if err := query.Recipients.Validate(); err != nil {
		return stores.RejectionPage{}, fmt.Errorf("invalid rejection list query: %w", err)
	}
	if query.Limit < 1 {
		return stores.RejectionPage{}, fmt.Errorf("rejection list limit must be positive")
	}
	recipient := query.Recipients.Address
	if !query.Recipients.All {
		recipient = message.NormalizeEmailAddress(recipient)
		if recipient == "" {
			return stores.RejectionPage{}, nil
		}
	}
	retentionSince := r.now().UTC().Add(-r.options.Expiry)
	if !query.RejectedSince.IsZero() && query.RejectedSince.After(retentionSince) {
		retentionSince = query.RejectedSince
	}
	cutoff := unixMillis(retentionSince)
	if !query.Recipients.All {
		rows, err := r.db.Query(ctx, `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason
			FROM rejection_recipients rr JOIN rejections r ON r.id = rr.rejection_id
			WHERE rr.recipient = ? AND r.rejected_at_ms >= ?
			ORDER BY r.rejected_at_ms DESC, r.id DESC LIMIT ?`, recipient, cutoff, query.Limit+1)
		if err != nil {
			return stores.RejectionPage{}, fmt.Errorf("list rejection history: %w", err)
		}
		defer rows.Close()
		entries := make([]stores.Rejection, 0)
		for rows.Next() {
			entry := stores.Rejection{Recipients: []string{recipient}}
			var id, rejectedAt int64
			if err := rows.Scan(&id, &entry.Sender, &entry.Subject, &rejectedAt, &entry.Reason); err != nil {
				return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
			}
			entry.ID, entry.RejectedAt = uint64(id), timeFromMillis(rejectedAt)
			entries = append(entries, entry)
		}
		if err := rows.Err(); err != nil {
			return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
		}
		return rejectionPage(entries, query.Limit), nil
	}

	rows, err := r.db.Query(ctx, `WITH limited_rejections AS (
			SELECT id, sender, subject, rejected_at_ms, reason FROM rejections
			WHERE rejected_at_ms >= ? ORDER BY rejected_at_ms DESC, id DESC LIMIT ?
		)
		SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason, rr.recipient
		FROM limited_rejections r JOIN rejection_recipients rr ON rr.rejection_id = r.id
		ORDER BY r.rejected_at_ms DESC, r.id DESC, rr.recipient ASC`, cutoff, query.Limit+1)
	if err != nil {
		return stores.RejectionPage{}, fmt.Errorf("list rejection history: %w", err)
	}
	defer rows.Close()
	entries := make([]stores.Rejection, 0)
	for rows.Next() {
		var id, rejectedAt int64
		var sender, subject, reason, recipient string
		if err := rows.Scan(&id, &sender, &subject, &rejectedAt, &reason, &recipient); err != nil {
			return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
		}
		if len(entries) == 0 || entries[len(entries)-1].ID != uint64(id) {
			entries = append(entries, stores.Rejection{ID: uint64(id), Sender: sender, Subject: subject,
				RejectedAt: timeFromMillis(rejectedAt), Reason: reason})
		}
		entries[len(entries)-1].Recipients = append(entries[len(entries)-1].Recipients, recipient)
	}
	if err := rows.Err(); err != nil {
		return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
	}
	return rejectionPage(entries, query.Limit), nil
}

func rejectionPage(entries []stores.Rejection, limit int) stores.RejectionPage {
	truncated := len(entries) > limit
	if truncated {
		entries = entries[:limit]
	}
	return stores.RejectionPage{Entries: entries, Truncated: truncated}
}

func (r *rejectionRepository) RejectionByID(ctx context.Context, id uint64, scope stores.RecipientScope) (stores.Rejection, bool, error) {
	if !r.enabled() || id == 0 {
		return stores.Rejection{}, false, nil
	}
	if err := scope.Validate(); err != nil {
		return stores.Rejection{}, false, err
	}
	query := `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason, rr.recipient
		FROM rejections r JOIN rejection_recipients rr ON rr.rejection_id = r.id
		WHERE r.id = ? AND r.rejected_at_ms >= ?`
	args := []any{id, unixMillis(r.now().UTC().Add(-r.options.Expiry))}
	if !scope.All {
		recipient := message.NormalizeEmailAddress(scope.Address)
		if recipient == "" {
			return stores.Rejection{}, false, nil
		}
		query += ` AND rr.recipient = ?`
		args = append(args, recipient)
	}
	query += ` ORDER BY rr.recipient`
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return stores.Rejection{}, false, fmt.Errorf("look up rejection history record: %w", err)
	}
	defer rows.Close()
	var entry stores.Rejection
	for rows.Next() {
		var rowID, rejectedAt int64
		var sender, subject, reason, recipient string
		if err := rows.Scan(&rowID, &sender, &subject, &rejectedAt, &reason, &recipient); err != nil {
			return stores.Rejection{}, false, fmt.Errorf("read rejection history record: %w", err)
		}
		if entry.ID == 0 {
			entry = stores.Rejection{ID: uint64(rowID), Sender: sender, Subject: subject,
				RejectedAt: timeFromMillis(rejectedAt), Reason: reason}
		}
		entry.Recipients = append(entry.Recipients, recipient)
	}
	if err := rows.Err(); err != nil {
		return stores.Rejection{}, false, fmt.Errorf("read rejection history record: %w", err)
	}
	return entry, entry.ID != 0, nil
}

func (r *rejectionRepository) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM rejections`, r.options.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM rejections WHERE id IN (
		SELECT id FROM rejections ORDER BY rejected_at_ms, id LIMIT ?
	)`, excess)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (r *rejectionRepository) Cleanup(ctx context.Context) (int64, error) {
	if !r.enabled() {
		return 0, nil
	}
	var deleted int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM rejections WHERE rejected_at_ms < ?`, unixMillis(r.now().UTC().Add(-r.options.Expiry)))
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
		return 0, fmt.Errorf("clean rejection history: %w", err)
	}
	return deleted, nil
}

func (r *rejectionRepository) Count(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var count int
	if err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM rejections`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count rejection history: %w", err)
	}
	return count, nil
}
