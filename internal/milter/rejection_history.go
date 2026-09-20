package milter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	maxRejectionSubjectRunes = 1000
	maxRejectionReasonRunes  = 1000
	maxRejectionRecipients   = 100
)

// rejectionHistoryStore is a purpose-built SQL repository. One rejection row
// represents one SMTP event; its recipients are committed in the same
// transaction and removed by foreign-key cascade with their parent.
type rejectionHistoryStore struct {
	cfg config.RejectionHistoryConfig
	db  *sqlstore.Store
	now func() time.Time
	log *slog.Logger
}

func newRejectionHistoryStore(cfg config.RejectionHistoryConfig, db *sqlstore.Store, log *slog.Logger) *rejectionHistoryStore {
	return &rejectionHistoryStore{cfg: cfg, db: db, now: time.Now, log: log}
}

func rejectionHistoryEnabled(cfg config.RejectionHistoryConfig) bool {
	return cfg.Expiry.Value() > 0
}

var _ stores.RejectionRepository = (*rejectionHistoryStore)(nil)
var _ stores.MaintainedRepository = (*rejectionHistoryStore)(nil)
var _ stores.RejectionHistoryRepository = (*rejectionHistoryStore)(nil)

func (s *rejectionHistoryStore) AddRejection(ctx context.Context, input stores.NewRejection) (uint64, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return 0, nil
	}
	rejectedAt := input.RejectedAt
	if rejectedAt.IsZero() {
		rejectedAt = s.now().UTC()
	}
	sender := normalizeEmailAddress(input.VisibleSender)
	if sender == "" {
		sender = normalizeEmailAddress(input.EnvelopeSender)
	}
	if sender == "" {
		return 0, nil
	}
	unique := normalizedAddressSet(input.Recipients, maxRejectionRecipients)
	if len(unique) == 0 {
		return 0, nil
	}
	normalizedRecipients := sortedSet(unique)
	rejectedAt = rejectedAt.UTC()
	subject := rejectionSingleLine(input.Subject, maxRejectionSubjectRunes)
	reason := rejectionReason(input.Reasons)
	recipientQuery := `INSERT INTO rejection_recipients (rejection_id, recipient) VALUES ` +
		valuePlaceholders(len(normalizedRecipients), 2)

	var recordID int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `INSERT INTO rejections
			(sender, subject, rejected_at_ms, reason) VALUES (?, ?, ?, ?)`,
			sender, subject, unixMillis(rejectedAt), reason)
		if err != nil {
			return err
		}
		recordID, err = result.LastInsertId()
		if err != nil {
			return fmt.Errorf("read rejection ID: %w", err)
		}
		args := make([]any, 0, len(normalizedRecipients)*2)
		for _, recipient := range normalizedRecipients {
			args = append(args, recordID, recipient)
		}
		if _, err := tx.ExecContext(ctx, recipientQuery, args...); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("add rejection history record: %w", err)
	}
	if s.log != nil {
		s.log.Debug("rejection history updated", "new_entries", 1, "recipient_count", len(normalizedRecipients))
	}
	return uint64(recordID), nil
}

func rejectionReason(reasons []string) string {
	cleaned := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reason = rejectionSingleLine(reason, maxRejectionReasonRunes)
		if reason != "" {
			cleaned = append(cleaned, reason)
		}
	}
	return rejectionSingleLine(strings.Join(cleaned, "; "), maxRejectionReasonRunes)
}

func rejectionSingleLine(value string, maxRunes int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(value, "�"))
	value = strings.Join(strings.Fields(value), " ")
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	return string([]rune(value)[:maxRunes]) + "…"
}

func (s *rejectionHistoryStore) ListRejections(ctx context.Context, query stores.RejectionListQuery) (stores.RejectionPage, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return stores.RejectionPage{}, nil
	}
	if err := query.Recipients.Validate(); err != nil {
		return stores.RejectionPage{}, fmt.Errorf("invalid rejection list query: %w", err)
	}
	if query.Limit < 1 {
		return stores.RejectionPage{}, fmt.Errorf("rejection list limit must be positive")
	}
	allRecipients := query.Recipients.All
	recipient := query.Recipients.Address
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return stores.RejectionPage{}, nil
		}
	}
	retentionSince := s.now().UTC().Add(-s.cfg.Expiry.Value())
	if !query.RejectedSince.IsZero() && query.RejectedSince.After(retentionSince) {
		retentionSince = query.RejectedSince
	}
	cutoff := unixMillis(retentionSince)
	if !allRecipients {
		rows, err := s.db.Query(ctx, `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason
			FROM rejection_recipients rr JOIN rejections r ON r.id = rr.rejection_id
			WHERE rr.recipient = ? AND r.rejected_at_ms >= ?
			ORDER BY r.rejected_at_ms DESC, r.id DESC LIMIT ?`, recipient, cutoff, query.Limit+1)
		if err != nil {
			return stores.RejectionPage{}, fmt.Errorf("list rejection history: %w", err)
		}
		defer rows.Close()
		var entries []stores.Rejection
		for rows.Next() {
			entry := stores.Rejection{Recipients: []string{recipient}}
			var id, rejectedAt int64
			if err := rows.Scan(&id, &entry.Sender, &entry.Subject, &rejectedAt, &entry.Reason); err != nil {
				return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
			}
			entry.ID, entry.RejectedAt = uint64(id), time.UnixMilli(rejectedAt).UTC()
			entries = append(entries, entry)
		}
		if err := rows.Err(); err != nil {
			return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
		}
		return rejectionPage(entries, query.Limit), nil
	}

	rows, err := s.db.Query(ctx, `WITH limited_rejections AS (
			SELECT id, sender, subject, rejected_at_ms, reason FROM rejections
			WHERE rejected_at_ms >= ?
			ORDER BY rejected_at_ms DESC, id DESC LIMIT ?
		)
		SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason, rr.recipient
		FROM limited_rejections r JOIN rejection_recipients rr ON rr.rejection_id = r.id
		ORDER BY r.rejected_at_ms DESC, r.id DESC, rr.recipient ASC`, cutoff, query.Limit+1)
	if err != nil {
		return stores.RejectionPage{}, fmt.Errorf("list rejection history: %w", err)
	}
	defer rows.Close()
	var entries []stores.Rejection
	for rows.Next() {
		var id, rejectedAt int64
		var sender, subject, reason, currentRecipient string
		if err := rows.Scan(&id, &sender, &subject, &rejectedAt, &reason, &currentRecipient); err != nil {
			return stores.RejectionPage{}, fmt.Errorf("read rejection history: %w", err)
		}
		if len(entries) == 0 || entries[len(entries)-1].ID != uint64(id) {
			entries = append(entries, stores.Rejection{ID: uint64(id), Sender: sender, Subject: subject,
				RejectedAt: time.UnixMilli(rejectedAt).UTC(), Reason: reason})
		}
		entries[len(entries)-1].Recipients = append(entries[len(entries)-1].Recipients, currentRecipient)
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

func (s *rejectionHistoryStore) RejectionByID(ctx context.Context, id uint64, scope stores.RecipientScope) (stores.Rejection, bool, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) || id == 0 {
		return stores.Rejection{}, false, nil
	}
	if err := scope.Validate(); err != nil {
		return stores.Rejection{}, false, err
	}
	cutoff := unixMillis(s.now().UTC().Add(-s.cfg.Expiry.Value()))
	query := `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason, rr.recipient
		FROM rejections r JOIN rejection_recipients rr ON rr.rejection_id = r.id
		WHERE r.id = ? AND r.rejected_at_ms >= ?`
	args := []any{id, cutoff}
	if !scope.All {
		recipient := normalizeEmailAddress(scope.Address)
		if recipient == "" {
			return stores.Rejection{}, false, nil
		}
		query += ` AND rr.recipient = ?`
		args = append(args, recipient)
	}
	query += ` ORDER BY rr.recipient`
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return stores.Rejection{}, false, fmt.Errorf("look up rejection history record: %w", err)
	}
	defer rows.Close()
	var entry stores.Rejection
	for rows.Next() {
		var rowID, rejectedAt int64
		var sender, subject, reason, currentRecipient string
		if err := rows.Scan(&rowID, &sender, &subject, &rejectedAt, &reason, &currentRecipient); err != nil {
			return stores.Rejection{}, false, fmt.Errorf("read rejection history record: %w", err)
		}
		if entry.ID == 0 {
			entry = stores.Rejection{ID: uint64(rowID), Sender: sender, Subject: subject,
				RejectedAt: time.UnixMilli(rejectedAt).UTC(), Reason: reason}
		}
		entry.Recipients = append(entry.Recipients, currentRecipient)
	}
	if err := rows.Err(); err != nil {
		return stores.Rejection{}, false, fmt.Errorf("read rejection history record: %w", err)
	}
	return entry, entry.ID != 0, nil
}

func (s *rejectionHistoryStore) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM rejections`, s.cfg.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM rejections WHERE id IN (
		SELECT id FROM rejections ORDER BY rejected_at_ms, id LIMIT ?
	)`, excess)
	if err != nil {
		return 0, fmt.Errorf("clean rejection history: %w", err)
	}
	return result.RowsAffected()
}

func (s *rejectionHistoryStore) Cleanup(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return 0, nil
	}
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var attemptDeleted int64
		if s.cfg.Expiry.Value() > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM rejections WHERE rejected_at_ms < ?`, unixMillis(s.now().UTC().Add(-s.cfg.Expiry.Value())))
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			attemptDeleted += n
		}
		capacityDeleted, err := s.enforceCapacityTx(ctx, tx)
		if err != nil {
			return err
		}
		attemptDeleted += capacityDeleted
		deleted = attemptDeleted
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("clean rejection history: %w", err)
	}
	return deleted, nil
}

func (s *rejectionHistoryStore) Count(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var count int
	if err := s.db.QueryRow(ctx, `SELECT COUNT(*) FROM rejections`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count rejection history: %w", err)
	}
	return count, nil
}
