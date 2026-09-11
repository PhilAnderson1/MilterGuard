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
)

const (
	maxRejectionSubjectRunes = 1000
	maxRejectionReasonRunes  = 1000
)

type rejectionHistoryEntry struct {
	ID         uint64
	Sender     string
	Subject    string
	Recipients []string
	RejectedAt time.Time
	Reason     string
}

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

func (s *rejectionHistoryStore) add(ctx context.Context, visibleSender, envelopeSender, subject string, recipients, reasons []string) error {
	_, err := s.addWithID(ctx, visibleSender, envelopeSender, subject, recipients, reasons)
	return err
}

func (s *rejectionHistoryStore) addWithID(ctx context.Context, visibleSender, envelopeSender, subject string, recipients, reasons []string) (uint64, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return 0, nil
	}
	sender := normalizeEmailAddress(visibleSender)
	if sender == "" {
		sender = normalizeEmailAddress(envelopeSender)
	}
	if sender == "" {
		return 0, nil
	}
	unique := normalizedAddressSet(recipients, maxLearnedRecipients)
	if len(unique) == 0 {
		return 0, nil
	}
	normalizedRecipients := sortedSet(unique)
	now := s.now().UTC()
	subject = rejectionSingleLine(subject, maxRejectionSubjectRunes)
	reason := rejectionReason(reasons)
	recipientQuery := `INSERT INTO rejection_recipients (rejection_id, recipient) VALUES ` +
		valuePlaceholders(len(normalizedRecipients), 2)

	var recordID int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `INSERT INTO rejections
			(sender, subject, rejected_at_ms, reason) VALUES (?, ?, ?, ?)`,
			sender, subject, unixMillis(now), reason)
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
		return 0, err
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

func (s *rejectionHistoryStore) list(recipient string) ([]rejectionHistoryEntry, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return nil, nil
	}
	allRecipients := recipient == "*"
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return nil, nil
		}
	}
	cutoff := unixMillis(s.now().UTC().Add(-s.cfg.Expiry.Value()))
	if !allRecipients {
		rows, err := s.db.Query(context.Background(), `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason
			FROM rejection_recipients rr JOIN rejections r ON r.id = rr.rejection_id
			WHERE rr.recipient = ? AND r.rejected_at_ms >= ?
			ORDER BY r.rejected_at_ms DESC, r.id DESC`, recipient, cutoff)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var entries []rejectionHistoryEntry
		for rows.Next() {
			entry := rejectionHistoryEntry{Recipients: []string{recipient}}
			var id, rejectedAt int64
			if err := rows.Scan(&id, &entry.Sender, &entry.Subject, &rejectedAt, &entry.Reason); err != nil {
				return nil, err
			}
			entry.ID, entry.RejectedAt = uint64(id), time.UnixMilli(rejectedAt).UTC()
			entries = append(entries, entry)
		}
		return entries, rows.Err()
	}

	rows, err := s.db.Query(context.Background(), `SELECT r.id, r.sender, r.subject, r.rejected_at_ms, r.reason, rr.recipient
		FROM rejections r JOIN rejection_recipients rr ON rr.rejection_id = r.id
		WHERE r.rejected_at_ms >= ?
		ORDER BY r.rejected_at_ms DESC, r.id DESC, rr.recipient ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []rejectionHistoryEntry
	for rows.Next() {
		var id, rejectedAt int64
		var sender, subject, reason, currentRecipient string
		if err := rows.Scan(&id, &sender, &subject, &rejectedAt, &reason, &currentRecipient); err != nil {
			return nil, err
		}
		if len(entries) == 0 || entries[len(entries)-1].ID != uint64(id) {
			entries = append(entries, rejectionHistoryEntry{ID: uint64(id), Sender: sender, Subject: subject,
				RejectedAt: time.UnixMilli(rejectedAt).UTC(), Reason: reason})
		}
		entries[len(entries)-1].Recipients = append(entries[len(entries)-1].Recipients, currentRecipient)
	}
	return entries, rows.Err()
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
		return 0, err
	}
	return result.RowsAffected()
}

func (s *rejectionHistoryStore) cleanup() (int64, error) {
	if s == nil || s.db == nil || !rejectionHistoryEnabled(s.cfg) {
		return 0, nil
	}
	ctx := context.Background()
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if s.cfg.Expiry.Value() > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM rejections WHERE rejected_at_ms < ?`, unixMillis(s.now().UTC().Add(-s.cfg.Expiry.Value())))
			if err != nil {
				return err
			}
			if n, err := result.RowsAffected(); err == nil {
				deleted += n
			}
		}
		capacityDeleted, err := s.enforceCapacityTx(ctx, tx)
		if err != nil {
			return err
		}
		deleted += capacityDeleted
		return nil
	})
	return deleted, err
}

func (s *rejectionHistoryStore) size() int {
	if s == nil || s.db == nil {
		return 0
	}
	var count int
	if err := s.db.QueryRow(context.Background(), `SELECT COUNT(*) FROM rejections`).Scan(&count); err != nil {
		return 0
	}
	return count
}
