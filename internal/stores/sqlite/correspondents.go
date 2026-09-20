package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const maxCorrespondentRecipients = 100

// correspondentRepository persists learned and manually managed correspondents.
type correspondentRepository struct {
	options CorrespondentOptions
	db      *sqlstore.Store
	now     func() time.Time
	log     *slog.Logger
}

func NewCorrespondents(db *sqlstore.Store, options CorrespondentOptions, log *slog.Logger) stores.CorrespondentRepository {
	return &correspondentRepository{options: options, db: db, now: clock(options.Now), log: log}
}

var _ stores.CorrespondentRepository = (*correspondentRepository)(nil)

func (s *correspondentRepository) LearnAuthenticated(ctx context.Context, localAddress string, recipients []string) error {
	if s == nil || s.db == nil || !s.options.LearnAuthenticatedRecipients {
		return nil
	}
	localAddress = message.NormalizeEmailAddress(localAddress)
	if localAddress == "" {
		return fmt.Errorf("authenticated envelope sender is unavailable or invalid")
	}
	unique := normalizedAddressSet(recipients, maxCorrespondentRecipients)
	if len(unique) == 0 {
		return nil
	}

	now := s.now().UTC()
	recipients = sortedSet(unique)
	target := `local_address=? AND correspondent IN (` + placeholders(len(recipients)) + `)`
	targetArgs := make([]any, 1, len(recipients)+1)
	targetArgs[0] = localAddress
	for _, recipient := range recipients {
		targetArgs = append(targetArgs, recipient)
	}
	insertQuery := `INSERT INTO correspondents
		(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
		VALUES ` + valuePlaceholders(len(recipients), 6) + ` ON CONFLICT(local_address, correspondent) DO NOTHING`
	insertArgs := make([]any, 0, len(recipients)*6)
	for _, recipient := range recipients {
		insertArgs = append(insertArgs, localAddress, recipient, unixMillis(now), unixMillis(now), stores.CorrespondentKindAuthenticatedOutbound, 0)
	}
	added := 0
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		added = 0
		if s.options.StaleAfter > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-s.options.StaleAfter)))
			if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE `+target+` AND last_activity_at_ms < ?`, args...); err != nil {
				return err
			}
		}
		args := []any{stores.CorrespondentKindAuthenticatedOutbound, unixMillis(now)}
		args = append(args, targetArgs...)
		if _, err := tx.ExecContext(ctx, `UPDATE correspondents
			SET whitelist_type=?, legitimate_email_count=0, last_activity_at_ms=?
			WHERE `+target+` AND whitelist_type<>?`, append(args, stores.CorrespondentKindManual)...); err != nil {
			return err
		}
		args = []any{unixMillis(now)}
		args = append(args, targetArgs...)
		args = append(args, stores.CorrespondentKindManual)
		args = append(args, s.activityDueArgs(now)...)
		if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms=?
			WHERE `+target+` AND whitelist_type=?`+s.activityDueSQL(), args...); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, insertQuery, insertArgs...)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		added = int(count)
		return err
	})
	if err != nil {
		return err
	}
	if s.log != nil {
		s.log.Debug("correspondent allowlist updated", "new_entries", added)
	}
	return nil
}

// touchInbound expects the canonical correspondent address derived for the
// current message; recipient addresses are normalized at the store boundary.
func (s *correspondentRepository) TouchInbound(ctx context.Context, correspondent string, recipients []string) error {
	if s == nil || s.db == nil || !s.options.UseAllowlist {
		return nil
	}
	if correspondent == "" {
		return nil
	}
	now := s.now().UTC()
	query := `UPDATE correspondents SET last_activity_at_ms = ?
		WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() + s.activityDueSQL()
	args := []any{unixMillis(now), correspondent, s.options.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	args = append(args, s.activityDueArgs(now)...)
	if s.options.Scope == "per_sender" {
		addresses := sortedSet(normalizedAddressSet(recipients, maxCorrespondentRecipients))
		if len(addresses) == 0 {
			return nil
		}
		query += " AND local_address IN (" + placeholders(len(addresses)) + ")"
		for _, address := range addresses {
			args = append(args, address)
		}
	}
	_, err := s.db.Exec(ctx, query, args...)
	return err
}

// recordInboundClassification expects the canonical correspondent address
// derived for the current message.
func (s *correspondentRepository) RecordInboundClassification(ctx context.Context, input stores.InboundClassification) error {
	if s == nil || s.db == nil || !input.RecipientsComplete {
		return nil
	}
	correspondent := input.Correspondent
	recipientSet := normalizedAddressSet(input.Recipients, maxCorrespondentRecipients)
	if correspondent == "" || len(recipientSet) == 0 {
		return nil
	}
	recipientList := sortedSet(recipientSet)
	now := s.now().UTC()
	if input.Classification == "unwanted" {
		if input.Score < input.UnwantedMinScore {
			return nil
		}
		query := `DELETE FROM correspondents WHERE correspondent = ? AND whitelist_type = ?`
		args := []any{correspondent, stores.CorrespondentKindRepeatedLegitimateInbound}
		if s.options.Scope == "per_sender" {
			query += " AND local_address IN (" + placeholders(len(recipientList)) + ")"
			for _, recipient := range recipientList {
				args = append(args, recipient)
			}
		}
		result, err := s.db.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		removed, _ := result.RowsAffected()
		if removed > 0 && s.log != nil {
			s.log.Debug("inbound-learned correspondent removed after unwanted classification", "correspondent", correspondent, "removed_entries", removed)
		}
		return nil
	}
	if input.Classification != "legitimate" {
		return nil
	}

	qualifying := s.options.LearnLegitimateSenders && input.Score >= s.options.LegitimateSenderMinScore && (!s.options.LegitimateSenderRequireDKIM || input.DKIMAligned)
	type candidateEvent struct {
		recipient string
		count     int
		promoted  bool
	}
	var events []candidateEvent
	target := `correspondent=? AND local_address IN (` + placeholders(len(recipientList)) + `)`
	targetArgs := make([]any, 1, len(recipientList)+1)
	targetArgs[0] = correspondent
	for _, recipient := range recipientList {
		targetArgs = append(targetArgs, recipient)
	}
	var insertQuery string
	var insertArgs []any
	if qualifying {
		insertQuery = `INSERT INTO correspondents
			(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
			VALUES ` + valuePlaceholders(len(recipientList), 6) + `
			ON CONFLICT(local_address, correspondent) DO NOTHING
			RETURNING local_address, legitimate_email_count`
		insertArgs = make([]any, 0, len(recipientList)*6)
		for _, recipient := range recipientList {
			insertArgs = append(insertArgs, recipient, correspondent, unixMillis(now), unixMillis(now), stores.CorrespondentKindRepeatedLegitimateInbound, 1)
		}
	}
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		events = nil
		if s.options.StaleAfter > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-s.options.StaleAfter)))
			if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE `+target+` AND last_activity_at_ms < ?`, args...); err != nil {
				return err
			}
		}
		if qualifying {
			args := []any{unixMillis(now)}
			args = append(args, targetArgs...)
			args = append(args, stores.CorrespondentKindRepeatedLegitimateInbound, s.options.LegitimateSenderMinMessages)
			rows, err := tx.QueryContext(ctx, `UPDATE correspondents
				SET legitimate_email_count=legitimate_email_count+1, last_activity_at_ms=?
				WHERE `+target+` AND whitelist_type=? AND legitimate_email_count<?
				RETURNING local_address, legitimate_email_count`, args...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var event candidateEvent
				if err := rows.Scan(&event.recipient, &event.count); err != nil {
					rows.Close()
					return err
				}
				event.promoted = event.count >= s.options.LegitimateSenderMinMessages
				events = append(events, event)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		args := []any{unixMillis(now)}
		args = append(args, targetArgs...)
		args = append(args, s.options.LegitimateSenderMinMessages, unixMillis(now))
		args = append(args, s.activityDueArgs(now)...)
		if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms=?
			WHERE `+target+` AND `+s.qualifiedSQL()+` AND last_activity_at_ms<>?`+s.activityDueSQL(), args...); err != nil {
			return err
		}
		if qualifying {
			rows, err := tx.QueryContext(ctx, insertQuery, insertArgs...)
			if err != nil {
				return err
			}
			for rows.Next() {
				var event candidateEvent
				if err := rows.Scan(&event.recipient, &event.count); err != nil {
					rows.Close()
					return err
				}
				event.promoted = event.count >= s.options.LegitimateSenderMinMessages
				events = append(events, event)
			}
			if err := rows.Close(); err != nil {
				return err
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil || s.log == nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].recipient < events[j].recipient })
	for _, event := range events {
		if event.promoted {
			s.log.Debug("inbound sender promoted to known correspondent", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count)
		} else {
			s.log.Debug("inbound sender legitimate candidate updated", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count, "required_count", s.options.LegitimateSenderMinMessages)
		}
	}
	return nil
}

// match expects the canonical correspondent address derived for the current
// message.
func (s *correspondentRepository) Match(ctx context.Context, correspondent string, recipients []string) (stores.CorrespondentMatch, error) {
	result := stores.CorrespondentMatch{}
	if s == nil || s.db == nil || !s.options.UseAllowlist {
		return result, nil
	}
	if correspondent == "" {
		return result, nil
	}
	now := s.now().UTC()
	if s.options.Scope == "global" {
		var found int
		query := `SELECT EXISTS(SELECT 1 FROM correspondents WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() + `)`
		args := []any{correspondent, s.options.LegitimateSenderMinMessages}
		args = append(args, s.notStaleArgs(now)...)
		if err := s.db.QueryRow(ctx, query, args...).Scan(&found); err != nil {
			return result, fmt.Errorf("match correspondent: %w", err)
		}
		result.Known, result.AllRecipientsMatched, result.TotalRecipients = found != 0, found != 0, 1
		if result.Known {
			result.MatchedRecipients = 1
		}
		return result, nil
	}
	addresses := sortedSet(normalizedAddressSet(recipients, maxCorrespondentRecipients))
	result.TotalRecipients = len(addresses)
	if len(addresses) == 0 {
		return result, nil
	}
	query := `SELECT count(*) FROM correspondents WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() +
		" AND local_address IN (" + placeholders(len(addresses)) + ")"
	args := []any{correspondent, s.options.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	for _, address := range addresses {
		args = append(args, address)
	}
	if err := s.db.QueryRow(ctx, query, args...).Scan(&result.MatchedRecipients); err != nil {
		return stores.CorrespondentMatch{TotalRecipients: len(addresses)}, fmt.Errorf("match correspondent recipients: %w", err)
	}
	result.Known = result.MatchedRecipients > 0
	result.AllRecipientsMatched = result.MatchedRecipients == result.TotalRecipients
	return result, nil
}

func (s *correspondentRepository) ListCorrespondents(ctx context.Context, list stores.CorrespondentListQuery) (stores.CorrespondentPage, error) {
	if s == nil || s.db == nil {
		return stores.CorrespondentPage{}, nil
	}
	if err := list.Recipients.Validate(); err != nil {
		return stores.CorrespondentPage{}, err
	}
	if list.Limit < 1 {
		return stores.CorrespondentPage{}, fmt.Errorf("correspondent list limit must be positive")
	}
	allRecipients := list.Recipients.All
	recipient := list.Recipients.Address
	if !allRecipients {
		recipient = message.NormalizeEmailAddress(recipient)
		if recipient == "" {
			return stores.CorrespondentPage{}, nil
		}
	}
	now := s.now().UTC()
	query := `SELECT id, local_address, correspondent, learned_at_ms, last_activity_at_ms,
		whitelist_type, legitimate_email_count FROM correspondents WHERE ` + s.qualifiedSQL() + s.notStaleSQL()
	args := []any{s.options.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	if !list.ActiveSince.IsZero() {
		query += " AND last_activity_at_ms >= ?"
		args = append(args, unixMillis(list.ActiveSince))
	}
	if !allRecipients {
		query += " AND local_address = ?"
		args = append(args, recipient)
	}
	query += " ORDER BY last_activity_at_ms DESC, local_address, correspondent LIMIT ?"
	args = append(args, list.Limit+1)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return stores.CorrespondentPage{}, fmt.Errorf("list correspondent allowlist: %w", err)
	}
	defer rows.Close()
	var result []stores.Correspondent
	for rows.Next() {
		entry, err := scanCorrespondent(rows)
		if err != nil {
			return stores.CorrespondentPage{}, fmt.Errorf("read correspondent allowlist: %w", err)
		}
		result = append(result, entry)
	}
	if err := rows.Err(); err != nil {
		return stores.CorrespondentPage{}, fmt.Errorf("read correspondent allowlist: %w", err)
	}
	truncated := len(result) > list.Limit
	if truncated {
		result = result[:list.Limit]
	}
	return stores.CorrespondentPage{Entries: result, Truncated: truncated}, nil
}

func (s *correspondentRepository) qualified(entry stores.Correspondent) bool {
	return entry.WhitelistType == stores.CorrespondentKindAuthenticatedOutbound || entry.WhitelistType == stores.CorrespondentKindManual ||
		(entry.WhitelistType == stores.CorrespondentKindRepeatedLegitimateInbound && entry.LegitimateEmailCount >= s.options.LegitimateSenderMinMessages)
}

func (s *correspondentRepository) qualifiedSQL() string {
	return `(whitelist_type IN ('authenticated_outbound', 'manual') OR
		(whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count >= ?))`
}

func (s *correspondentRepository) notStaleSQL() string {
	if s.options.StaleAfter <= 0 {
		return ""
	}
	return " AND last_activity_at_ms >= ?"
}

func (s *correspondentRepository) notStaleArgs(now time.Time) []any {
	if s.options.StaleAfter <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-s.options.StaleAfter))}
}

func (s *correspondentRepository) activityDueSQL() string {
	if s.options.ActivityUpdateInterval <= 0 {
		return ""
	}
	return " AND last_activity_at_ms <= ?"
}

func (s *correspondentRepository) activityDueArgs(now time.Time) []any {
	if s.options.ActivityUpdateInterval <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-s.options.ActivityUpdateInterval))}
}

func scanCorrespondent(row rowScanner) (stores.Correspondent, error) {
	var entry stores.Correspondent
	var learnedAt, activityAt int64
	err := row.Scan(&entry.ID, &entry.LocalAddress, &entry.Correspondent, &learnedAt,
		&activityAt, &entry.WhitelistType, &entry.LegitimateEmailCount)
	if err == nil {
		entry.LearnedAt, entry.LastActivityAt = timeFromMillis(learnedAt), timeFromMillis(activityAt)
	}
	return entry, err
}

func (s *correspondentRepository) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM correspondents`, s.options.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id IN (
		SELECT id FROM correspondents
		WHERE whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count < ?
		ORDER BY last_activity_at_ms, id LIMIT ?)`, s.options.LegitimateSenderMinMessages, excess)
	if err != nil {
		return 0, err
	}
	removed, err := result.RowsAffected()
	if err != nil || int(removed) >= excess {
		return removed, err
	}
	result, err = tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id IN (
		SELECT id FROM correspondents ORDER BY last_activity_at_ms, id LIMIT ?)`, excess-int(removed))
	if err != nil {
		return 0, err
	}
	remainingRemoved, err := result.RowsAffected()
	return removed + remainingRemoved, err
}

func (s *correspondentRepository) Cleanup(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var attemptDeleted int64
		if s.options.StaleAfter > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE last_activity_at_ms < ?`,
				unixMillis(s.now().UTC().Add(-s.options.StaleAfter)))
			if err != nil {
				return err
			}
			attemptDeleted, err = result.RowsAffected()
			if err != nil {
				return err
			}
		}
		removed, err := s.enforceCapacityTx(ctx, tx)
		if err != nil {
			return err
		}
		attemptDeleted += removed
		deleted = attemptDeleted
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (s *correspondentRepository) Count(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM correspondents`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count correspondents: %w", err)
	}
	return count, nil
}
