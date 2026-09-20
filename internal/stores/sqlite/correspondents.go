package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const maxCorrespondentRecipients = 100

// correspondentRepository persists learned and manually managed correspondents.
type correspondentRepository struct {
	options CorrespondentOptions
	db      *sqlitedb.Store
	now     func() time.Time
	log     *slog.Logger
}

func NewCorrespondents(db *sqlitedb.Store, options CorrespondentOptions, log *slog.Logger) stores.CorrespondentRepository {
	return &correspondentRepository{options: options, db: db, now: clock(options.Now), log: log}
}

var _ stores.CorrespondentRepository = (*correspondentRepository)(nil)

func (r *correspondentRepository) LearnAuthenticated(ctx context.Context, localAddress string, recipients []string) error {
	if r == nil || r.db == nil || !r.options.LearnAuthenticatedRecipients {
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

	now := r.now().UTC()
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
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		added = 0
		if r.options.StaleAfter > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-r.options.StaleAfter)))
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
		args = append(args, r.activityDueArgs(now)...)
		if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms=?
			WHERE `+target+` AND whitelist_type=?`+r.activityDueSQL(), args...); err != nil {
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
	if r.log != nil {
		r.log.Debug("correspondent allowlist updated", "new_entries", added)
	}
	return nil
}

// touchInbound expects the canonical correspondent address derived for the
// current message; recipient addresses are normalized at the store boundary.
func (r *correspondentRepository) TouchInbound(ctx context.Context, correspondent string, recipients []string) error {
	if r == nil || r.db == nil || !r.options.UseAllowlist {
		return nil
	}
	if correspondent == "" {
		return nil
	}
	now := r.now().UTC()
	query := `UPDATE correspondents SET last_activity_at_ms = ?
		WHERE correspondent = ? AND ` + r.qualifiedSQL() + r.notStaleSQL() + r.activityDueSQL()
	args := []any{unixMillis(now), correspondent, r.options.LegitimateSenderMinMessages}
	args = append(args, r.notStaleArgs(now)...)
	args = append(args, r.activityDueArgs(now)...)
	if r.options.Scope == "per_sender" {
		addresses := sortedSet(normalizedAddressSet(recipients, maxCorrespondentRecipients))
		if len(addresses) == 0 {
			return nil
		}
		query += " AND local_address IN (" + placeholders(len(addresses)) + ")"
		for _, address := range addresses {
			args = append(args, address)
		}
	}
	_, err := r.db.Exec(ctx, query, args...)
	return err
}

// recordInboundClassification expects the canonical correspondent address
// derived for the current message.
func (r *correspondentRepository) RecordInboundClassification(ctx context.Context, input stores.InboundClassification) error {
	if r == nil || r.db == nil || !input.RecipientsComplete {
		return nil
	}
	correspondent := input.Correspondent
	recipientSet := normalizedAddressSet(input.Recipients, maxCorrespondentRecipients)
	if correspondent == "" || len(recipientSet) == 0 {
		return nil
	}
	recipientList := sortedSet(recipientSet)
	now := r.now().UTC()
	if input.Classification == "unwanted" {
		if input.Score < input.UnwantedMinScore {
			return nil
		}
		query := `DELETE FROM correspondents WHERE correspondent = ? AND whitelist_type = ?`
		args := []any{correspondent, stores.CorrespondentKindRepeatedLegitimateInbound}
		if r.options.Scope == "per_sender" {
			query += " AND local_address IN (" + placeholders(len(recipientList)) + ")"
			for _, recipient := range recipientList {
				args = append(args, recipient)
			}
		}
		result, err := r.db.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		removed, _ := result.RowsAffected()
		if removed > 0 && r.log != nil {
			r.log.Debug("inbound-learned correspondent removed after unwanted classification", "correspondent", correspondent, "removed_entries", removed)
		}
		return nil
	}
	if input.Classification != "legitimate" {
		return nil
	}

	qualifying := r.options.LearnLegitimateSenders && input.Score >= r.options.LegitimateSenderMinScore && (!r.options.LegitimateSenderRequireDKIM || input.DKIMAligned)
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
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		events = nil
		if r.options.StaleAfter > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-r.options.StaleAfter)))
			if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE `+target+` AND last_activity_at_ms < ?`, args...); err != nil {
				return err
			}
		}
		if qualifying {
			args := []any{unixMillis(now)}
			args = append(args, targetArgs...)
			args = append(args, stores.CorrespondentKindRepeatedLegitimateInbound, r.options.LegitimateSenderMinMessages)
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
				event.promoted = event.count >= r.options.LegitimateSenderMinMessages
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
		args = append(args, r.options.LegitimateSenderMinMessages, unixMillis(now))
		args = append(args, r.activityDueArgs(now)...)
		if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms=?
			WHERE `+target+` AND `+r.qualifiedSQL()+` AND last_activity_at_ms<>?`+r.activityDueSQL(), args...); err != nil {
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
				event.promoted = event.count >= r.options.LegitimateSenderMinMessages
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
	if err != nil || r.log == nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool { return events[i].recipient < events[j].recipient })
	for _, event := range events {
		if event.promoted {
			r.log.Debug("inbound sender promoted to known correspondent", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count)
		} else {
			r.log.Debug("inbound sender legitimate candidate updated", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count, "required_count", r.options.LegitimateSenderMinMessages)
		}
	}
	return nil
}

// match expects the canonical correspondent address derived for the current
// message.
func (r *correspondentRepository) Match(ctx context.Context, correspondent string, recipients []string) (stores.CorrespondentMatch, error) {
	result := stores.CorrespondentMatch{}
	if r == nil || r.db == nil || !r.options.UseAllowlist {
		return result, nil
	}
	if correspondent == "" {
		return result, nil
	}
	now := r.now().UTC()
	if r.options.Scope == "global" {
		var found int
		query := `SELECT EXISTS(SELECT 1 FROM correspondents WHERE correspondent = ? AND ` + r.qualifiedSQL() + r.notStaleSQL() + `)`
		args := []any{correspondent, r.options.LegitimateSenderMinMessages}
		args = append(args, r.notStaleArgs(now)...)
		if err := r.db.QueryRow(ctx, query, args...).Scan(&found); err != nil {
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
	query := `SELECT count(*) FROM correspondents WHERE correspondent = ? AND ` + r.qualifiedSQL() + r.notStaleSQL() +
		" AND local_address IN (" + placeholders(len(addresses)) + ")"
	args := []any{correspondent, r.options.LegitimateSenderMinMessages}
	args = append(args, r.notStaleArgs(now)...)
	for _, address := range addresses {
		args = append(args, address)
	}
	if err := r.db.QueryRow(ctx, query, args...).Scan(&result.MatchedRecipients); err != nil {
		return stores.CorrespondentMatch{TotalRecipients: len(addresses)}, fmt.Errorf("match correspondent recipients: %w", err)
	}
	result.Known = result.MatchedRecipients > 0
	result.AllRecipientsMatched = result.MatchedRecipients == result.TotalRecipients
	return result, nil
}

func (r *correspondentRepository) ListCorrespondents(ctx context.Context, list stores.CorrespondentListQuery) (stores.CorrespondentPage, error) {
	if r == nil || r.db == nil {
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
	now := r.now().UTC()
	query := `SELECT id, local_address, correspondent, learned_at_ms, last_activity_at_ms,
		whitelist_type, legitimate_email_count FROM correspondents WHERE ` + r.qualifiedSQL() + r.notStaleSQL()
	args := []any{r.options.LegitimateSenderMinMessages}
	args = append(args, r.notStaleArgs(now)...)
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
	rows, err := r.db.Query(ctx, query, args...)
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

func (r *correspondentRepository) qualified(entry stores.Correspondent) bool {
	return entry.WhitelistType == stores.CorrespondentKindAuthenticatedOutbound || entry.WhitelistType == stores.CorrespondentKindManual ||
		(entry.WhitelistType == stores.CorrespondentKindRepeatedLegitimateInbound && entry.LegitimateEmailCount >= r.options.LegitimateSenderMinMessages)
}

func (r *correspondentRepository) qualifiedSQL() string {
	return `(whitelist_type IN ('authenticated_outbound', 'manual') OR
		(whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count >= ?))`
}

func (r *correspondentRepository) notStaleSQL() string {
	if r.options.StaleAfter <= 0 {
		return ""
	}
	return " AND last_activity_at_ms >= ?"
}

func (r *correspondentRepository) notStaleArgs(now time.Time) []any {
	if r.options.StaleAfter <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-r.options.StaleAfter))}
}

func (r *correspondentRepository) activityDueSQL() string {
	if r.options.ActivityUpdateInterval <= 0 {
		return ""
	}
	return " AND last_activity_at_ms <= ?"
}

func (r *correspondentRepository) activityDueArgs(now time.Time) []any {
	if r.options.ActivityUpdateInterval <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-r.options.ActivityUpdateInterval))}
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

func (r *correspondentRepository) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM correspondents`, r.options.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id IN (
		SELECT id FROM correspondents
		WHERE whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count < ?
		ORDER BY last_activity_at_ms, id LIMIT ?)`, r.options.LegitimateSenderMinMessages, excess)
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

func (r *correspondentRepository) Cleanup(ctx context.Context) (int64, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var deleted int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var attemptDeleted int64
		if r.options.StaleAfter > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE last_activity_at_ms < ?`,
				unixMillis(r.now().UTC().Add(-r.options.StaleAfter)))
			if err != nil {
				return err
			}
			attemptDeleted, err = result.RowsAffected()
			if err != nil {
				return err
			}
		}
		removed, err := r.enforceCapacityTx(ctx, tx)
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

func (r *correspondentRepository) Count(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var count int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM correspondents`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count correspondents: %w", err)
	}
	return count, nil
}
