package milter

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const maxCorrespondentRecipients = 100

// correspondentStore is a purpose-built SQL repository. It deliberately does
// not expose generic map-like access or reproduce the former JSON-store API.
type correspondentStore struct {
	cfg config.CorrespondentsConfig
	db  *sqlstore.Store
	now func() time.Time
	log *slog.Logger
}

func newCorrespondentStore(cfg config.CorrespondentsConfig, db *sqlstore.Store, log *slog.Logger) *correspondentStore {
	return &correspondentStore{cfg: cfg, db: db, now: time.Now, log: log}
}

func correspondentFeaturesEnabled(cfg config.CorrespondentsConfig) bool {
	return cfg.LearnAuthenticatedRecipients || cfg.LearnLegitimateSenders || cfg.UseAllowlist
}

var _ stores.CorrespondentPolicyRepository = (*correspondentStore)(nil)
var _ stores.CorrespondentAdminRepository = (*correspondentStore)(nil)
var _ stores.MaintainedRepository = (*correspondentStore)(nil)
var _ stores.CorrespondentRepository = (*correspondentStore)(nil)

func (s *correspondentStore) LearnAuthenticated(ctx context.Context, localAddress string, recipients []string) error {
	if s == nil || s.db == nil || !s.cfg.LearnAuthenticatedRecipients {
		return nil
	}
	localAddress = normalizeEmailAddress(localAddress)
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
		if s.cfg.StaleAfter.Value() > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-s.cfg.StaleAfter.Value())))
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
func (s *correspondentStore) TouchInbound(ctx context.Context, correspondent string, recipients []string) error {
	if s == nil || s.db == nil || !s.cfg.UseAllowlist {
		return nil
	}
	if correspondent == "" {
		return nil
	}
	now := s.now().UTC()
	query := `UPDATE correspondents SET last_activity_at_ms = ?
		WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() + s.activityDueSQL()
	args := []any{unixMillis(now), correspondent, s.cfg.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	args = append(args, s.activityDueArgs(now)...)
	if s.cfg.Scope == "per_sender" {
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
func (s *correspondentStore) RecordInboundClassification(ctx context.Context, input stores.InboundClassification) error {
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
		if s.cfg.Scope == "per_sender" {
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

	qualifying := s.cfg.LearnLegitimateSenders && input.Score >= s.cfg.LegitimateSenderMinScore && (!s.cfg.LegitimateSenderRequireDKIM || input.DKIMAligned)
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
		if s.cfg.StaleAfter.Value() > 0 {
			args := append(append([]any{}, targetArgs...), unixMillis(now.Add(-s.cfg.StaleAfter.Value())))
			if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE `+target+` AND last_activity_at_ms < ?`, args...); err != nil {
				return err
			}
		}
		if qualifying {
			args := []any{unixMillis(now)}
			args = append(args, targetArgs...)
			args = append(args, stores.CorrespondentKindRepeatedLegitimateInbound, s.cfg.LegitimateSenderMinMessages)
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
				event.promoted = event.count >= s.cfg.LegitimateSenderMinMessages
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
		args = append(args, s.cfg.LegitimateSenderMinMessages, unixMillis(now))
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
				event.promoted = event.count >= s.cfg.LegitimateSenderMinMessages
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
			s.log.Debug("inbound sender legitimate candidate updated", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count, "required_count", s.cfg.LegitimateSenderMinMessages)
		}
	}
	return nil
}

// match expects the canonical correspondent address derived for the current
// message.
func (s *correspondentStore) Match(ctx context.Context, correspondent string, recipients []string) (stores.CorrespondentMatch, error) {
	result := stores.CorrespondentMatch{}
	if s == nil || s.db == nil || !s.cfg.UseAllowlist {
		return result, nil
	}
	if correspondent == "" {
		return result, nil
	}
	now := s.now().UTC()
	if s.cfg.Scope == "global" {
		var found int
		query := `SELECT EXISTS(SELECT 1 FROM correspondents WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() + `)`
		args := []any{correspondent, s.cfg.LegitimateSenderMinMessages}
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
	args := []any{correspondent, s.cfg.LegitimateSenderMinMessages}
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

func (s *correspondentStore) ListCorrespondents(ctx context.Context, list stores.CorrespondentListQuery) (stores.CorrespondentPage, error) {
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
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return stores.CorrespondentPage{}, nil
		}
	}
	now := s.now().UTC()
	query := `SELECT id, local_address, correspondent, learned_at_ms, last_activity_at_ms,
		whitelist_type, legitimate_email_count FROM correspondents WHERE ` + s.qualifiedSQL() + s.notStaleSQL()
	args := []any{s.cfg.LegitimateSenderMinMessages}
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

func (s *correspondentStore) qualified(entry stores.Correspondent) bool {
	return entry.WhitelistType == stores.CorrespondentKindAuthenticatedOutbound || entry.WhitelistType == stores.CorrespondentKindManual ||
		(entry.WhitelistType == stores.CorrespondentKindRepeatedLegitimateInbound && entry.LegitimateEmailCount >= s.cfg.LegitimateSenderMinMessages)
}

func (s *correspondentStore) qualifiedSQL() string {
	return `(whitelist_type IN ('authenticated_outbound', 'manual') OR
		(whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count >= ?))`
}

func (s *correspondentStore) notStaleSQL() string {
	if s.cfg.StaleAfter.Value() <= 0 {
		return ""
	}
	return " AND last_activity_at_ms >= ?"
}

func (s *correspondentStore) notStaleArgs(now time.Time) []any {
	if s.cfg.StaleAfter.Value() <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-s.cfg.StaleAfter.Value()))}
}

func (s *correspondentStore) activityDueSQL() string {
	if s.cfg.ActivityUpdateInterval.Value() <= 0 {
		return ""
	}
	return " AND last_activity_at_ms <= ?"
}

func (s *correspondentStore) activityDueArgs(now time.Time) []any {
	if s.cfg.ActivityUpdateInterval.Value() <= 0 {
		return nil
	}
	return []any{unixMillis(now.Add(-s.cfg.ActivityUpdateInterval.Value()))}
}

type rowScanner interface{ Scan(...any) error }

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

func (s *correspondentStore) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*) - ?, 0) FROM correspondents`, s.cfg.MaxEntries).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id IN (
		SELECT id FROM correspondents
		WHERE whitelist_type = 'repeated_legitimate_inbound' AND legitimate_email_count < ?
		ORDER BY last_activity_at_ms, id LIMIT ?)`, s.cfg.LegitimateSenderMinMessages, excess)
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

func (s *correspondentStore) Cleanup(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var attemptDeleted int64
		if s.cfg.StaleAfter.Value() > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE last_activity_at_ms < ?`,
				unixMillis(s.now().UTC().Add(-s.cfg.StaleAfter.Value())))
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

func (s *correspondentStore) Count(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM correspondents`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count correspondents: %w", err)
	}
	return count, nil
}

func normalizedAddressSet(values []string, maximum int) map[string]bool {
	result := make(map[string]bool)
	for _, value := range values {
		if len(result) >= maximum {
			break
		}
		if value = normalizeEmailAddress(value); value != "" {
			result[value] = true
		}
	}
	return result
}

func sortedSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func placeholders(count int) string { return strings.TrimSuffix(strings.Repeat("?,", count), ",") }
func valuePlaceholders(rows, columns int) string {
	return strings.TrimSuffix(strings.Repeat("("+placeholders(columns)+"),", rows), ",")
}
func unixMillis(value time.Time) int64     { return value.UTC().UnixMilli() }
func timeFromMillis(value int64) time.Time { return time.UnixMilli(value).UTC() }

func normalizeEmailAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 320 {
		return ""
	}
	address, ok := message.MailboxAddress(value)
	if !ok || strings.Count(address, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(address, "@", 2)
	local := strings.ToLower(strings.TrimSpace(parts[0]))
	domain := normalizeDomain(parts[1])
	if local == "" || len(local)+len(domain)+1 > 254 || safeDNSHostname(domain) == "" {
		return ""
	}
	return local + "@" + domain
}

func emailAddressDomain(address string) string {
	if separator := strings.LastIndexByte(address, '@'); separator >= 0 {
		return address[separator+1:]
	}
	return ""
}
