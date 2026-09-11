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
)

const (
	maxLearnedRecipients           = 100
	whitelistAuthenticatedOutbound = "authenticated_outbound"
	whitelistRepeatedLegitimate    = "repeated_legitimate_inbound"
	whitelistManual                = "manual"
)

type correspondentEntry struct {
	ID                   uint64
	LocalAddress         string
	Correspondent        string
	LearnedAt            time.Time
	LastActivityAt       time.Time
	WhitelistType        string
	LegitimateEmailCount int
}

type correspondentMatch struct {
	Known                bool
	AllRecipientsMatched bool
	MatchedRecipients    int
	TotalRecipients      int
}

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

func (s *correspondentStore) learn(localAddress string, recipients []string) error {
	if s == nil || s.db == nil || !s.cfg.LearnAuthenticatedRecipients {
		return nil
	}
	localAddress = normalizeEmailAddress(localAddress)
	if localAddress == "" {
		return fmt.Errorf("authenticated envelope sender is unavailable or invalid")
	}
	unique := normalizedAddressSet(recipients, maxLearnedRecipients)
	if len(unique) == 0 {
		return nil
	}

	ctx := context.Background()
	now := s.now().UTC()
	added := 0
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		added = 0
		for _, recipient := range sortedSet(unique) {
			entry, found, err := s.getTx(ctx, tx, localAddress, recipient)
			if err != nil {
				return err
			}
			if found && s.entryStale(entry, now) {
				if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id = ?`, entry.ID); err != nil {
					return err
				}
				found = false
			}
			if !found {
				if _, err := tx.ExecContext(ctx, `INSERT INTO correspondents
					(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
					VALUES (?, ?, ?, ?, ?, 0)`, localAddress, recipient, unixMillis(now), unixMillis(now), whitelistAuthenticatedOutbound); err != nil {
					return err
				}
				added++
				continue
			}
			if entry.WhitelistType != whitelistManual {
				if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET whitelist_type = ?, legitimate_email_count = 0,
					last_activity_at_ms = ? WHERE id = ?`, whitelistAuthenticatedOutbound, unixMillis(now), entry.ID); err != nil {
					return err
				}
			} else if s.activityPersistenceDue(entry, now) {
				if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms = ? WHERE id = ?`, unixMillis(now), entry.ID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if s.log != nil {
		s.log.Debug("correspondent allowlist updated", "new_entries", added)
	}
	return nil
}

func (s *correspondentStore) touchInbound(correspondent string, recipients []string) error {
	if s == nil || s.db == nil || !s.cfg.UseAllowlist {
		return nil
	}
	correspondent = normalizeEmailAddress(correspondent)
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
		addresses := sortedSet(normalizedAddressSet(recipients, maxLearnedRecipients))
		if len(addresses) == 0 {
			return nil
		}
		query += " AND local_address IN (" + placeholders(len(addresses)) + ")"
		for _, address := range addresses {
			args = append(args, address)
		}
	}
	_, err := s.db.Exec(context.Background(), query, args...)
	return err
}

func (s *correspondentStore) recordInboundClassification(correspondent string, recipients []string, recipientsComplete bool, classification string, score, unwantedMinScore float64, dkimAligned bool) error {
	if s == nil || s.db == nil || !recipientsComplete {
		return nil
	}
	correspondent = normalizeEmailAddress(correspondent)
	recipientSet := normalizedAddressSet(recipients, maxLearnedRecipients)
	if correspondent == "" || len(recipientSet) == 0 {
		return nil
	}
	recipientList := sortedSet(recipientSet)
	now := s.now().UTC()
	if classification == "unwanted" {
		if score < unwantedMinScore {
			return nil
		}
		query := `DELETE FROM correspondents WHERE correspondent = ? AND whitelist_type = ?`
		args := []any{correspondent, whitelistRepeatedLegitimate}
		if s.cfg.Scope == "per_sender" {
			query += " AND local_address IN (" + placeholders(len(recipientList)) + ")"
			for _, recipient := range recipientList {
				args = append(args, recipient)
			}
		}
		result, err := s.db.Exec(context.Background(), query, args...)
		if err != nil {
			return err
		}
		removed, _ := result.RowsAffected()
		if removed > 0 && s.log != nil {
			s.log.Debug("inbound-learned correspondent removed after unwanted classification", "correspondent", correspondent, "removed_entries", removed)
		}
		return nil
	}
	if classification != "legitimate" {
		return nil
	}

	qualifying := s.cfg.LearnLegitimateSenders && score >= s.cfg.LegitimateSenderMinScore && (!s.cfg.LegitimateSenderRequireDKIM || dkimAligned)
	type candidateEvent struct {
		recipient string
		count     int
		promoted  bool
	}
	var events []candidateEvent
	ctx := context.Background()
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		events = nil
		for _, recipient := range recipientList {
			entry, found, err := s.getTx(ctx, tx, recipient, correspondent)
			if err != nil {
				return err
			}
			if found && s.entryStale(entry, now) {
				if _, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE id = ?`, entry.ID); err != nil {
					return err
				}
				found = false
			}
			if !found {
				if !qualifying {
					continue
				}
				if _, err := tx.ExecContext(ctx, `INSERT INTO correspondents
					(local_address, correspondent, learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count)
					VALUES (?, ?, ?, ?, ?, 1)`, recipient, correspondent, unixMillis(now), unixMillis(now), whitelistRepeatedLegitimate); err != nil {
					return err
				}
				events = append(events, candidateEvent{recipient: recipient, count: 1, promoted: s.cfg.LegitimateSenderMinMessages <= 1})
				continue
			}
			if entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual || s.qualified(entry) {
				if s.activityPersistenceDue(entry, now) {
					if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET last_activity_at_ms = ? WHERE id = ?`, unixMillis(now), entry.ID); err != nil {
						return err
					}
				}
				continue
			}
			if entry.WhitelistType == whitelistRepeatedLegitimate && qualifying {
				entry.LegitimateEmailCount++
				if _, err := tx.ExecContext(ctx, `UPDATE correspondents SET legitimate_email_count = ?, last_activity_at_ms = ? WHERE id = ?`, entry.LegitimateEmailCount, unixMillis(now), entry.ID); err != nil {
					return err
				}
				events = append(events, candidateEvent{recipient: recipient, count: entry.LegitimateEmailCount, promoted: s.qualified(entry)})
			}
		}
		return nil
	})
	if err != nil || s.log == nil {
		return err
	}
	for _, event := range events {
		if event.promoted {
			s.log.Debug("inbound sender promoted to known correspondent", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count)
		} else {
			s.log.Debug("inbound sender legitimate candidate updated", "local_address", event.recipient, "correspondent", correspondent, "legitimate_email_count", event.count, "required_count", s.cfg.LegitimateSenderMinMessages)
		}
	}
	return nil
}

func (s *correspondentStore) match(correspondent string, recipients []string) correspondentMatch {
	result := correspondentMatch{}
	if s == nil || s.db == nil || !s.cfg.UseAllowlist {
		return result
	}
	correspondent = normalizeEmailAddress(correspondent)
	if correspondent == "" {
		return result
	}
	now := s.now().UTC()
	if s.cfg.Scope == "global" {
		var found int
		query := `SELECT EXISTS(SELECT 1 FROM correspondents WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() + `)`
		args := []any{correspondent, s.cfg.LegitimateSenderMinMessages}
		args = append(args, s.notStaleArgs(now)...)
		if err := s.db.QueryRow(context.Background(), query, args...).Scan(&found); err != nil {
			s.logDatabaseError("match correspondent", err)
			return result
		}
		result.Known, result.AllRecipientsMatched, result.TotalRecipients = found != 0, found != 0, 1
		if result.Known {
			result.MatchedRecipients = 1
		}
		return result
	}
	addresses := sortedSet(normalizedAddressSet(recipients, maxLearnedRecipients))
	result.TotalRecipients = len(addresses)
	if len(addresses) == 0 {
		return result
	}
	query := `SELECT count(*) FROM correspondents WHERE correspondent = ? AND ` + s.qualifiedSQL() + s.notStaleSQL() +
		" AND local_address IN (" + placeholders(len(addresses)) + ")"
	args := []any{correspondent, s.cfg.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	for _, address := range addresses {
		args = append(args, address)
	}
	if err := s.db.QueryRow(context.Background(), query, args...).Scan(&result.MatchedRecipients); err != nil {
		s.logDatabaseError("match correspondent recipients", err)
		return correspondentMatch{TotalRecipients: len(addresses)}
	}
	result.Known = result.MatchedRecipients > 0
	result.AllRecipientsMatched = result.MatchedRecipients == result.TotalRecipients
	return result
}

func (s *correspondentStore) listAllowlist(recipient string) []correspondentEntry {
	if s == nil || s.db == nil {
		return nil
	}
	allRecipients := recipient == "*"
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return nil
		}
	}
	now := s.now().UTC()
	query := `SELECT id, local_address, correspondent, learned_at_ms, last_activity_at_ms,
		whitelist_type, legitimate_email_count FROM correspondents WHERE ` + s.qualifiedSQL() + s.notStaleSQL()
	args := []any{s.cfg.LegitimateSenderMinMessages}
	args = append(args, s.notStaleArgs(now)...)
	if !allRecipients {
		query += " AND local_address = ?"
		args = append(args, recipient)
	}
	query += " ORDER BY last_activity_at_ms DESC, local_address, correspondent"
	rows, err := s.db.Query(context.Background(), query, args...)
	if err != nil {
		s.logDatabaseError("list correspondent allowlist", err)
		return nil
	}
	defer rows.Close()
	var result []correspondentEntry
	for rows.Next() {
		entry, err := scanCorrespondent(rows)
		if err != nil {
			s.logDatabaseError("read correspondent allowlist", err)
			return nil
		}
		result = append(result, entry)
	}
	if err := rows.Err(); err != nil {
		s.logDatabaseError("read correspondent allowlist", err)
		return nil
	}
	return result
}

func (s *correspondentStore) qualified(entry correspondentEntry) bool {
	return entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual ||
		(entry.WhitelistType == whitelistRepeatedLegitimate && entry.LegitimateEmailCount >= s.cfg.LegitimateSenderMinMessages)
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

func (s *correspondentStore) activityPersistenceDue(entry correspondentEntry, now time.Time) bool {
	interval := s.cfg.ActivityUpdateInterval.Value()
	return interval <= 0 || !now.Before(entry.LastActivityAt.Add(interval))
}

func (s *correspondentStore) entryStale(entry correspondentEntry, now time.Time) bool {
	return s.cfg.StaleAfter.Value() > 0 && entry.LastActivityAt.Before(now.Add(-s.cfg.StaleAfter.Value()))
}

func (s *correspondentStore) getTx(ctx context.Context, tx *sql.Tx, localAddress, correspondent string) (correspondentEntry, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT id, local_address, correspondent, learned_at_ms,
		last_activity_at_ms, whitelist_type, legitimate_email_count FROM correspondents
		WHERE local_address = ? AND correspondent = ?`, localAddress, correspondent)
	entry, err := scanCorrespondent(row)
	if err == sql.ErrNoRows {
		return correspondentEntry{}, false, nil
	}
	return entry, err == nil, err
}

type rowScanner interface{ Scan(...any) error }

func scanCorrespondent(row rowScanner) (correspondentEntry, error) {
	var entry correspondentEntry
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

func (s *correspondentStore) cleanup() (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	ctx := context.Background()
	var deleted int64
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if s.cfg.StaleAfter.Value() > 0 {
			result, err := tx.ExecContext(ctx, `DELETE FROM correspondents WHERE last_activity_at_ms < ?`,
				unixMillis(s.now().UTC().Add(-s.cfg.StaleAfter.Value())))
			if err != nil {
				return err
			}
			deleted, _ = result.RowsAffected()
		}
		removed, err := s.enforceCapacityTx(ctx, tx)
		if err != nil {
			return err
		}
		deleted += removed
		return nil
	})
	return deleted, err
}

func (s *correspondentStore) size() int {
	if s == nil || s.db == nil {
		return 0
	}
	var count int
	if err := s.db.QueryRow(context.Background(), `SELECT count(*) FROM correspondents`).Scan(&count); err != nil {
		s.logDatabaseError("count correspondents", err)
	}
	return count
}

func (s *correspondentStore) logDatabaseError(operation string, err error) {
	if s != nil && s.log != nil && err != nil {
		s.log.Error("correspondent database operation failed", "operation", operation, "error", err)
	}
}

// snapshot is a diagnostic/test helper, not a storage API used by production.
func (s *correspondentStore) snapshot() map[string]correspondentEntry {
	result := make(map[string]correspondentEntry)
	if s == nil || s.db == nil {
		return result
	}
	rows, err := s.db.Query(context.Background(), `SELECT id, local_address, correspondent,
		learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count FROM correspondents`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		entry, err := scanCorrespondent(rows)
		if err != nil {
			return result
		}
		result[entry.LocalAddress+"\x00"+entry.Correspondent] = entry
	}
	if rows.Err() != nil {
		return map[string]correspondentEntry{}
	}
	return result
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

func placeholders(count int) string        { return strings.TrimSuffix(strings.Repeat("?,", count), ",") }
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
