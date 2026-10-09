package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const maxSenderBlockAddresses = 100

type senderBlocklistRepository struct {
	db      *sqlitedb.Store
	options SenderBlocklistOptions
	now     func() time.Time
}

// NewSenderBlocklist binds manual sender-block administration, message
// matching, expiry, and capacity maintenance to the shared SQLite database.
func NewSenderBlocklist(db *sqlitedb.Store, options SenderBlocklistOptions) stores.SenderBlocklistRepository {
	return &senderBlocklistRepository{db: db, options: options, now: clock(options.Now)}
}

var _ stores.SenderBlocklistRepository = (*senderBlocklistRepository)(nil)

func (r *senderBlocklistRepository) available() bool {
	return r != nil && r.db != nil && r.options.Expiry > 0
}

func normalizeSenderBlock(entry stores.SenderBlockEntry) (stores.SenderBlockEntry, error) {
	if strings.TrimSpace(entry.Recipient) == "*" {
		entry.Recipient = "*"
	} else {
		entry.Recipient = mailaddr.Normalize(entry.Recipient)
		if entry.Recipient == "" {
			return stores.SenderBlockEntry{}, fmt.Errorf("sender block recipient must be a valid email address or *")
		}
	}
	switch entry.SenderKind {
	case stores.SenderBlockExactMailbox:
		entry.SenderValue = mailaddr.Normalize(entry.SenderValue)
		if entry.SenderValue == "" {
			return stores.SenderBlockEntry{}, fmt.Errorf("sender block must contain a valid email address")
		}
	case stores.SenderBlockDomain:
		entry.SenderValue = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry.SenderValue)), ".")
		if mailaddr.Domain("x@"+entry.SenderValue) != entry.SenderValue {
			return stores.SenderBlockEntry{}, fmt.Errorf("sender block must contain a valid domain")
		}
	default:
		return stores.SenderBlockEntry{}, fmt.Errorf("invalid sender block kind")
	}
	return entry, nil
}

func (r *senderBlocklistRepository) AddSenderBlock(ctx context.Context, entry stores.SenderBlockEntry) (bool, stores.SenderBlockEntry, error) {
	if !r.available() {
		return false, stores.SenderBlockEntry{}, fmt.Errorf("sender blocklist repository is unavailable")
	}
	entry, err := normalizeSenderBlock(entry)
	if err != nil {
		return false, stores.SenderBlockEntry{}, err
	}
	entry.ExpiresAt = r.now().UTC().Add(r.options.Expiry)
	created := false
	var id int64
	err = r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT id FROM sender_blocklist
			WHERE recipient=? AND sender_kind=? AND sender_value=?`, entry.Recipient, entry.SenderKind, entry.SenderValue).Scan(&id)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		created = err == sql.ErrNoRows
		_, err = tx.ExecContext(ctx, `INSERT INTO sender_blocklist
			(recipient, sender_kind, sender_value, expires_at_ms) VALUES (?, ?, ?, ?)
			ON CONFLICT(recipient, sender_kind, sender_value) DO UPDATE SET
			expires_at_ms=excluded.expires_at_ms`, entry.Recipient, entry.SenderKind, entry.SenderValue, unixMillis(entry.ExpiresAt))
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, `SELECT id FROM sender_blocklist
			WHERE recipient=? AND sender_kind=? AND sender_value=?`, entry.Recipient, entry.SenderKind, entry.SenderValue).Scan(&id)
	})
	if err != nil {
		return false, stores.SenderBlockEntry{}, fmt.Errorf("add sender block: %w", err)
	}
	entry.ID = uint64(id)
	return created, entry, nil
}

func (r *senderBlocklistRepository) DeleteSenderBlocks(ctx context.Context, query stores.SenderBlockDeleteQuery) (int, error) {
	if !r.available() {
		return 0, fmt.Errorf("sender blocklist repository is unavailable")
	}
	if err := query.Recipients.Validate(); err != nil {
		return 0, fmt.Errorf("invalid sender block deletion: %w", err)
	}
	entry, err := normalizeSenderBlock(stores.SenderBlockEntry{
		Recipient: "*", SenderKind: query.SenderKind, SenderValue: query.SenderValue,
	})
	if err != nil {
		return 0, err
	}
	sqlText := `DELETE FROM sender_blocklist WHERE sender_kind=? AND sender_value=?`
	args := []any{entry.SenderKind, entry.SenderValue}
	if !query.Recipients.All {
		recipient := query.Recipients.Address
		if strings.TrimSpace(recipient) != "*" {
			recipient = mailaddr.Normalize(recipient)
			if recipient == "" {
				return 0, fmt.Errorf("sender block recipient must be a valid email address or *")
			}
		}
		sqlText += ` AND recipient=?`
		args = append(args, recipient)
	}
	result, err := r.db.Exec(ctx, sqlText, args...)
	if err != nil {
		return 0, fmt.Errorf("delete sender blocks: %w", err)
	}
	removed, err := result.RowsAffected()
	return int(removed), err
}

func (r *senderBlocklistRepository) ListSenderBlocks(ctx context.Context, query stores.SenderBlockListQuery) (stores.SenderBlockPage, error) {
	if !r.available() {
		return stores.SenderBlockPage{}, nil
	}
	if err := query.Recipients.Validate(); err != nil {
		return stores.SenderBlockPage{}, fmt.Errorf("invalid sender blocklist query: %w", err)
	}
	if query.Limit < 1 {
		return stores.SenderBlockPage{}, fmt.Errorf("sender blocklist limit must be positive")
	}
	sqlText := `SELECT id, recipient, sender_kind, sender_value, expires_at_ms
		FROM sender_blocklist WHERE expires_at_ms>?`
	args := []any{unixMillis(r.now().UTC())}
	if !query.Recipients.All {
		recipient := mailaddr.Normalize(query.Recipients.Address)
		if recipient == "" {
			return stores.SenderBlockPage{}, nil
		}
		sqlText += ` AND recipient=?`
		args = append(args, recipient)
	}
	sqlText += ` ORDER BY expires_at_ms DESC, id DESC LIMIT ?`
	args = append(args, query.Limit+1)
	rows, err := r.db.Query(ctx, sqlText, args...)
	if err != nil {
		return stores.SenderBlockPage{}, fmt.Errorf("list sender blocks: %w", err)
	}
	defer rows.Close()
	entries := make([]stores.SenderBlockEntry, 0)
	for rows.Next() {
		var entry stores.SenderBlockEntry
		var expires int64
		if err := rows.Scan(&entry.ID, &entry.Recipient, &entry.SenderKind, &entry.SenderValue, &expires); err != nil {
			return stores.SenderBlockPage{}, fmt.Errorf("read sender blocks: %w", err)
		}
		entry.ExpiresAt = timeFromMillis(expires)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return stores.SenderBlockPage{}, fmt.Errorf("read sender blocks: %w", err)
	}
	entries, truncated := limitedPage(entries, query.Limit)
	return stores.SenderBlockPage{Entries: entries, Truncated: truncated}, nil
}

func senderDomainCandidates(senders map[string]bool, includeSubdomains bool) map[string]bool {
	domains := make(map[string]bool)
	for sender := range senders {
		domain := mailaddr.Domain(sender)
		if domain == "" {
			continue
		}
		domains[domain] = true
		if !includeSubdomains {
			continue
		}
		for index := strings.IndexByte(domain, '.'); index >= 0; index = strings.IndexByte(domain, '.') {
			domain = domain[index+1:]
			if domain != "" {
				domains[domain] = true
			}
		}
	}
	return domains
}

func (r *senderBlocklistRepository) MatchSenderBlocks(ctx context.Context, query stores.SenderBlockMatchQuery) (stores.SenderBlockMatch, error) {
	if !r.available() {
		return stores.SenderBlockMatch{}, nil
	}
	senders := normalizedAddressSet(query.VisibleSenders, maxSenderBlockAddresses)
	recipients := normalizedAddressSet(query.Recipients, maxSenderBlockAddresses)
	if len(senders) == 0 || len(recipients) == 0 {
		return stores.SenderBlockMatch{}, nil
	}
	exactValues := sortedSet(senders)
	domainValues := sortedSet(senderDomainCandidates(senders, query.IncludeSubdomains))
	recipientValues := sortedSet(recipients)
	recipientScopes := append([]string{"*"}, recipientValues...)
	sqlText := `SELECT recipient, sender_kind, sender_value FROM sender_blocklist
		WHERE expires_at_ms>? AND recipient IN (` + placeholders(len(recipientScopes)) + `) AND (`
	args := []any{unixMillis(r.now().UTC())}
	for _, value := range recipientScopes {
		args = append(args, value)
	}
	parts := make([]string, 0, 2)
	if len(exactValues) > 0 {
		parts = append(parts, `(sender_kind=? AND sender_value IN (`+placeholders(len(exactValues))+`))`)
		args = append(args, stores.SenderBlockExactMailbox)
		for _, value := range exactValues {
			args = append(args, value)
		}
	}
	if len(domainValues) > 0 {
		parts = append(parts, `(sender_kind=? AND sender_value IN (`+placeholders(len(domainValues))+`))`)
		args = append(args, stores.SenderBlockDomain)
		for _, value := range domainValues {
			args = append(args, value)
		}
	}
	sqlText += strings.Join(parts, ` OR `) + `) ORDER BY sender_kind ASC, id ASC`
	rows, err := r.db.Query(ctx, sqlText, args...)
	if err != nil {
		return stores.SenderBlockMatch{}, fmt.Errorf("match sender blocks: %w", err)
	}
	defer rows.Close()
	blocked := make(map[string]bool)
	match := stores.SenderBlockMatch{}
	for rows.Next() {
		var recipient, senderValue string
		var kind stores.SenderBlockKind
		if err := rows.Scan(&recipient, &kind, &senderValue); err != nil {
			return stores.SenderBlockMatch{}, fmt.Errorf("read sender block matches: %w", err)
		}
		if match.MatchedSender == "" || (match.MatchedKind != stores.SenderBlockExactMailbox && kind == stores.SenderBlockExactMailbox) {
			match.MatchedKind = kind
			match.MatchedSender = matchedVisibleSender(kind, senderValue, exactValues, query.IncludeSubdomains)
		}
		if recipient == "*" {
			for value := range recipients {
				blocked[value] = true
			}
		} else if recipients[recipient] {
			blocked[recipient] = true
		}
	}
	if err := rows.Err(); err != nil {
		return stores.SenderBlockMatch{}, fmt.Errorf("read sender block matches: %w", err)
	}
	match.BlockedRecipients = sortedSet(blocked)
	return match, nil
}

func matchedVisibleSender(kind stores.SenderBlockKind, value string, visibleSenders []string, includeSubdomains bool) string {
	if kind == stores.SenderBlockExactMailbox {
		return value
	}
	for _, sender := range visibleSenders {
		domain := mailaddr.Domain(sender)
		if domain == value || (includeSubdomains && strings.HasSuffix(domain, "."+value)) {
			return sender
		}
	}
	return ""
}

func (r *senderBlocklistRepository) Cleanup(ctx context.Context) (int64, error) {
	if !r.available() {
		return 0, nil
	}
	var deleted int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `DELETE FROM sender_blocklist WHERE expires_at_ms<=?`, unixMillis(r.now().UTC()))
		if err != nil {
			return err
		}
		deleted, err = result.RowsAffected()
		if err != nil {
			return err
		}
		excess, err := capacityExcessTx(ctx, tx, "sender_blocklist", r.options.MaxEntries)
		if err != nil || excess == 0 {
			return err
		}
		result, err = tx.ExecContext(ctx, `DELETE FROM sender_blocklist WHERE id IN (
			SELECT id FROM sender_blocklist ORDER BY expires_at_ms, id LIMIT ?
		)`, excess)
		if err != nil {
			return err
		}
		trimmed, err := result.RowsAffected()
		deleted += trimmed
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("clean sender blocklist: %w", err)
	}
	return deleted, nil
}

func (r *senderBlocklistRepository) Count(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var count int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM sender_blocklist`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sender blocklist: %w", err)
	}
	return count, nil
}
