package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	repeatRefreshInterval = time.Minute
)

// rejectedIPRecord is the internal SQL representation used by transactional
// reputation operations and test diagnostics.
type rejectedIPRecord struct {
	ID              uint64
	IP              string
	Strikes         []time.Time
	BlockLevel      string
	BlockedUntil    time.Time
	LegitimateCount int
	LastActivityAt  time.Time
}

type ipReputationRepository struct {
	db                           *sqlitedb.Store
	shortDuration                time.Duration
	repeatThreshold              int
	repeatWindow, repeatDuration time.Duration
	repeatRefreshOnAttempt       bool
	legitimatePerStrike, maxSize int
	now                          func() time.Time
	log                          *slog.Logger
}

// NewIPReputation binds strike, block, listing, and maintenance operations to
// the shared SQLite database.
func NewIPReputation(db *sqlitedb.Store, options IPReputationOptions, log *slog.Logger) stores.PersistentIPReputationRepository {
	return &ipReputationRepository{db: db, shortDuration: options.BlockDuration, repeatThreshold: options.RepeatThreshold,
		repeatWindow: options.RepeatWindow, repeatDuration: options.RepeatBlockDuration,
		repeatRefreshOnAttempt: options.RepeatRefreshOnAttempt, legitimatePerStrike: options.LegitimatePerStrike,
		maxSize: options.MaxEntries, now: clock(options.Now), log: log}
}
func (r *ipReputationRepository) enabled() bool {
	return r != nil && r.db != nil && r.maxSize > 0 && (r.shortDuration > 0 || r.repeatThreshold > 0)
}

var _ stores.PersistentIPReputationRepository = (*ipReputationRepository)(nil)

func (r *ipReputationRepository) RecordRejection(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	if !r.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, nil
	}
	addr = netsafety.CanonicalIP(addr)
	now := r.now().UTC()
	record := rejectedIPRecord{IP: addr.String(), LastActivityAt: now}
	strikeCount := 0
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		// An expired repeat block starts fresh. Lookup no longer removes expired
		// state because the common MAIL FROM path must remain read-only.
		if _, err := tx.ExecContext(ctx, `DELETE FROM ip_reputation
			WHERE ip=? AND block_level='repeat' AND blocked_until_ms<=?`, addr.String(), unixMillis(now)); err != nil {
			return err
		}
		var id int64
		if err := tx.QueryRowContext(ctx, `INSERT INTO ip_reputation
			(ip, legitimate_count, last_activity_at_ms) VALUES (?, 0, ?)
			ON CONFLICT(ip) DO UPDATE SET legitimate_count=0,
				last_activity_at_ms=excluded.last_activity_at_ms
			RETURNING id`, addr.String(), unixMillis(now)).Scan(&id); err != nil {
			return err
		}
		if r.repeatThreshold > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ip_strikes (ip_reputation_id, struck_at_ms) VALUES (?, ?)`, id, unixMillis(now)); err != nil {
				return err
			}
			// Retain exactly the newest strikes within the rolling window. IDs
			// provide a deterministic tie-break when timestamps are identical.
			if _, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes
				WHERE ip_reputation_id=? AND id NOT IN (
					SELECT id FROM ip_strikes
					WHERE ip_reputation_id=? AND struck_at_ms>?
					ORDER BY struck_at_ms DESC,id DESC LIMIT ?
				)`, id, id, unixMillis(now.Add(-r.repeatWindow)), r.repeatThreshold); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=?`, id); err != nil {
			return err
		}
		var level sql.NullString
		var blockedUntil sql.NullInt64
		repeatEnabled, shortEnabled := r.repeatThreshold > 0, r.shortDuration > 0
		err := tx.QueryRowContext(ctx, `UPDATE ip_reputation SET
			block_level=CASE
				WHEN ? AND (SELECT count(*) FROM ip_strikes WHERE ip_reputation_id=?)>=? THEN 'repeat'
				WHEN ? THEN 'short' ELSE NULL END,
			blocked_until_ms=CASE
				WHEN ? AND (SELECT count(*) FROM ip_strikes WHERE ip_reputation_id=?)>=? THEN ?
				WHEN ? THEN ? ELSE NULL END,
			legitimate_count=0,last_activity_at_ms=?
			WHERE id=?
			RETURNING block_level,blocked_until_ms,
				(SELECT count(*) FROM ip_strikes WHERE ip_reputation_id=?)`,
			repeatEnabled, id, r.repeatThreshold, shortEnabled,
			repeatEnabled, id, r.repeatThreshold, unixMillis(now.Add(r.repeatDuration)),
			shortEnabled, unixMillis(now.Add(r.shortDuration)), unixMillis(now), id, id,
		).Scan(&level, &blockedUntil, &strikeCount)
		if err != nil {
			return err
		}
		record.ID, record.IP = uint64(id), addr.String()
		record.BlockLevel, record.LegitimateCount, record.LastActivityAt = level.String, 0, now
		if blockedUntil.Valid {
			record.BlockedUntil = timeFromMillis(blockedUntil.Int64)
		}
		return nil
	})
	if err != nil {
		return stores.IPBlock{}, fmt.Errorf("record sending IP rejection: %w", err)
	}
	block := stores.IPBlock{Address: addr, Level: stores.IPBlockLevel(record.BlockLevel), ExpiresAt: record.BlockedUntil, StrikeCount: strikeCount}
	return block, nil
}

func (r *ipReputationRepository) RecordLegitimate(ctx context.Context, addr netip.Addr) error {
	if !r.enabled() || r.legitimatePerStrike <= 0 || !addr.IsValid() {
		return nil
	}
	addr, now := netsafety.CanonicalIP(addr), r.now().UTC()
	hasStrike, err := r.hasCurrentStrike(ctx, addr.String(), now)
	if err != nil {
		return fmt.Errorf("check sending IP for legitimate evidence: %w", err)
	}
	if !hasStrike {
		return nil
	}
	type legitimateResult struct {
		record        rejectedIPRecord
		strikeCount   int
		removed       bool
		strikeRemoved bool
	}
	var outcome legitimateResult
	err = r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		attempt := legitimateResult{}
		defer func() { outcome = attempt }()
		var found bool
		var err error
		attempt.record, found, err = r.getTx(ctx, tx, addr.String())
		if err != nil || !found {
			return err
		}
		if err := r.pruneStrikesTx(ctx, tx, int64(attempt.record.ID), now); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ip_strikes WHERE ip_reputation_id=?`, attempt.record.ID).Scan(&attempt.strikeCount); err != nil {
			return err
		}
		active := attempt.record.BlockLevel != "" && attempt.record.BlockedUntil.After(now)
		if attempt.strikeCount == 0 {
			if !active {
				_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, attempt.record.ID)
				attempt.removed = err == nil
				return err
			}
			attempt.record.LegitimateCount = 0
			_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET legitimate_count=0 WHERE id=?`, attempt.record.ID)
			return err
		}
		attempt.record.LegitimateCount++
		attempt.record.LastActivityAt = now
		if attempt.record.LegitimateCount >= r.legitimatePerStrike {
			result, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE id=(SELECT id FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id LIMIT 1)`, attempt.record.ID)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			attempt.strikeRemoved = count > 0
			if attempt.strikeRemoved {
				attempt.strikeCount--
			}
			attempt.record.LegitimateCount = 0
		}
		if attempt.strikeCount == 0 && !active {
			_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, attempt.record.ID)
			attempt.removed = err == nil
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET legitimate_count=?,last_activity_at_ms=? WHERE id=?`, attempt.record.LegitimateCount, unixMillis(now), attempt.record.ID)
		return err
	})
	if err != nil {
		return fmt.Errorf("record legitimate sending IP evidence: %w", err)
	}
	if outcome.removed {
		r.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "no_strikes")
		return nil
	}
	r.debug("sending IP legitimate evidence recorded", "remote_ip", addr.String(), "legitimate_count", outcome.record.LegitimateCount, "strike_removed", outcome.strikeRemoved, "strike_count", outcome.strikeCount, "block_level", outcome.record.BlockLevel)
	return nil
}

func (r *ipReputationRepository) hasCurrentStrike(ctx context.Context, ip string, now time.Time) (bool, error) {
	if r.repeatThreshold <= 0 || r.repeatWindow <= 0 {
		return false, nil
	}
	var exists int
	err := r.db.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM ip_reputation r
		JOIN ip_strikes s ON s.ip_reputation_id=r.id
		WHERE r.ip=? AND s.struck_at_ms>?
	)`, ip, unixMillis(now.Add(-r.repeatWindow))).Scan(&exists)
	return exists != 0, err
}

// ActiveBlock returns the active block for addr. A repeat block may have its
// sliding expiry refreshed atomically as part of this lookup.
func (r *ipReputationRepository) ActiveBlock(ctx context.Context, addr netip.Addr) (stores.IPBlock, bool, error) {
	if !r.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, false, nil
	}
	addr = netsafety.CanonicalIP(addr)
	now := r.now().UTC()
	block, found, err := r.readActiveBlock(ctx, addr.String(), now)
	if err != nil {
		return stores.IPBlock{}, false, fmt.Errorf("look up active sending IP block: %w", err)
	}
	if !found || block.Level != stores.IPBlockLevelRepeat || !r.repeatRefreshOnAttempt {
		return block, found, nil
	}
	if now.Add(r.repeatDuration).Sub(block.ExpiresAt) < repeatRefreshInterval {
		return block, true, nil
	}
	refreshed, err := r.refreshRepeatBlock(ctx, addr.String(), now, &block)
	if err != nil {
		return block, true, fmt.Errorf("refresh repeat sending IP block: %w", err)
	}
	if refreshed {
		r.debug("sending IP repeat block expiry refreshed", "remote_ip", addr.String(), "block_level", block.Level, "strike_count", block.StrikeCount, "block_expires_at", block.ExpiresAt)
	}
	return block, true, nil
}

func (r *ipReputationRepository) readActiveBlock(ctx context.Context, ip string, now time.Time) (stores.IPBlock, bool, error) {
	var level string
	var blockedUntil int64
	var strikeCount int
	cutoff := unixMillis(now)
	if r.repeatThreshold > 0 && r.repeatWindow > 0 {
		cutoff = unixMillis(now.Add(-r.repeatWindow))
	}
	err := r.db.QueryRow(ctx, `SELECT r.block_level, r.blocked_until_ms,
		(SELECT count(*) FROM ip_strikes s WHERE s.ip_reputation_id=r.id AND s.struck_at_ms>?)
		FROM ip_reputation r
		WHERE r.ip=? AND r.block_level IS NOT NULL AND r.blocked_until_ms>?`,
		cutoff, ip, unixMillis(now)).Scan(&level, &blockedUntil, &strikeCount)
	if errors.Is(err, sql.ErrNoRows) {
		return stores.IPBlock{}, false, nil
	}
	if err != nil {
		return stores.IPBlock{}, false, err
	}
	expires := timeFromMillis(blockedUntil)
	addr, parseErr := netip.ParseAddr(ip)
	if parseErr != nil {
		return stores.IPBlock{}, false, fmt.Errorf("parse stored IP address: %w", parseErr)
	}
	return stores.IPBlock{Address: addr, ExpiresAt: expires, Level: stores.IPBlockLevel(level), StrikeCount: strikeCount}, true, nil
}

func (r *ipReputationRepository) refreshRepeatBlock(ctx context.Context, ip string, now time.Time, block *stores.IPBlock) (bool, error) {
	expires := now.Add(r.repeatDuration)
	result, err := r.db.Exec(ctx, `UPDATE ip_reputation
		SET blocked_until_ms=?, last_activity_at_ms=?
		WHERE ip=? AND block_level='repeat' AND blocked_until_ms>?
			AND blocked_until_ms<=?`,
		unixMillis(expires), unixMillis(now), ip, unixMillis(now), unixMillis(expires.Add(-repeatRefreshInterval)))
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	if err != nil || updated == 0 {
		return false, err
	}
	block.ExpiresAt = expires
	return true, nil
}

func (r *ipReputationRepository) getTx(ctx context.Context, tx *sql.Tx, ip string) (rejectedIPRecord, bool, error) {
	var record rejectedIPRecord
	var id, activity int64
	var level sql.NullString
	var blocked sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms FROM ip_reputation WHERE ip=?`, ip).Scan(&id, &record.IP, &level, &blocked, &record.LegitimateCount, &activity)
	if errors.Is(err, sql.ErrNoRows) {
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	record.ID, record.BlockLevel, record.LastActivityAt = uint64(id), level.String, timeFromMillis(activity)
	if blocked.Valid {
		record.BlockedUntil = timeFromMillis(blocked.Int64)
	}
	return record, true, nil
}

func (r *ipReputationRepository) pruneStrikesTx(ctx context.Context, tx *sql.Tx, id int64, now time.Time) error {
	if r.repeatThreshold == 0 || r.repeatWindow <= 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=?`, id)
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=? AND struck_at_ms<=?`, id, unixMillis(now.Add(-r.repeatWindow)))
	return err
}
func (r *ipReputationRepository) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*)-?,0) FROM ip_reputation`, r.maxSize).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	var totalRemoved int64
	for _, level := range []any{nil, stores.IPBlockLevelShort, stores.IPBlockLevelRepeat} {
		if excess == 0 {
			return totalRemoved, nil
		}
		query := `DELETE FROM ip_reputation WHERE id IN (SELECT id FROM ip_reputation WHERE block_level = ? ORDER BY last_activity_at_ms,id LIMIT ?)`
		if level == nil {
			query = `DELETE FROM ip_reputation WHERE id IN (SELECT id FROM ip_reputation WHERE block_level IS NULL ORDER BY last_activity_at_ms,id LIMIT ?)`
		}
		var result sql.Result
		var err error
		if level == nil {
			result, err = tx.ExecContext(ctx, query, excess)
		} else {
			result, err = tx.ExecContext(ctx, query, level, excess)
		}
		if err != nil {
			return 0, err
		}
		removed, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		totalRemoved += removed
		excess -= int(removed)
	}
	return totalRemoved, nil
}
func (r *ipReputationRepository) debug(msg string, attrs ...any) {
	if r.log != nil {
		r.log.Debug(msg, attrs...)
	}
}
func (r *ipReputationRepository) Count(ctx context.Context) (int, error) {
	if r == nil || r.db == nil {
		return 0, nil
	}
	var n int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM ip_reputation`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count sending IP records: %w", err)
	}
	return n, nil
}

func (r *ipReputationRepository) AddManualBlock(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	if !r.enabled() || !addr.IsValid() {
		return stores.IPBlock{}, fmt.Errorf("IP reputation blocking is disabled or the address is invalid")
	}
	addr = netsafety.CanonicalIP(addr)
	now := r.now().UTC()
	level, duration := stores.IPBlockLevelRepeat, r.repeatDuration
	if duration <= 0 {
		level, duration = stores.IPBlockLevelShort, r.shortDuration
	}
	if duration <= 0 {
		return stores.IPBlock{}, fmt.Errorf("no IP block duration is configured")
	}
	expires := now.Add(duration)
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO ip_reputation(ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms) VALUES(?,?,?,0,?) ON CONFLICT(ip) DO UPDATE SET block_level=excluded.block_level,blocked_until_ms=excluded.blocked_until_ms,legitimate_count=0,last_activity_at_ms=excluded.last_activity_at_ms`, addr.String(), level, unixMillis(expires), unixMillis(now)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return stores.IPBlock{}, fmt.Errorf("add manual sending IP block: %w", err)
	}
	r.debug("sending IP manually blocked", "remote_ip", addr.String(), "block_level", level, "block_expires_at", expires)
	return stores.IPBlock{Address: addr, Level: stores.IPBlockLevel(level), ExpiresAt: expires}, nil
}
func (r *ipReputationRepository) Delete(ctx context.Context, addr netip.Addr) (bool, error) {
	if r == nil || r.db == nil || !addr.IsValid() {
		return false, fmt.Errorf("invalid IP address")
	}
	addr = netsafety.CanonicalIP(addr)
	result, err := r.db.Exec(ctx, `DELETE FROM ip_reputation WHERE ip=?`, addr.String())
	if err != nil {
		return false, fmt.Errorf("delete sending IP block: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count deleted sending IP blocks: %w", err)
	}
	if n > 0 {
		r.debug("sending IP manually removed from rejection reputation", "remote_ip", addr.String())
	}
	return n > 0, nil
}
func (r *ipReputationRepository) ListActiveBlocks(ctx context.Context, list stores.IPBlockListQuery) (stores.IPBlockPage, error) {
	if !r.enabled() {
		return stores.IPBlockPage{}, nil
	}
	if list.Limit < 1 {
		return stores.IPBlockPage{}, fmt.Errorf("IP block list limit must be positive")
	}
	query := `SELECT ip,block_level,blocked_until_ms FROM ip_reputation WHERE block_level IS NOT NULL AND blocked_until_ms>?`
	args := []any{unixMillis(r.now().UTC())}
	if !list.ActiveSince.IsZero() {
		query += ` AND last_activity_at_ms>=?`
		args = append(args, unixMillis(list.ActiveSince))
	}
	query += ` ORDER BY ip LIMIT ?`
	args = append(args, list.Limit+1)
	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return stores.IPBlockPage{}, fmt.Errorf("list active sending IP blocks: %w", err)
	}
	defer rows.Close()
	var out []stores.IPBlock
	for rows.Next() {
		var ip, level string
		var ms int64
		if err := rows.Scan(&ip, &level, &ms); err != nil {
			return stores.IPBlockPage{}, fmt.Errorf("read active sending IP block: %w", err)
		}
		address, err := netip.ParseAddr(ip)
		if err != nil {
			return stores.IPBlockPage{}, fmt.Errorf("parse stored IP address: %w", err)
		}
		v := stores.IPBlock{Address: address, Level: stores.IPBlockLevel(level), ExpiresAt: timeFromMillis(ms)}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return stores.IPBlockPage{}, fmt.Errorf("read active sending IP blocks: %w", err)
	}
	truncated := len(out) > list.Limit
	if truncated {
		out = out[:list.Limit]
	}
	return stores.IPBlockPage{Entries: out, Truncated: truncated}, nil
}

// Cleanup removes inactive strike-less rows, prunes old strikes, clears expired
// blocks where appropriate, and enforces repository capacity.
func (r *ipReputationRepository) Cleanup(ctx context.Context) (int64, error) {
	if !r.enabled() {
		return 0, nil
	}
	now := r.now().UTC()
	var deleted int64
	err := r.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var attemptDeleted int64
		var result sql.Result
		var e error
		if r.repeatThreshold == 0 || r.repeatWindow <= 0 {
			result, e = tx.ExecContext(ctx, `DELETE FROM ip_strikes`)
		} else {
			result, e = tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE struck_at_ms<=?`, unixMillis(now.Add(-r.repeatWindow)))
		}
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return e
		}
		attemptDeleted += n
		result, e = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE block_level='repeat' AND blocked_until_ms<=?`, unixMillis(now))
		if e != nil {
			return e
		}
		n, e = result.RowsAffected()
		if e != nil {
			return e
		}
		attemptDeleted += n
		if _, e := tx.ExecContext(ctx, `UPDATE ip_reputation SET block_level=NULL,blocked_until_ms=NULL WHERE block_level='short' AND blocked_until_ms<=?`, unixMillis(now)); e != nil {
			return e
		}
		result, e = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE block_level IS NULL AND NOT EXISTS(SELECT 1 FROM ip_strikes WHERE ip_strikes.ip_reputation_id=ip_reputation.id)`)
		if e != nil {
			return e
		}
		n, e = result.RowsAffected()
		if e != nil {
			return e
		}
		attemptDeleted += n
		capacityDeleted, e := r.enforceCapacityTx(ctx, tx)
		if e != nil {
			return e
		}
		attemptDeleted += capacityDeleted
		deleted = attemptDeleted
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("clean sending IP reputation: %w", err)
	}
	return deleted, nil
}
