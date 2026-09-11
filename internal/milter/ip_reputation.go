package milter

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

const (
	rejectedIPBlockShort  = "short"
	rejectedIPBlockRepeat = "repeat"
	repeatRefreshInterval = time.Minute
)

type ipBlock struct {
	expires     time.Time
	level       string
	strikeCount int
}
type activeIPBlock struct {
	IP, Hostname, Level string
	ExpiresAt           time.Time
}

// rejectedIPRecord is retained only as a diagnostic representation for tests.
// Production operations use indexed SQL directly.
type rejectedIPRecord struct {
	ID              uint64
	IP              string
	Strikes         []time.Time
	BlockLevel      string
	BlockedUntil    time.Time
	LegitimateCount int
	LastActivityAt  time.Time
}

func canonicalIP(addr netip.Addr) netip.Addr {
	if addr.Is6() {
		addr = addr.WithZone("")
	}
	return addr.Unmap()
}

func canonicalIPPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	addr, bits := prefix.Addr(), prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		addr, bits = addr.Unmap(), bits-96
	} else if addr.Is6() {
		addr = addr.WithZone("")
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

func (s *Server) resolveActiveIPHostnames(parent context.Context, entries []activeIPBlock) []activeIPBlock {
	if len(entries) == 0 || s.resolver == nil || s.cfg.Milter.ConnectionDNSTimeout.Value() <= 0 {
		return entries
	}
	indices := make(chan int)
	var wg sync.WaitGroup
	for range min(8, len(entries)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range indices {
				addr, err := netip.ParseAddr(entries[index].IP)
				if err != nil || !connectionAddressRoutable(addr) {
					continue
				}
				ctx, cancel := context.WithTimeout(parent, s.cfg.Milter.ConnectionDNSTimeout.Value())
				names, err := s.reverseLookupSafely(ctx, addr)
				cancel()
				if err != nil {
					continue
				}
				for _, candidate := range names {
					if hostname := safeDNSHostname(candidate); hostname != "" {
						entries[index].Hostname = hostname
						break
					}
				}
			}
		}()
	}
	for index := range entries {
		select {
		case indices <- index:
		case <-parent.Done():
			close(indices)
			wg.Wait()
			return entries
		}
	}
	close(indices)
	wg.Wait()
	return entries
}

func (s *Server) reverseLookupSafely(ctx context.Context, addr netip.Addr) (names []string, err error) {
	defer func() {
		if panicValue := recover(); panicValue != nil {
			s.logRecoveredWorkerPanic(ctx, "IP command reverse-DNS lookup", panicValue, "remote_ip", addr.String())
			err = fmt.Errorf("reverse-DNS lookup panicked")
		}
	}()
	return s.resolver.LookupAddr(ctx, addr.String())
}

// ipReputationStore is a purpose-built SQL repository. Policy changes and
// their associated strike changes are committed in one transaction.
type ipReputationStore struct {
	db                           *sqlstore.Store
	shortDuration                time.Duration
	repeatThreshold              int
	repeatWindow, repeatDuration time.Duration
	repeatRefreshOnAttempt       bool
	legitimatePerStrike, maxSize int
	allowlist                    []netip.Prefix
	domainAllowlist              []string
	now                          func() time.Time
	log                          *slog.Logger
}

func newIPReputationStore(cfg config.IPReputationConfig, db *sqlstore.Store, log *slog.Logger) *ipReputationStore {
	s := &ipReputationStore{db: db, shortDuration: cfg.BlockDuration.Value(), repeatThreshold: cfg.RepeatThreshold,
		repeatWindow: cfg.RepeatWindow.Value(), repeatDuration: cfg.RepeatBlockDuration.Value(),
		repeatRefreshOnAttempt: cfg.RepeatRefreshOnAttempt, legitimatePerStrike: cfg.LegitimatePerStrike,
		maxSize: cfg.MaxEntries, now: time.Now, log: log}
	for _, entry := range cfg.IPAllowlist {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			if prefix, ok := canonicalIPPrefix(prefix); ok {
				s.allowlist = append(s.allowlist, prefix)
			}
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			bits := 128
			if addr.Is4() || addr.Is4In6() {
				bits = 32
			}
			s.allowlist = append(s.allowlist, netip.PrefixFrom(canonicalIP(addr), bits))
		}
	}
	for _, domain := range cfg.DomainAllowlist {
		s.domainAllowlist = append(s.domainAllowlist, normalizeDomain(domain))
	}
	return s
}

func ipReputationFeaturesEnabled(cfg config.IPReputationConfig) bool {
	return cfg.MaxEntries > 0 && (cfg.BlockDuration.Value() > 0 || cfg.RepeatThreshold > 0)
}
func (s *ipReputationStore) enabled() bool {
	return s != nil && s.db != nil && s.maxSize > 0 && (s.shortDuration > 0 || s.repeatThreshold > 0)
}

func (s *ipReputationStore) allowed(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, true
	}
	addr = canonicalIP(addr)
	for _, prefix := range s.allowlist {
		if prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (s *ipReputationStore) add(ctx context.Context, addr netip.Addr, score float64, dns connectionDNSResult) bool {
	if !s.enabled() || !addr.IsValid() {
		return false
	}
	addr = canonicalIP(addr)
	if prefix, ok := s.allowed(addr); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "matched_prefix", prefix.String(), "reason", "ip_allowlist")
		return false
	}
	if hostname, domain, ok := s.domainAllowed(dns); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain, "reason", "domain_allowlist")
		return false
	}
	now := s.now().UTC()
	record := rejectedIPRecord{IP: addr.String(), LastActivityAt: now}
	strikeCount := 0
	err := s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
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
		if s.repeatThreshold > 0 {
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
				)`, id, id, unixMillis(now.Add(-s.repeatWindow)), s.repeatThreshold); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=?`, id); err != nil {
			return err
		}
		var level sql.NullString
		var blockedUntil sql.NullInt64
		repeatEnabled, shortEnabled := s.repeatThreshold > 0, s.shortDuration > 0
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
			repeatEnabled, id, s.repeatThreshold, shortEnabled,
			repeatEnabled, id, s.repeatThreshold, unixMillis(now.Add(s.repeatDuration)),
			shortEnabled, unixMillis(now.Add(s.shortDuration)), unixMillis(now), id, id,
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
		s.logDatabaseError("add sending IP strike", err)
		return false
	}
	s.debug("sending IP reputation updated", "remote_ip", addr.String(), "score", score, "block_level", record.BlockLevel, "strike_count", strikeCount, "block_expires_at", record.BlockedUntil)
	return record.BlockLevel != ""
}

func (s *ipReputationStore) recordLegitimate(ctx context.Context, addr netip.Addr) {
	if !s.enabled() || s.legitimatePerStrike <= 0 || !addr.IsValid() {
		return
	}
	addr, now := canonicalIP(addr), s.now().UTC()
	hasStrike, err := s.hasCurrentStrike(ctx, addr.String(), now)
	if err != nil {
		s.logDatabaseError("check sending IP for legitimate evidence", err)
		return
	}
	if !hasStrike {
		return
	}
	var record rejectedIPRecord
	strikeCount := 0
	removed, strikeRemoved := false, false
	err = s.db.WithTx(ctx, nil, func(tx *sql.Tx) error {
		var found bool
		var err error
		record, found, err = s.getTx(ctx, tx, addr.String())
		if err != nil || !found {
			return err
		}
		if err := s.pruneStrikesTx(ctx, tx, int64(record.ID), now); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM ip_strikes WHERE ip_reputation_id=?`, record.ID).Scan(&strikeCount); err != nil {
			return err
		}
		active := record.BlockLevel != "" && record.BlockedUntil.After(now)
		if strikeCount == 0 {
			if !active {
				_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, record.ID)
				removed = err == nil
				return err
			}
			record.LegitimateCount = 0
			_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET legitimate_count=0 WHERE id=?`, record.ID)
			return err
		}
		record.LegitimateCount++
		record.LastActivityAt = now
		if record.LegitimateCount >= s.legitimatePerStrike {
			result, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE id=(SELECT id FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id LIMIT 1)`, record.ID)
			if err != nil {
				return err
			}
			count, err := result.RowsAffected()
			if err != nil {
				return err
			}
			strikeRemoved = count > 0
			if strikeRemoved {
				strikeCount--
			}
			record.LegitimateCount = 0
		}
		if strikeCount == 0 && !active {
			_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, record.ID)
			removed = err == nil
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET legitimate_count=?,last_activity_at_ms=? WHERE id=?`, record.LegitimateCount, unixMillis(now), record.ID)
		return err
	})
	if err != nil {
		s.logDatabaseError("record legitimate sending IP evidence", err)
		return
	}
	if removed {
		s.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "no_strikes")
		return
	}
	s.debug("sending IP legitimate evidence recorded", "remote_ip", addr.String(), "legitimate_count", record.LegitimateCount, "strike_removed", strikeRemoved, "strike_count", strikeCount, "block_level", record.BlockLevel)
}

func (s *ipReputationStore) hasCurrentStrike(ctx context.Context, ip string, now time.Time) (bool, error) {
	if s.repeatThreshold <= 0 || s.repeatWindow <= 0 {
		return false, nil
	}
	var exists int
	err := s.db.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM ip_reputation r
		JOIN ip_strikes s ON s.ip_reputation_id=r.id
		WHERE r.ip=? AND s.struck_at_ms>?
	)`, ip, unixMillis(now.Add(-s.repeatWindow))).Scan(&exists)
	return exists != 0, err
}

func (s *ipReputationStore) lookup(ctx context.Context, addr netip.Addr) (ipBlock, bool) {
	if !s.enabled() || !addr.IsValid() {
		return ipBlock{}, false
	}
	addr = canonicalIP(addr)
	if _, ok := s.allowed(addr); ok {
		return ipBlock{}, false
	}
	now := s.now().UTC()
	block, found, err := s.readActiveBlock(ctx, addr.String(), now)
	if err != nil {
		s.logDatabaseError("look up sending IP reputation", err)
		return ipBlock{}, false
	}
	if !found || block.level != rejectedIPBlockRepeat || !s.repeatRefreshOnAttempt {
		return block, found
	}
	if now.Add(s.repeatDuration).Sub(block.expires) < repeatRefreshInterval {
		return block, true
	}
	refreshed, err := s.refreshRepeatBlock(ctx, addr.String(), now, &block)
	if err != nil {
		s.logDatabaseError("refresh repeat sending IP block", err)
		return block, true
	}
	if refreshed {
		s.debug("sending IP repeat block expiry refreshed", "remote_ip", addr.String(), "block_level", block.level, "strike_count", block.strikeCount, "block_expires_at", block.expires)
	}
	return block, true
}

func (s *ipReputationStore) readActiveBlock(ctx context.Context, ip string, now time.Time) (ipBlock, bool, error) {
	var level string
	var blockedUntil int64
	var strikeCount int
	cutoff := unixMillis(now)
	if s.repeatThreshold > 0 && s.repeatWindow > 0 {
		cutoff = unixMillis(now.Add(-s.repeatWindow))
	}
	err := s.db.QueryRow(ctx, `SELECT r.block_level, r.blocked_until_ms,
		(SELECT count(*) FROM ip_strikes s WHERE s.ip_reputation_id=r.id AND s.struck_at_ms>?)
		FROM ip_reputation r
		WHERE r.ip=? AND r.block_level IS NOT NULL AND r.blocked_until_ms>?`,
		cutoff, ip, unixMillis(now)).Scan(&level, &blockedUntil, &strikeCount)
	if errors.Is(err, sql.ErrNoRows) {
		return ipBlock{}, false, nil
	}
	if err != nil {
		return ipBlock{}, false, err
	}
	expires := timeFromMillis(blockedUntil)
	return ipBlock{expires: expires, level: level, strikeCount: strikeCount}, true, nil
}

func (s *ipReputationStore) refreshRepeatBlock(ctx context.Context, ip string, now time.Time, block *ipBlock) (bool, error) {
	expires := now.Add(s.repeatDuration)
	result, err := s.db.Exec(ctx, `UPDATE ip_reputation
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
	block.expires = expires
	return true, nil
}

func (s *ipReputationStore) getTx(ctx context.Context, tx *sql.Tx, ip string) (rejectedIPRecord, bool, error) {
	var r rejectedIPRecord
	var id, activity int64
	var level sql.NullString
	var blocked sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT id,ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms FROM ip_reputation WHERE ip=?`, ip).Scan(&id, &r.IP, &level, &blocked, &r.LegitimateCount, &activity)
	if err == sql.ErrNoRows {
		return r, false, nil
	}
	if err != nil {
		return r, false, err
	}
	r.ID, r.BlockLevel, r.LastActivityAt = uint64(id), level.String, timeFromMillis(activity)
	if blocked.Valid {
		r.BlockedUntil = timeFromMillis(blocked.Int64)
	}
	return r, true, nil
}

func (s *ipReputationStore) pruneStrikesTx(ctx context.Context, tx *sql.Tx, id int64, now time.Time) error {
	if s.repeatThreshold == 0 || s.repeatWindow <= 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=?`, id)
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE ip_reputation_id=? AND struck_at_ms<=?`, id, unixMillis(now.Add(-s.repeatWindow)))
	return err
}
func (s *ipReputationStore) strikesTx(ctx context.Context, tx *sql.Tx, id int64) ([]time.Time, error) {
	rows, err := tx.QueryContext(ctx, `SELECT struck_at_ms FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []time.Time
	for rows.Next() {
		var ms int64
		if err := rows.Scan(&ms); err != nil {
			return nil, err
		}
		values = append(values, timeFromMillis(ms))
	}
	return values, rows.Err()
}
func (s *ipReputationStore) enforceCapacityTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*)-?,0) FROM ip_reputation`, s.maxSize).Scan(&excess); err != nil || excess == 0 {
		return 0, err
	}
	var totalRemoved int64
	for _, level := range []any{nil, rejectedIPBlockShort, rejectedIPBlockRepeat} {
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
func nullableString(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func nullableMillis(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return unixMillis(v)
}

func (s *ipReputationStore) domainAllowed(dns connectionDNSResult) (string, string, bool) {
	if len(s.domainAllowlist) == 0 || dns.status != message.ReverseDNSAvailable {
		return "", "", false
	}
	for _, entry := range dns.names {
		if entry.Confirmation != message.ForwardConfirmed {
			continue
		}
		hostname := normalizeDomain(entry.Hostname)
		for _, domain := range s.domainAllowlist {
			if domainMatches(hostname, domain) {
				return hostname, domain, true
			}
		}
	}
	return "", "", false
}
func normalizeDomain(v string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
}
func domainMatches(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}
func (s *ipReputationStore) debug(msg string, attrs ...any) {
	if s.log != nil {
		s.log.Debug(msg, attrs...)
	}
}
func (s *ipReputationStore) size() int {
	if s == nil || s.db == nil {
		return 0
	}
	var n int
	if err := s.db.QueryRow(context.Background(), `SELECT count(*) FROM ip_reputation`).Scan(&n); err != nil {
		s.logDatabaseError("count sending IP records", err)
	}
	return n
}

func (s *ipReputationStore) snapshot() map[netip.Addr]rejectedIPRecord {
	result := map[netip.Addr]rejectedIPRecord{}
	if s == nil || s.db == nil {
		return result
	}
	rows, err := s.db.Query(context.Background(), `SELECT id,ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms FROM ip_reputation`)
	if err != nil {
		return result
	}
	for rows.Next() {
		var r rejectedIPRecord
		var id, activity int64
		var level sql.NullString
		var blocked sql.NullInt64
		if rows.Scan(&id, &r.IP, &level, &blocked, &r.LegitimateCount, &activity) != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		r.ID, r.BlockLevel, r.LastActivityAt = uint64(id), level.String, timeFromMillis(activity)
		if blocked.Valid {
			r.BlockedUntil = timeFromMillis(blocked.Int64)
		}
		addr, e := netip.ParseAddr(r.IP)
		if e != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		result[addr] = r
	}
	rows.Close()
	for addr, r := range result {
		strikeRows, e := s.db.Query(context.Background(), `SELECT struck_at_ms FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id`, r.ID)
		if e != nil {
			return map[netip.Addr]rejectedIPRecord{}
		}
		for strikeRows.Next() {
			var ms int64
			if strikeRows.Scan(&ms) != nil {
				strikeRows.Close()
				return map[netip.Addr]rejectedIPRecord{}
			}
			r.Strikes = append(r.Strikes, timeFromMillis(ms))
		}
		strikeRows.Close()
		result[addr] = r
	}
	return result
}

func (s *ipReputationStore) manualAdd(addr netip.Addr) (activeIPBlock, error) {
	if !s.enabled() || !addr.IsValid() {
		return activeIPBlock{}, fmt.Errorf("IP reputation blocking is disabled or the address is invalid")
	}
	addr = canonicalIP(addr)
	if prefix, ok := s.allowed(addr); ok {
		return activeIPBlock{}, fmt.Errorf("IP address is protected by allowlist %s", prefix)
	}
	now := s.now().UTC()
	level, duration := rejectedIPBlockRepeat, s.repeatDuration
	if duration <= 0 {
		level, duration = rejectedIPBlockShort, s.shortDuration
	}
	if duration <= 0 {
		return activeIPBlock{}, fmt.Errorf("no IP block duration is configured")
	}
	expires := now.Add(duration)
	err := s.db.WithTx(context.Background(), nil, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO ip_reputation(ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms) VALUES(?,?,?,0,?) ON CONFLICT(ip) DO UPDATE SET block_level=excluded.block_level,blocked_until_ms=excluded.blocked_until_ms,legitimate_count=0,last_activity_at_ms=excluded.last_activity_at_ms`, addr.String(), level, unixMillis(expires), unixMillis(now)); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return activeIPBlock{}, err
	}
	s.debug("sending IP manually blocked", "remote_ip", addr.String(), "block_level", level, "block_expires_at", expires)
	return activeIPBlock{IP: addr.String(), Level: level, ExpiresAt: expires}, nil
}
func (s *ipReputationStore) manualDelete(addr netip.Addr) (bool, error) {
	if s == nil || s.db == nil || !addr.IsValid() {
		return false, fmt.Errorf("invalid IP address")
	}
	addr = canonicalIP(addr)
	result, err := s.db.Exec(context.Background(), `DELETE FROM ip_reputation WHERE ip=?`, addr.String())
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		s.debug("sending IP manually removed from rejection reputation", "remote_ip", addr.String())
	}
	return n > 0, nil
}
func (s *ipReputationStore) listActive() []activeIPBlock {
	if !s.enabled() {
		return nil
	}
	rows, err := s.db.Query(context.Background(), `SELECT ip,block_level,blocked_until_ms FROM ip_reputation WHERE block_level IS NOT NULL AND blocked_until_ms>? ORDER BY ip`, unixMillis(s.now().UTC()))
	if err != nil {
		s.logDatabaseError("list active sending IP blocks", err)
		return nil
	}
	defer rows.Close()
	var out []activeIPBlock
	for rows.Next() {
		var v activeIPBlock
		var ms int64
		if rows.Scan(&v.IP, &v.Level, &ms) != nil {
			return nil
		}
		v.ExpiresAt = timeFromMillis(ms)
		out = append(out, v)
	}
	return out
}
func (s *ipReputationStore) cleanup() (int64, error) {
	if !s.enabled() {
		return 0, nil
	}
	now := s.now().UTC()
	var deleted int64
	err := s.db.WithTx(context.Background(), nil, func(tx *sql.Tx) error {
		var result sql.Result
		var e error
		if s.repeatThreshold == 0 || s.repeatWindow <= 0 {
			result, e = tx.Exec(`DELETE FROM ip_strikes`)
		} else {
			result, e = tx.Exec(`DELETE FROM ip_strikes WHERE struck_at_ms<=?`, unixMillis(now.Add(-s.repeatWindow)))
		}
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e == nil {
			deleted += n
		}
		result, e = tx.Exec(`DELETE FROM ip_reputation WHERE block_level='repeat' AND blocked_until_ms<=?`, unixMillis(now))
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e == nil {
			deleted += n
		}
		if _, e := tx.Exec(`UPDATE ip_reputation SET block_level=NULL,blocked_until_ms=NULL WHERE block_level='short' AND blocked_until_ms<=?`, unixMillis(now)); e != nil {
			return e
		}
		result, e = tx.Exec(`DELETE FROM ip_reputation WHERE block_level IS NULL AND NOT EXISTS(SELECT 1 FROM ip_strikes WHERE ip_strikes.ip_reputation_id=ip_reputation.id)`)
		if e != nil {
			return e
		}
		if n, e := result.RowsAffected(); e == nil {
			deleted += n
		}
		capacityDeleted, e := s.enforceCapacityTx(context.Background(), tx)
		if e != nil {
			return e
		}
		deleted += capacityDeleted
		return nil
	})
	return deleted, err
}
func (s *ipReputationStore) logDatabaseError(operation string, err error) {
	if s != nil && s.log != nil && err != nil {
		s.log.Error("IP reputation database operation failed", "operation", operation, "error", err)
	}
}
