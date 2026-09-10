package milter

import (
	"context"
	"database/sql"
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

func (s *ipReputationStore) add(addr netip.Addr, score float64, dns connectionDNSResult) bool {
	if !s.enabled() || !addr.IsValid() {
		return false
	}
	addr = canonicalIP(addr)
	if prefix, ok := s.allowed(addr); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "matched_prefix", prefix.String(), "reason", "ip_allowlist", "cache_size", s.size())
		return false
	}
	if hostname, domain, ok := s.domainAllowed(dns); ok {
		s.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain, "reason", "domain_allowlist", "cache_size", s.size())
		return false
	}
	now := s.now().UTC()
	record := rejectedIPRecord{IP: addr.String(), LastActivityAt: now}
	err := s.db.WithTx(context.Background(), nil, func(tx *sql.Tx) error {
		ctx := context.Background()
		// Acquire SQLite's single-writer lock before reading mutable state. This
		// avoids a deferred-transaction upgrade racing another strike.
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO ip_reputation
			(ip, legitimate_count, last_activity_at_ms) VALUES (?, 0, ?)`, addr.String(), unixMillis(now))
		if err != nil {
			return err
		}
		var found bool
		record, found, err = s.getTx(ctx, tx, addr.String())
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("inserted IP reputation row cannot be read")
		}
		id := int64(record.ID)
		if err := s.pruneStrikesTx(ctx, tx, id, now); err != nil {
			return err
		}
		if s.repeatThreshold > 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ip_strikes (ip_reputation_id, struck_at_ms) VALUES (?, ?)`, id, unixMillis(now)); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM ip_strikes WHERE id IN (SELECT id FROM ip_strikes WHERE ip_reputation_id = ? ORDER BY struck_at_ms DESC, id DESC LIMIT -1 OFFSET ?)`, id, s.repeatThreshold); err != nil {
				return err
			}
		}
		record.Strikes, err = s.strikesTx(ctx, tx, id)
		if err != nil {
			return err
		}
		record.IP, record.LastActivityAt, record.LegitimateCount = addr.String(), now, 0
		if s.repeatThreshold > 0 && len(record.Strikes) >= s.repeatThreshold {
			record.BlockLevel, record.BlockedUntil = rejectedIPBlockRepeat, now.Add(s.repeatDuration)
		} else if s.shortDuration > 0 {
			record.BlockLevel, record.BlockedUntil = rejectedIPBlockShort, now.Add(s.shortDuration)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE ip_reputation SET block_level=?, blocked_until_ms=?, legitimate_count=0, last_activity_at_ms=? WHERE id=?`, nullableString(record.BlockLevel), nullableMillis(record.BlockedUntil), unixMillis(now), id); err != nil {
			return err
		}
		return s.enforceCapacityTx(ctx, tx)
	})
	if err != nil {
		s.logDatabaseError("add sending IP strike", err)
		return false
	}
	s.debug("sending IP reputation updated", "remote_ip", addr.String(), "score", score, "block_level", record.BlockLevel, "strike_count", len(record.Strikes), "block_expires_at", record.BlockedUntil, "cache_size", s.size())
	return record.BlockLevel != ""
}

func (s *ipReputationStore) recordLegitimate(addr netip.Addr) {
	if !s.enabled() || s.legitimatePerStrike <= 0 || !addr.IsValid() {
		return
	}
	addr, now := canonicalIP(addr), s.now().UTC()
	var record rejectedIPRecord
	removed, strikeRemoved := false, false
	err := s.db.WithTx(context.Background(), nil, func(tx *sql.Tx) error {
		ctx := context.Background()
		if _, err := tx.ExecContext(ctx, `UPDATE ip_reputation SET ip=ip WHERE ip=?`, addr.String()); err != nil {
			return err
		}
		var found bool
		var err error
		record, found, err = s.getTx(ctx, tx, addr.String())
		if err != nil || !found {
			return err
		}
		if err := s.pruneStrikesTx(ctx, tx, int64(record.ID), now); err != nil {
			return err
		}
		record.Strikes, err = s.strikesTx(ctx, tx, int64(record.ID))
		if err != nil {
			return err
		}
		active := record.BlockLevel != "" && record.BlockedUntil.After(now)
		if len(record.Strikes) == 0 {
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
			count, _ := result.RowsAffected()
			strikeRemoved = count > 0
			record.LegitimateCount = 0
		}
		record.Strikes, err = s.strikesTx(ctx, tx, int64(record.ID))
		if err != nil {
			return err
		}
		if len(record.Strikes) == 0 && !active {
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
		s.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "no_strikes", "cache_size", s.size())
		return
	}
	s.debug("sending IP legitimate evidence recorded", "remote_ip", addr.String(), "legitimate_count", record.LegitimateCount, "strike_removed", strikeRemoved, "strike_count", len(record.Strikes), "block_level", record.BlockLevel, "cache_size", s.size())
}

func (s *ipReputationStore) lookup(addr netip.Addr) (ipBlock, bool) {
	if !s.enabled() || !addr.IsValid() {
		return ipBlock{}, false
	}
	addr = canonicalIP(addr)
	if _, ok := s.allowed(addr); ok {
		return ipBlock{}, false
	}
	now := s.now().UTC()
	var block ipBlock
	found := false
	removedReason := ""
	expiredStrikeCount := 0
	err := s.db.WithTx(context.Background(), nil, func(tx *sql.Tx) error {
		ctx := context.Background()
		if _, err := tx.ExecContext(ctx, `UPDATE ip_reputation SET ip=ip WHERE ip=?`, addr.String()); err != nil {
			return err
		}
		record, ok, err := s.getTx(ctx, tx, addr.String())
		if err != nil || !ok {
			return err
		}
		if err := s.pruneStrikesTx(ctx, tx, int64(record.ID), now); err != nil {
			return err
		}
		record.Strikes, err = s.strikesTx(ctx, tx, int64(record.ID))
		if err != nil {
			return err
		}
		if record.BlockLevel != "" && !record.BlockedUntil.After(now) {
			if record.BlockLevel == rejectedIPBlockRepeat {
				_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, record.ID)
				removedReason = "repeat_block_expired"
				return err
			}
			expiredStrikeCount = len(record.Strikes)
			record.BlockLevel, record.BlockedUntil = "", time.Time{}
			if len(record.Strikes) == 0 {
				_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, record.ID)
				removedReason = "short_block_expired"
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET block_level=NULL,blocked_until_ms=NULL WHERE id=?`, record.ID)
			return err
		}
		if record.BlockLevel == "" {
			if len(record.Strikes) == 0 {
				_, err = tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id=?`, record.ID)
			}
			return err
		}
		if record.BlockLevel == rejectedIPBlockRepeat && s.repeatRefreshOnAttempt {
			record.BlockedUntil, record.LastActivityAt = now.Add(s.repeatDuration), now
			_, err = tx.ExecContext(ctx, `UPDATE ip_reputation SET blocked_until_ms=?,last_activity_at_ms=? WHERE id=?`, unixMillis(record.BlockedUntil), unixMillis(now), record.ID)
			if err != nil {
				return err
			}
		}
		block, found = ipBlock{record.BlockedUntil, record.BlockLevel, len(record.Strikes)}, true
		return nil
	})
	if err != nil {
		s.logDatabaseError("look up sending IP reputation", err)
		return ipBlock{}, false
	}
	if removedReason == "short_block_expired" {
		s.debug("sending IP short block expired", "remote_ip", addr.String(), "strike_count", expiredStrikeCount, "cache_size", s.size())
	} else if removedReason != "" {
		s.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", removedReason, "cache_size", s.size())
	}
	if found && block.level == rejectedIPBlockRepeat && s.repeatRefreshOnAttempt {
		s.debug("sending IP repeat block expiry refreshed", "remote_ip", addr.String(), "block_level", block.level, "strike_count", block.strikeCount, "block_expires_at", block.expires, "cache_size", s.size())
	}
	return block, found
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
func (s *ipReputationStore) enforceCapacityTx(ctx context.Context, tx *sql.Tx) error {
	var excess int
	if err := tx.QueryRowContext(ctx, `SELECT max(count(*)-?,0) FROM ip_reputation`, s.maxSize).Scan(&excess); err != nil || excess == 0 {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM ip_reputation WHERE id IN (SELECT id FROM ip_reputation ORDER BY CASE block_level WHEN 'repeat' THEN 2 WHEN 'short' THEN 1 ELSE 0 END,last_activity_at_ms,ip LIMIT ?)`, excess)
	return err
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
		return s.enforceCapacityTx(context.Background(), tx)
	})
	if err != nil {
		return activeIPBlock{}, err
	}
	s.debug("sending IP manually blocked", "remote_ip", addr.String(), "block_level", level, "block_expires_at", expires, "cache_size", s.size())
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
		s.debug("sending IP manually removed from rejection reputation", "remote_ip", addr.String(), "cache_size", s.size())
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
		return nil
	})
	return deleted, err
}
func (s *ipReputationStore) logDatabaseError(operation string, err error) {
	if s != nil && s.log != nil && err != nil {
		s.log.Error("IP reputation database operation failed", "operation", operation, "error", err)
	}
}
