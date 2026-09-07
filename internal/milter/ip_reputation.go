package milter

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const (
	rejectedIPFileVersion                  = 1
	estimatedIPReputationEntryBytes  int64 = 1 << 10
	rejectedIPRefreshPersistInterval       = 5 * time.Minute
	rejectedIPBlockShort                   = "short"
	rejectedIPBlockRepeat                  = "repeat"
)

type ipBlock struct {
	expires        time.Time
	classification string
	score          float64
	level          string
	strikeCount    int
}

type activeIPBlock struct {
	IP        string
	Hostname  string
	Level     string
	ExpiresAt time.Time
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
				names, err := s.resolver.LookupAddr(ctx, addr.String())
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

type rejectedIPRecord struct {
	ID                 uint64      `json:"id"`
	IP                 string      `json:"ip"`
	Strikes            []time.Time `json:"strikes,omitempty"`
	BlockLevel         string      `json:"block_level,omitempty"`
	BlockedUntil       time.Time   `json:"blocked_until,omitempty"`
	Classification     string      `json:"classification,omitempty"`
	Score              float64     `json:"score,omitempty"`
	LegitimateCount    int         `json:"legitimate_count,omitempty"`
	LastActivityAt     time.Time   `json:"last_activity_at"`
	PersistedRefreshAt time.Time   `json:"-"`
}

type ipReputationStore struct {
	mu                     *sync.RWMutex
	entries                map[netip.Addr]rejectedIPRecord
	db                     *jsonstore.Database[netip.Addr, rejectedIPRecord]
	shortDuration          time.Duration
	repeatThreshold        int
	repeatWindow           time.Duration
	repeatDuration         time.Duration
	repeatRefreshOnAttempt bool
	legitimatePerStrike    int
	maxSize                int
	stateFile              string
	allowlist              []netip.Prefix
	domainAllowlist        []string
	now                    func() time.Time
	log                    *slog.Logger
	loadErr                error
}

func newIPReputationStore(reputation config.IPReputationConfig, log *slog.Logger) *ipReputationStore {
	cache := &ipReputationStore{
		shortDuration:   reputation.BlockDuration.Value(),
		repeatThreshold: reputation.RepeatThreshold, repeatWindow: reputation.RepeatWindow.Value(),
		repeatDuration: reputation.RepeatBlockDuration.Value(), repeatRefreshOnAttempt: reputation.RepeatRefreshOnAttempt,
		legitimatePerStrike: reputation.LegitimatePerStrike,
		maxSize:             reputation.MaxEntries, stateFile: reputation.StateFile, now: time.Now, log: log,
	}
	cache.db = jsonstore.New("IP", reputation.StateFile, rejectedIPFileVersion, reputation.MaxEntries,
		persistentStoreReadLimit(reputation.MaxEntries, estimatedIPReputationEntryBytes),
		func(record rejectedIPRecord) netip.Addr { addr, _ := netip.ParseAddr(record.IP); return addr.Unmap() },
		jsonstore.Identity[rejectedIPRecord]{
			Get: func(record rejectedIPRecord) uint64 { return record.ID },
			Set: func(record rejectedIPRecord, id uint64) rejectedIPRecord { record.ID = id; return record },
		}, nil,
		func(a, b rejectedIPRecord) bool {
			rank := func(v rejectedIPRecord) int {
				if v.BlockLevel == rejectedIPBlockRepeat {
					return 2
				}
				if v.BlockLevel == rejectedIPBlockShort {
					return 1
				}
				return 0
			}
			ar, br := rank(a), rank(b)
			return ar < br || (ar == br && a.LastActivityAt.Before(b.LastActivityAt))
		}, func(a, b rejectedIPRecord) bool { return a.IP < b.IP }, log)
	cache.db.Now = func() time.Time { return cache.now() }
	cache.db.Maintain = func(record rejectedIPRecord, now time.Time) (rejectedIPRecord, bool, bool) {
		originalStrikeCount, originalLevel, originalUntil := len(record.Strikes), record.BlockLevel, record.BlockedUntil
		record.Strikes = cache.pruneStrikes(record.Strikes, now)
		if record.BlockLevel == rejectedIPBlockRepeat && !record.BlockedUntil.After(now) {
			return record, false, true
		}
		if record.BlockLevel == rejectedIPBlockShort && !record.BlockedUntil.After(now) {
			record.BlockLevel, record.BlockedUntil = "", time.Time{}
		}
		changed := originalStrikeCount != len(record.Strikes) || originalLevel != record.BlockLevel || !originalUntil.Equal(record.BlockedUntil)
		return record, record.BlockLevel != "" || len(record.Strikes) > 0, changed
	}
	cache.db.OnEvict = func(addr netip.Addr, _ rejectedIPRecord) {
		cache.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "capacity", "cache_size", len(cache.db.Records))
	}
	cache.db.CloneValue = func(record rejectedIPRecord) rejectedIPRecord {
		record.Strikes = append([]time.Time(nil), record.Strikes...)
		return record
	}
	cache.mu, cache.entries = &cache.db.Mu, cache.db.Records
	for _, entry := range reputation.IPAllowlist {
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			cache.allowlist = append(cache.allowlist, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			bits := 128
			if addr.Is4() || addr.Is4In6() {
				bits = 32
			}
			cache.allowlist = append(cache.allowlist, netip.PrefixFrom(addr.Unmap(), bits))
		}
	}
	for _, domain := range reputation.DomainAllowlist {
		cache.domainAllowlist = append(cache.domainAllowlist, normalizeDomain(domain))
	}
	if cache.enabled() && cache.stateFile != "" {
		if err := cache.load(); err != nil && !os.IsNotExist(err) {
			cache.loadErr = err
		}
	}
	return cache
}

func (c *ipReputationStore) enabled() bool {
	return c != nil && c.maxSize > 0 && (c.shortDuration > 0 || c.repeatThreshold > 0)
}

func (c *ipReputationStore) allowed(addr netip.Addr) (netip.Prefix, bool) {
	if !addr.IsValid() {
		return netip.Prefix{}, true
	}
	addr = addr.Unmap()
	for _, prefix := range c.allowlist {
		if prefix.Contains(addr) {
			return prefix, true
		}
	}
	return netip.Prefix{}, false
}

func (c *ipReputationStore) add(addr netip.Addr, classification string, score float64, dns connectionDNSResult) bool {
	if !c.enabled() || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if prefix, ok := c.allowed(addr); ok {
		c.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "matched_prefix", prefix.String(), "reason", "ip_allowlist", "cache_size", c.size())
		return false
	}
	if hostname, domain, ok := c.domainAllowed(dns); ok {
		c.debug("sending IP excluded from rejection reputation", "remote_ip", addr.String(), "reverse_dns", hostname, "matched_domain", domain, "reason", "domain_allowlist", "cache_size", c.size())
		return false
	}
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, existed := c.entries[addr]
	if existed {
		c.db.MarkReadsLocked(1)
	}
	if !existed && len(c.entries) >= c.maxSize {
		c.cleanupLocked(now)
	}
	if !existed && len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}
	record.IP = addr.String()
	record.Strikes = c.pruneStrikes(record.Strikes, now)
	if c.repeatThreshold > 0 {
		record.Strikes = append(record.Strikes, now)
		if len(record.Strikes) > c.repeatThreshold {
			record.Strikes = record.Strikes[len(record.Strikes)-c.repeatThreshold:]
		}
	}
	record.Classification, record.Score, record.LastActivityAt = classification, score, now
	record.LegitimateCount = 0
	if c.repeatThreshold > 0 && len(record.Strikes) >= c.repeatThreshold {
		record.BlockLevel, record.BlockedUntil = rejectedIPBlockRepeat, now.Add(c.repeatDuration)
	} else if c.shortDuration > 0 {
		record.BlockLevel, record.BlockedUntil = rejectedIPBlockShort, now.Add(c.shortDuration)
	}
	record.PersistedRefreshAt = now
	c.entries[addr] = record
	c.saveOrLogLocked(1, 0)
	c.debug("sending IP reputation updated", "remote_ip", addr.String(), "classification", classification, "score", score, "block_level", record.BlockLevel, "strike_count", len(record.Strikes), "block_expires_at", record.BlockedUntil, "cache_size", len(c.entries))
	return record.BlockLevel != ""
}

// recordLegitimate applies positive AI evidence only to an existing reputation
// record. It never creates a record or ends an active block early.
func (c *ipReputationStore) recordLegitimate(addr netip.Addr) {
	if !c.enabled() || c.legitimatePerStrike <= 0 || !addr.IsValid() {
		return
	}
	addr = addr.Unmap()
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.entries[addr]
	if !ok {
		return
	}
	c.db.MarkReadsLocked(1)
	record.Strikes = c.pruneStrikes(record.Strikes, now)
	if len(record.Strikes) == 0 {
		record.LegitimateCount = 0
		if record.BlockLevel == "" || !record.BlockedUntil.After(now) {
			delete(c.entries, addr)
			c.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "no_strikes", "cache_size", len(c.entries))
			c.saveOrLogLocked(0, 1)
			return
		}
		c.entries[addr] = record
		return
	}
	record.LegitimateCount++
	record.LastActivityAt = now
	strikeRemoved := false
	if record.LegitimateCount >= c.legitimatePerStrike {
		record.Strikes = record.Strikes[1:]
		record.LegitimateCount = 0
		strikeRemoved = true
	}
	if len(record.Strikes) == 0 && record.BlockLevel == "" {
		delete(c.entries, addr)
	} else {
		c.entries[addr] = record
	}
	if len(record.Strikes) == 0 && record.BlockLevel == "" {
		c.saveOrLogLocked(0, 1)
	} else {
		c.saveOrLogLocked(1, 0)
	}
	c.debug("sending IP legitimate evidence recorded", "remote_ip", addr.String(), "legitimate_count", record.LegitimateCount, "strike_removed", strikeRemoved, "strike_count", len(record.Strikes), "block_level", record.BlockLevel, "cache_size", len(c.entries))
}

func (c *ipReputationStore) lookup(addr netip.Addr) (ipBlock, bool) {
	if !c.enabled() || !addr.IsValid() {
		return ipBlock{}, false
	}
	if _, allowed := c.allowed(addr); allowed {
		return ipBlock{}, false
	}
	addr = addr.Unmap()
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	record, ok := c.entries[addr]
	if !ok {
		return ipBlock{}, false
	}
	c.db.MarkReadsLocked(1)
	record.Strikes = c.pruneStrikes(record.Strikes, now)
	if record.BlockLevel != "" && !record.BlockedUntil.After(now) {
		if record.BlockLevel == rejectedIPBlockRepeat {
			delete(c.entries, addr)
			c.debug("sending IP removed from rejection reputation", "remote_ip", addr.String(), "reason", "repeat_block_expired", "cache_size", len(c.entries))
			c.saveOrLogLocked(0, 1)
			return ipBlock{}, false
		}
		record.BlockLevel, record.BlockedUntil = "", time.Time{}
		if len(record.Strikes) == 0 {
			delete(c.entries, addr)
		} else {
			c.entries[addr] = record
		}
		c.debug("sending IP short block expired", "remote_ip", addr.String(), "strike_count", len(record.Strikes), "cache_size", len(c.entries))
		if len(record.Strikes) == 0 {
			c.saveOrLogLocked(0, 1)
		} else {
			c.saveOrLogLocked(1, 0)
		}
		return ipBlock{}, false
	}
	if record.BlockLevel == "" {
		if len(record.Strikes) == 0 {
			delete(c.entries, addr)
			c.saveOrLogLocked(0, 1)
		} else {
			c.entries[addr] = record
		}
		return ipBlock{}, false
	}
	if record.BlockLevel == rejectedIPBlockRepeat && c.repeatRefreshOnAttempt {
		record.BlockedUntil, record.LastActivityAt = now.Add(c.repeatDuration), now
		persist := now.Sub(record.PersistedRefreshAt) >= rejectedIPRefreshPersistInterval
		if persist {
			record.PersistedRefreshAt = now
		}
		c.entries[addr] = record
		c.debug("sending IP repeat block expiry refreshed", "remote_ip", addr.String(), "block_level", record.BlockLevel, "strike_count", len(record.Strikes), "block_expires_at", record.BlockedUntil, "cache_size", len(c.entries))
		if persist {
			c.saveOrLogLocked(1, 0)
		}
	} else {
		c.entries[addr] = record
	}
	return ipBlock{expires: record.BlockedUntil, classification: record.Classification, score: record.Score, level: record.BlockLevel, strikeCount: len(record.Strikes)}, true
}

func (c *ipReputationStore) pruneStrikes(strikes []time.Time, now time.Time) []time.Time {
	if c.repeatThreshold == 0 || c.repeatWindow <= 0 {
		return nil
	}
	cutoff := now.Add(-c.repeatWindow)
	kept := strikes[:0]
	for _, strike := range strikes {
		if strike.After(cutoff) {
			kept = append(kept, strike)
		}
	}
	return kept
}

func (c *ipReputationStore) cleanupLocked(now time.Time) bool {
	return c.db.RemoveExpiredLocked(now) > 0
}

func (c *ipReputationStore) evictOldestLocked() {
	c.db.EvictOneLocked()
}

func (c *ipReputationStore) domainAllowed(dns connectionDNSResult) (string, string, bool) {
	if len(c.domainAllowlist) == 0 || dns.status != message.ReverseDNSAvailable {
		return "", "", false
	}
	for _, entry := range dns.names {
		if entry.Confirmation != message.ForwardConfirmed {
			continue
		}
		hostname := normalizeDomain(entry.Hostname)
		for _, domain := range c.domainAllowlist {
			if domainMatches(hostname, domain) {
				return hostname, domain, true
			}
		}
	}
	return "", "", false
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
func domainMatches(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func (c *ipReputationStore) debug(msg string, attrs ...any) {
	if c.log != nil {
		c.log.Debug(msg, attrs...)
	}
}

func (c *ipReputationStore) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ipReputationStore) manualAdd(addr netip.Addr) (activeIPBlock, error) {
	if !c.enabled() || !addr.IsValid() {
		return activeIPBlock{}, fmt.Errorf("IP reputation blocking is disabled or the address is invalid")
	}
	addr = addr.Unmap()
	if prefix, allowed := c.allowed(addr); allowed {
		return activeIPBlock{}, fmt.Errorf("IP address is protected by allowlist %s", prefix)
	}
	now := c.now().UTC()
	level, duration := rejectedIPBlockRepeat, c.repeatDuration
	if duration <= 0 {
		level, duration = rejectedIPBlockShort, c.shortDuration
	}
	if duration <= 0 {
		return activeIPBlock{}, fmt.Errorf("no IP block duration is configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	before := cloneRejectedIPEntries(c.entries)
	if _, exists := c.entries[addr]; !exists && len(c.entries) >= c.maxSize {
		c.cleanupLocked(now)
	}
	if _, exists := c.entries[addr]; !exists && len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}
	record := c.entries[addr]
	record.IP, record.BlockLevel = addr.String(), level
	record.BlockedUntil, record.LastActivityAt = now.Add(duration), now
	record.Classification, record.Score, record.LegitimateCount = "manual", 1, 0
	record.PersistedRefreshAt = now
	c.entries[addr] = record
	if err := c.saveLocked(1, 0); err != nil {
		c.db.ReplaceLocked(before)
		return activeIPBlock{}, err
	}
	c.debug("sending IP manually blocked", "remote_ip", addr.String(), "block_level", level, "block_expires_at", record.BlockedUntil, "cache_size", len(c.entries))
	return activeIPBlock{IP: addr.String(), Level: level, ExpiresAt: record.BlockedUntil}, nil
}

func (c *ipReputationStore) manualDelete(addr netip.Addr) (bool, error) {
	if c == nil || !addr.IsValid() {
		return false, fmt.Errorf("invalid IP address")
	}
	addr = addr.Unmap()
	c.mu.Lock()
	defer c.mu.Unlock()
	before := cloneRejectedIPEntries(c.entries)
	if _, found := c.entries[addr]; !found {
		return false, nil
	}
	delete(c.entries, addr)
	if err := c.saveLocked(0, 1); err != nil {
		c.db.ReplaceLocked(before)
		return false, err
	}
	c.debug("sending IP manually removed from rejection reputation", "remote_ip", addr.String(), "cache_size", len(c.entries))
	return true, nil
}

func (c *ipReputationStore) listActive() []activeIPBlock {
	if !c.enabled() {
		return nil
	}
	now := c.now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupLocked(now)
	result := make([]activeIPBlock, 0)
	for _, record := range c.entries {
		if (record.BlockLevel == rejectedIPBlockShort || record.BlockLevel == rejectedIPBlockRepeat) && record.BlockedUntil.After(now) {
			result = append(result, activeIPBlock{IP: record.IP, Level: record.BlockLevel, ExpiresAt: record.BlockedUntil})
		}
	}
	c.db.MarkReadsLocked(uint64(len(result)))
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	if c.db.Dirty && !c.db.DeferWrites {
		if _, err := c.db.FlushLocked("write"); err != nil && c.log != nil {
			c.log.Error("cannot save rejected IP state", "file", c.stateFile, "error", err)
		}
	}
	return result
}

func cloneRejectedIPEntries(entries map[netip.Addr]rejectedIPRecord) map[netip.Addr]rejectedIPRecord {
	clone := make(map[netip.Addr]rejectedIPRecord, len(entries))
	for addr, record := range entries {
		record.Strikes = append([]time.Time(nil), record.Strikes...)
		clone[addr] = record
	}
	return clone
}
