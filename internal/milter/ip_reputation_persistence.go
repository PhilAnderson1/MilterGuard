package milter

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/jsonfile"
)

func (s *ipReputationStore) load() error {
	var stored rejectedIPFile
	if err := jsonfile.Read(s.stateFile, persistentStoreReadLimit(s.maxSize, estimatedIPReputationEntryBytes), &stored); err != nil {
		return err
	}
	if stored.Version != rejectedIPFileVersion {
		return fmt.Errorf("unsupported rejected IP state version %d", stored.Version)
	}
	if len(stored.Entries) > s.maxSize {
		return fmt.Errorf("rejected IP state contains %d entries; maximum is %d", len(stored.Entries), s.maxSize)
	}
	now := s.now().UTC()
	for _, record := range stored.Entries {
		addr, err := netip.ParseAddr(record.IP)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		record.IP, record.Strikes = addr.String(), s.pruneStrikes(record.Strikes, now)
		if len(record.Strikes) > s.repeatThreshold {
			record.Strikes = record.Strikes[len(record.Strikes)-s.repeatThreshold:]
		}
		if record.BlockLevel == rejectedIPBlockRepeat && !record.BlockedUntil.After(now) {
			continue
		}
		if record.BlockLevel == rejectedIPBlockShort && !record.BlockedUntil.After(now) {
			record.BlockLevel, record.BlockedUntil = "", time.Time{}
		}
		if record.BlockLevel != "" && record.BlockLevel != rejectedIPBlockShort && record.BlockLevel != rejectedIPBlockRepeat {
			continue
		}
		if record.BlockLevel == "" && len(record.Strikes) == 0 {
			continue
		}
		record.PersistedRefreshAt = now
		s.entries[addr] = record
	}
	return nil
}

func (s *ipReputationStore) saveOrLogLocked() {
	if err := s.saveLocked(); err != nil && s.log != nil {
		s.log.Error("cannot save rejected IP state", "file", s.stateFile, "error", err)
	}
}

func (s *ipReputationStore) saveLocked() error {
	if s.deferWrites {
		s.dirty = true
		return nil
	}
	return s.writeLocked()
}

func (s *ipReputationStore) writeLocked() error {
	if s.stateFile == "" {
		return nil
	}
	entries := make([]rejectedIPRecord, 0, len(s.entries))
	for _, record := range s.entries {
		entries = append(entries, record)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })
	return jsonfile.Write(s.stateFile, rejectedIPFile{Version: rejectedIPFileVersion, Entries: entries}, 0750, 0640)
}

func (s *ipReputationStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.deferWrites = true
	s.mu.Unlock()
}

func (s *ipReputationStore) flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	if err := s.writeLocked(); err != nil {
		return err
	}
	s.dirty = false
	return nil
}
