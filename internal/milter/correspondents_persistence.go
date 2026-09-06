package milter

import (
	"fmt"
	"sort"

	"github.com/PhilAnderson1/MilterGuard/internal/jsonfile"
)

func (s *correspondentStore) load() error {
	var data correspondentFile
	if err := jsonfile.Read(s.cfg.File, persistentStoreReadLimit(s.cfg.MaxEntries, estimatedCorrespondentEntryBytes), &data); err != nil {
		return err
	}
	if data.Version != legacyCorrespondentFileVersion && data.Version != correspondentFileVersion {
		return fmt.Errorf("unsupported correspondent allowlist version %d", data.Version)
	}
	changed := data.Version != correspondentFileVersion
	for _, entry := range data.Entries {
		entry.Correspondent = normalizeEmailAddress(entry.Correspondent)
		entry.LocalAddress = normalizeEmailAddress(entry.LocalAddress)
		if entry.Correspondent == "" || entry.LocalAddress == "" {
			changed = true
			continue
		}
		if entry.LastActivityAt.IsZero() {
			entry.LastActivityAt = entry.LearnedAt
			changed = true
		}
		if entry.WhitelistType == "" {
			entry.WhitelistType = whitelistAuthenticatedOutbound
			changed = true
		}
		if entry.WhitelistType != whitelistAuthenticatedOutbound && entry.WhitelistType != whitelistRepeatedLegitimate && entry.WhitelistType != whitelistManual {
			changed = true
			continue
		}
		if (entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual) && entry.LegitimateEmailCount != 0 {
			entry.LegitimateEmailCount = 0
			changed = true
		}
		entry.PersistedActivityAt = entry.LastActivityAt
		s.entries[s.key(entry.LocalAddress, entry.Correspondent)] = entry
	}
	if s.removeStaleLocked(s.now().UTC()) > 0 {
		changed = true
	}
	for len(s.entries) > s.cfg.MaxEntries {
		s.evictOldestLocked()
		changed = true
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *correspondentStore) saveLocked() error {
	if s.deferWrites {
		s.dirty = true
		s.markActivityPersistedLocked()
		return nil
	}
	return s.writeLocked()
}

func (s *correspondentStore) writeLocked() error {
	entries := make([]correspondentEntry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LocalAddress != entries[j].LocalAddress {
			return entries[i].LocalAddress < entries[j].LocalAddress
		}
		return entries[i].Correspondent < entries[j].Correspondent
	})
	if err := jsonfile.Write(s.cfg.File, correspondentFile{Version: correspondentFileVersion, Entries: entries}, 0750, 0640); err != nil {
		return err
	}
	s.markActivityPersistedLocked()
	return nil
}

func (s *correspondentStore) markActivityPersistedLocked() {
	for key, entry := range s.entries {
		entry.PersistedActivityAt = entry.LastActivityAt
		s.entries[key] = entry
	}
}

func (s *correspondentStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.deferWrites = true
	s.mu.Unlock()
}

func (s *correspondentStore) flush() error {
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
