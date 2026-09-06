package milter

import (
	"fmt"
	"log/slog"
	"net/mail"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

const (
	correspondentFileVersion               = 2
	legacyCorrespondentFileVersion         = 1
	estimatedCorrespondentEntryBytes int64 = 1 << 10
	maxLearnedRecipients                   = 100
	whitelistAuthenticatedOutbound         = "authenticated_outbound"
	whitelistRepeatedLegitimate            = "repeated_legitimate_inbound"
	whitelistManual                        = "manual"
)

type correspondentEntry struct {
	LocalAddress         string    `json:"local_address"`
	Correspondent        string    `json:"correspondent"`
	LearnedAt            time.Time `json:"learned_at"`
	LastActivityAt       time.Time `json:"last_activity_at"`
	PersistedActivityAt  time.Time `json:"-"`
	WhitelistType        string    `json:"whitelist_type"`
	LegitimateEmailCount int       `json:"legitimate_email_count,omitempty"`
}

type correspondentFile struct {
	Version int                  `json:"version"`
	Entries []correspondentEntry `json:"entries"`
}

type correspondentMatch struct {
	Known                bool
	AllRecipientsMatched bool
	MatchedRecipients    int
	TotalRecipients      int
}

type correspondentStore struct {
	mu          sync.RWMutex
	cfg         config.CorrespondentsConfig
	entries     map[string]correspondentEntry
	now         func() time.Time
	log         *slog.Logger
	deferWrites bool
	dirty       bool
}

func newCorrespondentStore(cfg config.CorrespondentsConfig, log *slog.Logger) *correspondentStore {
	store := &correspondentStore{cfg: cfg, entries: make(map[string]correspondentEntry), now: time.Now, log: log}
	if !cfg.LearnAuthenticatedRecipients && !cfg.LearnLegitimateSenders && !cfg.UseAllowlist {
		return store
	}
	if err := store.load(); err != nil && !os.IsNotExist(err) && log != nil {
		log.Error("cannot load correspondent allowlist; continuing with an empty list", "file", cfg.File, "error", err)
	}
	return store
}

func (s *correspondentStore) key(localAddress, correspondent string) string {
	return localAddress + "\x00" + correspondent
}

func (s *correspondentStore) learn(localAddress string, recipients []string) error {
	if s == nil || !s.cfg.LearnAuthenticatedRecipients {
		return nil
	}
	localAddress = normalizeEmailAddress(localAddress)
	if localAddress == "" {
		return fmt.Errorf("authenticated envelope sender is unavailable or invalid")
	}
	unique := make(map[string]bool)
	for _, recipient := range recipients {
		if len(unique) >= maxLearnedRecipients {
			break
		}
		if recipient = normalizeEmailAddress(recipient); recipient != "" {
			unique[recipient] = true
		}
	}
	if len(unique) == 0 {
		return nil
	}

	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	structuralChange := s.removeStaleLocked(now) > 0
	persistActivity := false
	added := 0
	for recipient := range unique {
		key := s.key(localAddress, recipient)
		if entry, exists := s.entries[key]; exists {
			promoted := entry.WhitelistType != whitelistAuthenticatedOutbound && entry.WhitelistType != whitelistManual
			entry.LastActivityAt = now
			if entry.WhitelistType != whitelistManual {
				entry.WhitelistType = whitelistAuthenticatedOutbound
				entry.LegitimateEmailCount = 0
			}
			if promoted {
				structuralChange = true
			}
			if s.activityPersistenceDue(entry, now) {
				persistActivity = true
			}
			s.entries[key] = entry
			continue
		}
		for len(s.entries) >= s.cfg.MaxEntries {
			s.evictOldestLocked()
			structuralChange = true
		}
		s.entries[key] = correspondentEntry{LocalAddress: localAddress, Correspondent: recipient, LearnedAt: now, LastActivityAt: now, WhitelistType: whitelistAuthenticatedOutbound}
		structuralChange = true
		added++
	}
	if !structuralChange && !persistActivity {
		return nil
	}
	if err := s.saveLocked(); err != nil {
		return err
	}
	if s.log != nil {
		s.log.Debug("correspondent allowlist updated", "new_entries", added, "entry_count", len(s.entries))
	}
	return nil
}

// touchInbound records qualifying accepted inbound activity only for
// relationships that participated in matching under the configured scope.
func (s *correspondentStore) touchInbound(correspondent string, recipients []string) error {
	if s == nil || !s.cfg.UseAllowlist {
		return nil
	}
	correspondent = normalizeEmailAddress(correspondent)
	if correspondent == "" {
		return nil
	}
	recipientSet := make(map[string]bool)
	for _, recipient := range recipients {
		if recipient = normalizeEmailAddress(recipient); recipient != "" {
			recipientSet[recipient] = true
		}
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	structuralChange := s.removeStaleLocked(now) > 0
	persistActivity := false
	for key, entry := range s.entries {
		if entry.Correspondent != correspondent {
			continue
		}
		if s.cfg.Scope == "per_sender" && !recipientSet[entry.LocalAddress] {
			continue
		}
		if !s.qualified(entry) {
			continue
		}
		entry.LastActivityAt = now
		if s.activityPersistenceDue(entry, now) {
			persistActivity = true
		}
		s.entries[key] = entry
	}
	if !structuralChange && !persistActivity {
		return nil
	}
	return s.saveLocked()
}

func (s *correspondentStore) recordInboundClassification(correspondent string, recipients []string, recipientsComplete bool, classification string, score, unwantedMinScore float64, dkimAligned bool) error {
	if s == nil || !recipientsComplete {
		return nil
	}
	correspondent = normalizeEmailAddress(correspondent)
	if correspondent == "" {
		return nil
	}
	recipientSet := make(map[string]bool)
	for _, recipient := range recipients {
		if recipient = normalizeEmailAddress(recipient); recipient != "" {
			recipientSet[recipient] = true
		}
	}
	if len(recipientSet) == 0 {
		return nil
	}
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	saveNeeded := s.removeStaleLocked(now) > 0

	if classification == "unwanted" {
		if score < unwantedMinScore {
			if saveNeeded {
				return s.saveLocked()
			}
			return nil
		}
		removed := 0
		for key, entry := range s.entries {
			if entry.Correspondent != correspondent || entry.WhitelistType != whitelistRepeatedLegitimate {
				continue
			}
			if s.cfg.Scope == "per_sender" && !recipientSet[entry.LocalAddress] {
				continue
			}
			delete(s.entries, key)
			removed++
		}
		if removed > 0 {
			saveNeeded = true
			if s.log != nil {
				s.log.Debug("inbound-learned correspondent removed after unwanted classification", "correspondent", correspondent, "removed_entries", removed, "entry_count", len(s.entries))
			}
		}
		if saveNeeded {
			return s.saveLocked()
		}
		return nil
	}
	if classification != "legitimate" {
		if saveNeeded {
			return s.saveLocked()
		}
		return nil
	}

	qualifying := s.cfg.LearnLegitimateSenders && score >= s.cfg.LegitimateSenderMinScore && (!s.cfg.LegitimateSenderRequireDKIM || dkimAligned)
	for recipient := range recipientSet {
		key := s.key(recipient, correspondent)
		entry, exists := s.entries[key]
		if !exists {
			if !qualifying {
				continue
			}
			for len(s.entries) >= s.cfg.MaxEntries {
				s.evictOldestLocked()
			}
			entry = correspondentEntry{
				LocalAddress: recipient, Correspondent: correspondent, LearnedAt: now, LastActivityAt: now,
				WhitelistType: whitelistRepeatedLegitimate, LegitimateEmailCount: 1,
			}
			s.entries[key] = entry
			saveNeeded = true
			if s.log != nil {
				if s.qualified(entry) {
					s.log.Debug("inbound sender promoted to known correspondent", "local_address", recipient, "correspondent", correspondent, "legitimate_email_count", 1)
				} else {
					s.log.Debug("inbound sender legitimate candidate updated", "local_address", recipient, "correspondent", correspondent, "legitimate_email_count", 1, "required_count", s.cfg.LegitimateSenderMinMessages)
				}
			}
			continue
		}
		if entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual {
			entry.LastActivityAt = now
			if s.activityPersistenceDue(entry, now) {
				saveNeeded = true
			}
			s.entries[key] = entry
			continue
		}
		if entry.WhitelistType != whitelistRepeatedLegitimate {
			continue
		}
		if s.qualified(entry) {
			entry.LastActivityAt = now
			if s.activityPersistenceDue(entry, now) {
				saveNeeded = true
			}
			s.entries[key] = entry
			continue
		}
		if qualifying {
			entry.LegitimateEmailCount++
			entry.LastActivityAt = now
			s.entries[key] = entry
			saveNeeded = true
			if s.log != nil {
				if s.qualified(entry) {
					s.log.Debug("inbound sender promoted to known correspondent", "local_address", recipient, "correspondent", correspondent, "legitimate_email_count", entry.LegitimateEmailCount)
				} else {
					s.log.Debug("inbound sender legitimate candidate updated", "local_address", recipient, "correspondent", correspondent, "legitimate_email_count", entry.LegitimateEmailCount, "required_count", s.cfg.LegitimateSenderMinMessages)
				}
			}
		}
	}
	if saveNeeded {
		return s.saveLocked()
	}
	return nil
}

func (s *correspondentStore) qualified(entry correspondentEntry) bool {
	return entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual ||
		(entry.WhitelistType == whitelistRepeatedLegitimate && entry.LegitimateEmailCount >= s.cfg.LegitimateSenderMinMessages)
}

func (s *correspondentStore) activityPersistenceDue(entry correspondentEntry, now time.Time) bool {
	interval := s.cfg.ActivityUpdateInterval.Value()
	return interval == 0 || entry.PersistedActivityAt.IsZero() || !now.Before(entry.PersistedActivityAt.Add(interval))
}

func (s *correspondentStore) match(correspondent string, recipients []string) correspondentMatch {
	result := correspondentMatch{}
	if s == nil || !s.cfg.UseAllowlist {
		return result
	}
	correspondent = normalizeEmailAddress(correspondent)
	if correspondent == "" {
		return result
	}
	s.removeStale()
	if s.cfg.Scope == "global" {
		s.mu.RLock()
		for _, entry := range s.entries {
			if entry.Correspondent == correspondent && s.qualified(entry) {
				result.Known = true
				break
			}
		}
		s.mu.RUnlock()
		result.AllRecipientsMatched = result.Known
		result.TotalRecipients = 1
		if result.Known {
			result.MatchedRecipients = 1
		}
		return result
	}
	unique := make(map[string]bool)
	for _, recipient := range recipients {
		if recipient = normalizeEmailAddress(recipient); recipient != "" {
			unique[recipient] = true
		}
	}
	result.TotalRecipients = len(unique)
	if result.TotalRecipients == 0 {
		return result
	}
	s.mu.RLock()
	for recipient := range unique {
		if entry, found := s.entries[s.key(recipient, correspondent)]; found && s.qualified(entry) {
			result.MatchedRecipients++
		}
	}
	s.mu.RUnlock()
	result.Known = result.MatchedRecipients > 0
	result.AllRecipientsMatched = result.MatchedRecipients == result.TotalRecipients
	return result
}

func (s *correspondentStore) listAllowlist(recipient string) []correspondentEntry {
	if s == nil {
		return nil
	}
	allRecipients := recipient == "*"
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return nil
		}
	}
	s.removeStale()
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]correspondentEntry, 0)
	for _, entry := range s.entries {
		if s.qualified(entry) && (allRecipients || entry.LocalAddress == recipient) {
			result = append(result, entry)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		iActivity := correspondentActivityTime(result[i])
		jActivity := correspondentActivityTime(result[j])
		if !iActivity.Equal(jActivity) {
			return iActivity.After(jActivity)
		}
		if result[i].LocalAddress != result[j].LocalAddress {
			return result[i].LocalAddress < result[j].LocalAddress
		}
		return result[i].Correspondent < result[j].Correspondent
	})
	return result
}

func correspondentActivityTime(entry correspondentEntry) time.Time {
	if !entry.LastActivityAt.IsZero() {
		return entry.LastActivityAt
	}
	return entry.LearnedAt
}

func (s *correspondentStore) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	oldestQualified := true
	for key, entry := range s.entries {
		activity := entry.LastActivityAt
		if activity.IsZero() {
			activity = entry.LearnedAt
		}
		qualified := s.qualified(entry)
		if oldestKey == "" || (oldestQualified && !qualified) || (qualified == oldestQualified && activity.Before(oldestTime)) {
			oldestKey, oldestTime, oldestQualified = key, activity, qualified
		}
	}
	delete(s.entries, oldestKey)
}

func (s *correspondentStore) removeStale() {
	if s == nil || s.cfg.StaleAfter.Value() <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := s.removeStaleLocked(s.now().UTC())
	if removed == 0 {
		return
	}
	if err := s.saveLocked(); err != nil && s.log != nil {
		s.log.Error("cannot persist stale correspondent eviction", "error", err)
	}
}

func (s *correspondentStore) removeStaleLocked(now time.Time) int {
	staleAfter := s.cfg.StaleAfter.Value()
	if staleAfter <= 0 {
		return 0
	}
	cutoff := now.Add(-staleAfter)
	removed := 0
	for key, entry := range s.entries {
		activity := entry.LastActivityAt
		if activity.IsZero() {
			activity = entry.LearnedAt
		}
		if activity.Before(cutoff) {
			delete(s.entries, key)
			removed++
		}
	}
	if removed > 0 && s.log != nil {
		s.log.Debug("stale correspondent relationships removed", "removed_entries", removed, "entry_count", len(s.entries))
	}
	return removed
}

func normalizeEmailAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 320 {
		return ""
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address == "" || strings.Count(address.Address, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(address.Address, "@", 2)
	local := strings.ToLower(strings.TrimSpace(parts[0]))
	domain := normalizeDomain(parts[1])
	if local == "" || len(local)+len(domain)+1 > 254 || safeDNSHostname(domain) == "" {
		return ""
	}
	return local + "@" + domain
}
