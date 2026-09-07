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
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
)

const (
	correspondentFileVersion               = 1
	estimatedCorrespondentEntryBytes int64 = 1 << 10
	maxLearnedRecipients                   = 100
	whitelistAuthenticatedOutbound         = "authenticated_outbound"
	whitelistRepeatedLegitimate            = "repeated_legitimate_inbound"
	whitelistManual                        = "manual"
)

type correspondentEntry struct {
	ID                   uint64    `json:"id"`
	LocalAddress         string    `json:"local_address"`
	Correspondent        string    `json:"correspondent"`
	LearnedAt            time.Time `json:"learned_at"`
	LastActivityAt       time.Time `json:"last_activity_at"`
	PersistedActivityAt  time.Time `json:"-"`
	WhitelistType        string    `json:"whitelist_type"`
	LegitimateEmailCount int       `json:"legitimate_email_count,omitempty"`
}

type correspondentMatch struct {
	Known                bool
	AllRecipientsMatched bool
	MatchedRecipients    int
	TotalRecipients      int
}

type correspondentStore struct {
	mu      *sync.RWMutex
	cfg     config.CorrespondentsConfig
	entries map[string]correspondentEntry
	db      *jsonstore.Database[string, correspondentEntry]
	now     func() time.Time
	log     *slog.Logger
	loadErr error
}

func newCorrespondentStore(cfg config.CorrespondentsConfig, log *slog.Logger) *correspondentStore {
	store := newEmptyCorrespondentStore(cfg, log)
	if !cfg.LearnAuthenticatedRecipients && !cfg.LearnLegitimateSenders && !cfg.UseAllowlist {
		return store
	}
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		store.loadErr = err
	}
	return store
}

func newEmptyCorrespondentStore(cfg config.CorrespondentsConfig, log *slog.Logger) *correspondentStore {
	store := &correspondentStore{cfg: cfg, now: time.Now, log: log}
	store.db = jsonstore.New("Contacts", cfg.File, correspondentFileVersion, cfg.MaxEntries,
		persistentStoreReadLimit(cfg.MaxEntries, estimatedCorrespondentEntryBytes),
		func(entry correspondentEntry) string { return store.key(entry.LocalAddress, entry.Correspondent) },
		jsonstore.Identity[correspondentEntry]{
			Get: func(entry correspondentEntry) uint64 { return entry.ID },
			Set: func(entry correspondentEntry, id uint64) correspondentEntry { entry.ID = id; return entry },
		},
		func(entry correspondentEntry, now time.Time) bool {
			staleAfter := cfg.StaleAfter.Value()
			return staleAfter > 0 && correspondentActivityTime(entry).Before(now.Add(-staleAfter))
		}, func(a, b correspondentEntry) bool {
			aq, bq := store.qualified(a), store.qualified(b)
			return (!aq && bq) || (aq == bq && correspondentActivityTime(a).Before(correspondentActivityTime(b)))
		}, func(a, b correspondentEntry) bool {
			return a.LocalAddress < b.LocalAddress || (a.LocalAddress == b.LocalAddress && a.Correspondent < b.Correspondent)
		}, log)
	store.db.Now = func() time.Time { return store.now() }
	store.db.PrepareForWrite = func(entry correspondentEntry) correspondentEntry {
		entry.PersistedActivityAt = entry.LastActivityAt
		return entry
	}
	store.db.AfterWrite = func(records map[string]correspondentEntry) {
		for key, entry := range records {
			entry.PersistedActivityAt = entry.LastActivityAt
			records[key] = entry
		}
	}
	store.mu, store.entries = &store.db.Mu, store.db.Records
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
	structuralChange := false
	persistActivity := false
	writes, deletes := 0, 0
	added := 0
	for recipient := range unique {
		key := s.key(localAddress, recipient)
		if entry, exists := s.entries[key]; exists {
			s.db.MarkReadsLocked(1)
			if s.entryStale(entry, now) {
				delete(s.entries, key)
				structuralChange = true
				deletes++
			} else {
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
				if promoted || s.activityPersistenceDue(entry, now) {
					writes++
				}
				s.entries[key] = entry
				continue
			}
		}
		if len(s.entries) >= s.cfg.MaxEntries {
			if s.removeStaleLocked(now) > 0 {
				structuralChange = true
			}
		}
		for len(s.entries) >= s.cfg.MaxEntries {
			s.evictOldestLocked()
			structuralChange = true
		}
		s.entries[key] = correspondentEntry{LocalAddress: localAddress, Correspondent: recipient, LearnedAt: now, LastActivityAt: now, WhitelistType: whitelistAuthenticatedOutbound}
		structuralChange = true
		writes++
		added++
	}
	if !structuralChange && !persistActivity {
		return nil
	}
	if err := s.saveLocked(writes, deletes); err != nil {
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
	persistActivity := false
	writes := 0
	for key, entry := range s.entries {
		if s.entryStale(entry, now) {
			continue
		}
		if entry.Correspondent != correspondent {
			continue
		}
		if s.cfg.Scope == "per_sender" && !recipientSet[entry.LocalAddress] {
			continue
		}
		if !s.qualified(entry) {
			continue
		}
		s.db.MarkReadsLocked(1)
		entry.LastActivityAt = now
		if s.activityPersistenceDue(entry, now) {
			persistActivity = true
			writes++
		}
		s.entries[key] = entry
	}
	if !persistActivity {
		return nil
	}
	return s.saveLocked(writes, 0)
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
	saveNeeded := false
	writes, deletes := 0, 0

	if classification == "unwanted" {
		if score < unwantedMinScore {
			if saveNeeded {
				return s.saveLocked(writes, deletes)
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
			deletes++
		}
		if removed > 0 {
			saveNeeded = true
			if s.log != nil {
				s.log.Debug("inbound-learned correspondent removed after unwanted classification", "correspondent", correspondent, "removed_entries", removed, "entry_count", len(s.entries))
			}
		}
		if saveNeeded {
			return s.saveLocked(writes, deletes)
		}
		return nil
	}
	if classification != "legitimate" {
		if saveNeeded {
			return s.saveLocked(writes, deletes)
		}
		return nil
	}

	qualifying := s.cfg.LearnLegitimateSenders && score >= s.cfg.LegitimateSenderMinScore && (!s.cfg.LegitimateSenderRequireDKIM || dkimAligned)
	for recipient := range recipientSet {
		key := s.key(recipient, correspondent)
		entry, exists := s.entries[key]
		if exists {
			s.db.MarkReadsLocked(1)
		}
		if exists && s.entryStale(entry, now) {
			delete(s.entries, key)
			exists = false
			saveNeeded = true
			deletes++
		}
		if !exists {
			if !qualifying {
				continue
			}
			if len(s.entries) >= s.cfg.MaxEntries {
				if s.removeStaleLocked(now) > 0 {
					saveNeeded = true
				}
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
			writes++
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
				writes++
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
				writes++
			}
			s.entries[key] = entry
			continue
		}
		if qualifying {
			entry.LegitimateEmailCount++
			entry.LastActivityAt = now
			s.entries[key] = entry
			saveNeeded = true
			writes++
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
		return s.saveLocked(writes, deletes)
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
	now := s.now().UTC()
	if s.cfg.Scope == "global" {
		s.mu.Lock()
		for _, entry := range s.entries {
			if entry.Correspondent == correspondent && !s.entryStale(entry, now) && s.qualified(entry) {
				s.db.MarkReadsLocked(1)
				result.Known = true
				break
			}
		}
		s.mu.Unlock()
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
	s.mu.Lock()
	for recipient := range unique {
		if entry, found := s.entries[s.key(recipient, correspondent)]; found && !s.entryStale(entry, now) && s.qualified(entry) {
			s.db.MarkReadsLocked(1)
			result.MatchedRecipients++
		}
	}
	s.mu.Unlock()
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
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]correspondentEntry, 0)
	for _, entry := range s.entries {
		if !s.entryStale(entry, now) && s.qualified(entry) && (allRecipients || entry.LocalAddress == recipient) {
			result = append(result, entry)
		}
	}
	s.db.MarkReadsLocked(uint64(len(result)))
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
	s.db.EvictOneLocked()
}

func (s *correspondentStore) removeStaleLocked(now time.Time) int {
	removed := int(s.db.RemoveExpiredLocked(now))
	if removed > 0 && s.log != nil {
		s.log.Debug("stale correspondent relationships removed", "removed_entries", removed, "entry_count", len(s.entries))
	}
	return removed
}

func (s *correspondentStore) entryStale(entry correspondentEntry, now time.Time) bool {
	staleAfter := s.cfg.StaleAfter.Value()
	return staleAfter > 0 && correspondentActivityTime(entry).Before(now.Add(-staleAfter))
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
