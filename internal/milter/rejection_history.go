package milter

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonfile"
)

const (
	rejectionHistoryVersion                   = 1
	estimatedRejectionHistoryEntryBytes int64 = 2 << 10
	maxRejectionReasonRunes                   = 1000
)

type rejectionHistoryEntry struct {
	Sender     string    `json:"sender"`
	Recipient  string    `json:"recipient"`
	RejectedAt time.Time `json:"rejected_at"`
	Reason     string    `json:"reason,omitempty"`
}

type rejectionHistoryFile struct {
	Version int                     `json:"version"`
	Entries []rejectionHistoryEntry `json:"entries"`
}

type rejectionHistoryStore struct {
	mu          sync.RWMutex
	cfg         config.RejectionHistoryConfig
	entries     []rejectionHistoryEntry
	now         func() time.Time
	log         *slog.Logger
	deferWrites bool
	dirty       bool
}

func newRejectionHistoryStore(cfg config.RejectionHistoryConfig, log *slog.Logger) *rejectionHistoryStore {
	store := &rejectionHistoryStore{cfg: cfg, now: time.Now, log: log}
	if cfg.Expiry.Value() <= 0 {
		return store
	}
	if err := store.load(); err != nil && !os.IsNotExist(err) && log != nil {
		log.Error("cannot load rejection history; continuing with an empty history", "file", cfg.File, "error", err)
	}
	return store
}

func (s *rejectionHistoryStore) add(visibleSender, envelopeSender string, recipients, reasons []string) error {
	if s == nil || s.cfg.Expiry.Value() <= 0 {
		return nil
	}
	sender := normalizeEmailAddress(visibleSender)
	if sender == "" {
		sender = normalizeEmailAddress(envelopeSender)
	}
	if sender == "" {
		return nil
	}
	unique := make(map[string]bool)
	for _, recipient := range recipients {
		if normalized := normalizeEmailAddress(recipient); normalized != "" {
			unique[normalized] = true
		}
	}
	if len(unique) == 0 {
		return nil
	}
	now := s.now().UTC()
	reason := rejectionReason(reasons)
	s.mu.Lock()
	defer s.mu.Unlock()
	before := append([]rejectionHistoryEntry(nil), s.entries...)
	s.pruneLocked(now)
	for recipient := range unique {
		s.entries = append(s.entries, rejectionHistoryEntry{Sender: sender, Recipient: recipient, RejectedAt: now, Reason: reason})
	}
	if excess := len(s.entries) - s.cfg.MaxEntries; excess > 0 {
		s.entries = append([]rejectionHistoryEntry(nil), s.entries[excess:]...)
	}
	if err := s.saveLocked(); err != nil {
		s.entries = before
		return err
	}
	if s.log != nil {
		s.log.Debug("rejection history updated", "new_entries", len(unique), "entry_count", len(s.entries))
	}
	return nil
}

func rejectionReason(reasons []string) string {
	cleaned := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reason = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, strings.ToValidUTF8(reason, "�"))
		reason = strings.Join(strings.Fields(reason), " ")
		if reason != "" {
			cleaned = append(cleaned, reason)
		}
	}
	combined := strings.Join(cleaned, "; ")
	if utf8.RuneCountInString(combined) <= maxRejectionReasonRunes {
		return combined
	}
	return string([]rune(combined)[:maxRejectionReasonRunes]) + "…"
}

func (s *rejectionHistoryStore) list(recipient string) []rejectionHistoryEntry {
	if s == nil || s.cfg.Expiry.Value() <= 0 {
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
	if s.pruneLocked(now) {
		if err := s.saveLocked(); err != nil && s.log != nil {
			s.log.Error("cannot prune rejection history", "file", s.cfg.File, "error", err)
		}
	}
	result := make([]rejectionHistoryEntry, 0)
	for _, entry := range s.entries {
		if allRecipients || entry.Recipient == recipient {
			result = append(result, entry)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].RejectedAt.After(result[j].RejectedAt)
	})
	return result
}

func (s *rejectionHistoryStore) pruneLocked(now time.Time) bool {
	cutoff := now.Add(-s.cfg.Expiry.Value())
	kept := s.entries[:0]
	for _, entry := range s.entries {
		if !entry.RejectedAt.Before(cutoff) {
			kept = append(kept, entry)
		}
	}
	changed := len(kept) != len(s.entries)
	s.entries = kept
	return changed
}

func (s *rejectionHistoryStore) load() error {
	var stored rejectionHistoryFile
	if err := jsonfile.Read(s.cfg.File, persistentStoreReadLimit(s.cfg.MaxEntries, estimatedRejectionHistoryEntryBytes), &stored); err != nil {
		return err
	}
	if stored.Version != rejectionHistoryVersion {
		return fmt.Errorf("unsupported rejection history version %d", stored.Version)
	}
	for _, entry := range stored.Entries {
		entry.Sender = normalizeEmailAddress(entry.Sender)
		entry.Recipient = normalizeEmailAddress(entry.Recipient)
		if entry.Sender != "" && entry.Recipient != "" && !entry.RejectedAt.IsZero() {
			s.entries = append(s.entries, entry)
		}
	}
	s.pruneLocked(s.now().UTC())
	sort.SliceStable(s.entries, func(i, j int) bool { return s.entries[i].RejectedAt.Before(s.entries[j].RejectedAt) })
	if excess := len(s.entries) - s.cfg.MaxEntries; excess > 0 {
		s.entries = s.entries[excess:]
	}
	return nil
}

func (s *rejectionHistoryStore) saveLocked() error {
	if s.deferWrites {
		s.dirty = true
		return nil
	}
	return s.writeLocked()
}

func (s *rejectionHistoryStore) writeLocked() error {
	entries := append([]rejectionHistoryEntry(nil), s.entries...)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].RejectedAt.Before(entries[j].RejectedAt) })
	return jsonfile.Write(s.cfg.File, rejectionHistoryFile{Version: rejectionHistoryVersion, Entries: entries}, 0750, 0640)
}

func (s *rejectionHistoryStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.deferWrites = true
	s.mu.Unlock()
}

func (s *rejectionHistoryStore) flush() error {
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
