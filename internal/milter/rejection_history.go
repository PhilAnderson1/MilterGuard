package milter

import (
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
)

const (
	rejectionHistoryVersion                   = 1
	estimatedRejectionHistoryEntryBytes int64 = 2 << 10
	maxRejectionReasonRunes                   = 1000
)

type rejectionHistoryEntry struct {
	ID         string    `json:"id,omitempty"`
	Sender     string    `json:"sender"`
	Recipient  string    `json:"recipient"`
	RejectedAt time.Time `json:"rejected_at"`
	Reason     string    `json:"reason,omitempty"`
}

type rejectionHistoryStore struct {
	cfg      config.RejectionHistoryConfig
	now      func() time.Time
	log      *slog.Logger
	db       *jsonstore.Database[string, rejectionHistoryEntry]
	sequence atomic.Uint64
}

func newRejectionHistoryStore(cfg config.RejectionHistoryConfig, log *slog.Logger) *rejectionHistoryStore {
	store := &rejectionHistoryStore{cfg: cfg, now: time.Now, log: log}
	store.db = jsonstore.New("Rejections", cfg.File, rejectionHistoryVersion, cfg.MaxEntries, persistentStoreReadLimit(cfg.MaxEntries, estimatedRejectionHistoryEntryBytes), func(v rejectionHistoryEntry) string { return v.ID }, func(v rejectionHistoryEntry, now time.Time) bool {
		return cfg.Expiry.Value() > 0 && v.RejectedAt.Before(now.Add(-cfg.Expiry.Value()))
	}, func(a, b rejectionHistoryEntry) bool { return a.RejectedAt.Before(b.RejectedAt) }, func(a, b rejectionHistoryEntry) bool { return a.RejectedAt.Before(b.RejectedAt) }, log)
	store.db.Now = func() time.Time { return store.now() }
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
	err := s.db.Update(func(records map[string]rejectionHistoryEntry) (uint64, uint64, uint64, bool) {
		for recipient := range unique {
			id := fmt.Sprintf("%d-%d-%s", now.UnixNano(), s.sequence.Add(1), recipient)
			records[id] = rejectionHistoryEntry{ID: id, Sender: sender, Recipient: recipient, RejectedAt: now, Reason: reason}
		}
		return 0, uint64(len(unique)), 0, true
	})
	if err != nil {
		return err
	}
	if s.log != nil {
		s.log.Debug("rejection history updated", "new_entries", len(unique), "entry_count", s.db.Size())
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
	result := s.db.View(func(entry rejectionHistoryEntry) bool { return allRecipients || entry.Recipient == recipient })
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].RejectedAt.After(result[j].RejectedAt)
	})
	return result
}

func (s *rejectionHistoryStore) load() error {
	sequence := 0
	changed, err := s.db.Load(func(version int) bool { return version == rejectionHistoryVersion }, func(entry rejectionHistoryEntry) (rejectionHistoryEntry, bool, bool) {
		entry.Sender = normalizeEmailAddress(entry.Sender)
		entry.Recipient = normalizeEmailAddress(entry.Recipient)
		modified := entry.ID == ""
		if modified {
			sequence++
			entry.ID = fmt.Sprintf("legacy-%d-%d", entry.RejectedAt.UnixNano(), sequence)
		}
		return entry, entry.Sender != "" && entry.Recipient != "" && !entry.RejectedAt.IsZero(), modified
	})
	if err == nil && changed {
		_, err = s.db.Flush()
	}
	return err
}

func (s *rejectionHistoryStore) enableDeferredPersistence() {
	if s != nil {
		s.db.SetDeferred(true)
	}
}
func (s *rejectionHistoryStore) flush() error {
	if s == nil {
		return nil
	}
	_, err := s.db.Flush()
	return err
}
