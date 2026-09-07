package milter

import (
	"log/slog"
	"os"
	"slices"
	"sort"
	"strings"
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
	ID         uint64    `json:"id"`
	Sender     string    `json:"sender"`
	Recipients []string  `json:"recipients"`
	RejectedAt time.Time `json:"rejected_at"`
	Reason     string    `json:"reason,omitempty"`
}

type rejectionHistoryStore struct {
	cfg     config.RejectionHistoryConfig
	now     func() time.Time
	log     *slog.Logger
	db      *jsonstore.Database[uint64, rejectionHistoryEntry]
	loadErr error
}

func newRejectionHistoryStore(cfg config.RejectionHistoryConfig, log *slog.Logger) *rejectionHistoryStore {
	store := &rejectionHistoryStore{cfg: cfg, now: time.Now, log: log}
	store.db = jsonstore.New("Rejections", cfg.File, rejectionHistoryVersion, cfg.MaxEntries, persistentStoreReadLimit(cfg.MaxEntries, estimatedRejectionHistoryEntryBytes), func(v rejectionHistoryEntry) uint64 { return v.ID }, jsonstore.Identity[rejectionHistoryEntry]{
		Get: func(v rejectionHistoryEntry) uint64 { return v.ID },
		Set: func(v rejectionHistoryEntry, id uint64) rejectionHistoryEntry { v.ID = id; return v },
	}, func(v rejectionHistoryEntry, now time.Time) bool {
		return cfg.Expiry.Value() > 0 && v.RejectedAt.Before(now.Add(-cfg.Expiry.Value()))
	}, func(a, b rejectionHistoryEntry) bool { return a.RejectedAt.Before(b.RejectedAt) }, func(a, b rejectionHistoryEntry) bool { return a.RejectedAt.Before(b.RejectedAt) }, log)
	store.db.Now = func() time.Time { return store.now() }
	if cfg.Expiry.Value() <= 0 {
		return store
	}
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		store.loadErr = err
	}
	return store
}

func (s *rejectionHistoryStore) add(visibleSender, envelopeSender string, recipients, reasons []string) error {
	_, err := s.addWithID(visibleSender, envelopeSender, recipients, reasons)
	return err
}

func (s *rejectionHistoryStore) addWithID(visibleSender, envelopeSender string, recipients, reasons []string) (uint64, error) {
	if s == nil || s.cfg.Expiry.Value() <= 0 {
		return 0, nil
	}
	sender := normalizeEmailAddress(visibleSender)
	if sender == "" {
		sender = normalizeEmailAddress(envelopeSender)
	}
	if sender == "" {
		return 0, nil
	}
	unique := make(map[string]bool)
	for _, recipient := range recipients {
		if normalized := normalizeEmailAddress(recipient); normalized != "" {
			unique[normalized] = true
		}
	}
	if len(unique) == 0 {
		return 0, nil
	}
	now := s.now().UTC()
	reason := rejectionReason(reasons)
	normalizedRecipients := make([]string, 0, len(unique))
	for recipient := range unique {
		normalizedRecipients = append(normalizedRecipients, recipient)
	}
	sort.Strings(normalizedRecipients)
	added, err := s.db.Add(rejectionHistoryEntry{Sender: sender, Recipients: normalizedRecipients, RejectedAt: now, Reason: reason})
	if err != nil {
		return 0, err
	}
	if s.log != nil {
		s.log.Debug("rejection history updated", "new_entries", 1, "recipient_count", len(normalizedRecipients), "entry_count", s.db.Size())
	}
	if len(added) != 1 {
		return 0, nil
	}
	return added[0].ID, nil
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
	result := s.db.View(func(entry rejectionHistoryEntry) bool {
		return allRecipients || slices.Contains(entry.Recipients, recipient)
	})
	if !allRecipients {
		for i := range result {
			// Do not disclose other recipients of the same rejected message to a
			// normal user querying only their own rejection history.
			result[i].Recipients = []string{recipient}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].RejectedAt.After(result[j].RejectedAt)
	})
	return result
}

func (s *rejectionHistoryStore) load() error {
	changed, err := s.db.Load(func(version int) bool { return version == rejectionHistoryVersion }, func(entry rejectionHistoryEntry) (rejectionHistoryEntry, bool, bool) {
		entry.Sender = normalizeEmailAddress(entry.Sender)
		unique := make(map[string]bool)
		for _, recipient := range entry.Recipients {
			if normalized := normalizeEmailAddress(recipient); normalized != "" {
				unique[normalized] = true
			}
		}
		entry.Recipients = entry.Recipients[:0]
		for recipient := range unique {
			entry.Recipients = append(entry.Recipients, recipient)
		}
		sort.Strings(entry.Recipients)
		return entry, entry.Sender != "" && len(entry.Recipients) > 0 && !entry.RejectedAt.IsZero(), false
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
