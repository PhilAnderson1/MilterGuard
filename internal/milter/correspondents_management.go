package milter

import (
	"fmt"
	"os"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

// AddManualCorrespondent adds an immediately qualified relationship. The
// caller must ensure the running daemon is stopped while editing its database.
func AddManualCorrespondent(cfg config.CorrespondentsConfig, sender, recipient string) (bool, error) {
	store, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return false, err
	}
	return store.addManual(sender, recipient)
}

func (store *correspondentStore) addManual(sender, recipient string) (bool, error) {
	sender = normalizeEmailAddress(sender)
	recipient = normalizeEmailAddress(recipient)
	if sender == "" || recipient == "" {
		return false, fmt.Errorf("sender and recipient must be valid email addresses")
	}
	now := store.now().UTC()
	key := store.key(recipient, sender)
	existed := false
	err := store.db.Update(func(records map[string]correspondentEntry) (reads, writes, deletes uint64, changed bool) {
		entry, found := records[key]
		existed = found
		if found {
			reads++
		} else {
			entry = correspondentEntry{LocalAddress: recipient, Correspondent: sender, LearnedAt: now}
		}
		entry.LastActivityAt = now
		entry.WhitelistType = whitelistManual
		entry.LegitimateEmailCount = 0
		records[key] = entry
		return reads, 1, 0, true
	})
	if err != nil {
		return false, err
	}
	return !existed, nil
}

// DeleteCorrespondents deletes an exact relationship, or every relationship
// for sender when recipient is "*". Explicit deletion applies to all types.
func DeleteCorrespondents(cfg config.CorrespondentsConfig, sender, recipient string) (int, error) {
	store, err := openCorrespondentStoreForManagement(cfg)
	if err != nil {
		return 0, err
	}
	return store.deleteManual(sender, recipient)
}

func (store *correspondentStore) deleteManual(sender, recipient string) (int, error) {
	sender = normalizeEmailAddress(sender)
	if sender == "" {
		return 0, fmt.Errorf("sender must be a valid email address")
	}
	allRecipients := recipient == "*"
	if !allRecipients {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return 0, fmt.Errorf("recipient must be a valid email address or *")
		}
	}
	removed := 0
	err := store.db.Update(func(records map[string]correspondentEntry) (reads, writes, deletes uint64, changed bool) {
		for key, entry := range records {
			if entry.Correspondent == sender && (allRecipients || entry.LocalAddress == recipient) {
				delete(records, key)
				removed++
			}
		}
		return 0, 0, uint64(removed), removed > 0
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}

func openCorrespondentStoreForManagement(cfg config.CorrespondentsConfig) (*correspondentStore, error) {
	store := newEmptyCorrespondentStore(cfg, nil)
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return store, nil
}
