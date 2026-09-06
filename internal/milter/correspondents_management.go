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
	store.mu.Lock()
	defer store.mu.Unlock()
	before := cloneCorrespondentEntries(store.entries)
	store.removeStaleLocked(now)
	key := store.key(recipient, sender)
	entry, existed := store.entries[key]
	if !existed {
		for len(store.entries) >= store.cfg.MaxEntries {
			store.evictOldestLocked()
		}
		entry = correspondentEntry{LocalAddress: recipient, Correspondent: sender, LearnedAt: now}
	}
	entry.LastActivityAt = now
	entry.WhitelistType = whitelistManual
	entry.LegitimateEmailCount = 0
	store.entries[key] = entry
	if err := store.saveLocked(); err != nil {
		store.db.replaceLocked(before)
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
	store.mu.Lock()
	defer store.mu.Unlock()
	before := cloneCorrespondentEntries(store.entries)
	staleRemoved := store.removeStaleLocked(store.now().UTC())
	removed := 0
	for key, entry := range store.entries {
		if entry.Correspondent == sender && (allRecipients || entry.LocalAddress == recipient) {
			delete(store.entries, key)
			removed++
		}
	}
	if removed > 0 || staleRemoved > 0 {
		if err := store.saveLocked(); err != nil {
			store.db.replaceLocked(before)
			return 0, err
		}
	}
	return removed, nil
}

func cloneCorrespondentEntries(entries map[string]correspondentEntry) map[string]correspondentEntry {
	clone := make(map[string]correspondentEntry, len(entries))
	for key, entry := range entries {
		clone[key] = entry
	}
	return clone
}

func openCorrespondentStoreForManagement(cfg config.CorrespondentsConfig) (*correspondentStore, error) {
	store := newEmptyCorrespondentStore(cfg, nil)
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return store, nil
}
