package milter

func (s *correspondentStore) load() error {
	changed, err := s.db.load(func(version int) bool {
		return version == legacyCorrespondentFileVersion || version == correspondentFileVersion
	}, func(entry correspondentEntry) (correspondentEntry, bool, bool) {
		modified := false
		entry.Correspondent = normalizeEmailAddress(entry.Correspondent)
		entry.LocalAddress = normalizeEmailAddress(entry.LocalAddress)
		if entry.Correspondent == "" || entry.LocalAddress == "" {
			return entry, false, true
		}
		if entry.LastActivityAt.IsZero() {
			entry.LastActivityAt = entry.LearnedAt
			modified = true
		}
		if entry.WhitelistType == "" {
			entry.WhitelistType = whitelistAuthenticatedOutbound
			modified = true
		}
		if entry.WhitelistType != whitelistAuthenticatedOutbound && entry.WhitelistType != whitelistRepeatedLegitimate && entry.WhitelistType != whitelistManual {
			return entry, false, true
		}
		if (entry.WhitelistType == whitelistAuthenticatedOutbound || entry.WhitelistType == whitelistManual) && entry.LegitimateEmailCount != 0 {
			entry.LegitimateEmailCount = 0
			modified = true
		}
		entry.PersistedActivityAt = entry.LastActivityAt
		return entry, true, modified
	})
	if err != nil {
		return err
	}
	if changed {
		return s.saveLocked()
	}
	return nil
}

func (s *correspondentStore) saveLocked() error {
	return s.db.changedLocked(1)
}

func (s *correspondentStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.db.setDeferred(true)
}

func (s *correspondentStore) flush() error {
	if s == nil {
		return nil
	}
	_, err := s.db.flush()
	return err
}
