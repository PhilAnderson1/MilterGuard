package milter

func (s *correspondentStore) load() error {
	changed, err := s.db.Load(func(version int) bool {
		return version == correspondentFileVersion
	}, func(entry correspondentEntry) (correspondentEntry, bool, bool) {
		modified := false
		entry.Correspondent = normalizeEmailAddress(entry.Correspondent)
		entry.LocalAddress = normalizeEmailAddress(entry.LocalAddress)
		if entry.Correspondent == "" || entry.LocalAddress == "" {
			return entry, false, true
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
		_, err = s.db.Flush()
		return err
	}
	return nil
}
