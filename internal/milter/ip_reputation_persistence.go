package milter

import (
	"net/netip"
	"time"
)

func (s *ipReputationStore) load() error {
	now := s.now().UTC()
	_, err := s.db.Load(func(version int) bool { return version == rejectedIPFileVersion }, func(record rejectedIPRecord) (rejectedIPRecord, bool, bool) {
		addr, err := netip.ParseAddr(record.IP)
		if err != nil {
			return record, false, true
		}
		addr = addr.Unmap()
		changed := record.IP != addr.String()
		record.IP, record.Strikes = addr.String(), s.pruneStrikes(record.Strikes, now)
		if len(record.Strikes) > s.repeatThreshold {
			record.Strikes = record.Strikes[len(record.Strikes)-s.repeatThreshold:]
		}
		if record.BlockLevel == rejectedIPBlockRepeat && !record.BlockedUntil.After(now) {
			return record, false, true
		}
		if record.BlockLevel == rejectedIPBlockShort && !record.BlockedUntil.After(now) {
			record.BlockLevel, record.BlockedUntil = "", time.Time{}
		}
		if record.BlockLevel != "" && record.BlockLevel != rejectedIPBlockShort && record.BlockLevel != rejectedIPBlockRepeat {
			return record, false, true
		}
		if record.BlockLevel == "" && len(record.Strikes) == 0 {
			return record, false, true
		}
		record.PersistedRefreshAt = now
		return record, true, changed
	})
	return err
}

func (s *ipReputationStore) saveOrLogLocked(writes, deletes int) {
	if err := s.saveLocked(writes, deletes); err != nil && s.log != nil {
		s.log.Error("cannot save rejected IP state", "file", s.stateFile, "error", err)
	}
}

func (s *ipReputationStore) saveLocked(writes, deletes int) error {
	return s.db.ChangedLocked(uint64(writes), uint64(deletes))
}

func (s *ipReputationStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.db.SetDeferred(true)
}

func (s *ipReputationStore) flush() error {
	if s == nil {
		return nil
	}
	_, err := s.db.Flush()
	return err
}
