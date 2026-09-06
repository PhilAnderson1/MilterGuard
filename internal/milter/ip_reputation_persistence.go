package milter

import (
	"net/netip"
	"time"
)

func (s *ipReputationStore) load() error {
	now := s.now().UTC()
	_, err := s.db.load(func(version int) bool { return version == rejectedIPFileVersion }, func(record rejectedIPRecord) (rejectedIPRecord, bool, bool) {
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

func (s *ipReputationStore) saveOrLogLocked() {
	if err := s.saveLocked(); err != nil && s.log != nil {
		s.log.Error("cannot save rejected IP state", "file", s.stateFile, "error", err)
	}
}

func (s *ipReputationStore) saveLocked() error {
	return s.db.changedLocked(1)
}

func (s *ipReputationStore) enableDeferredPersistence() {
	if s == nil {
		return
	}
	s.db.setDeferred(true)
}

func (s *ipReputationStore) flush() error {
	if s == nil {
		return nil
	}
	_, err := s.db.flush()
	return err
}
