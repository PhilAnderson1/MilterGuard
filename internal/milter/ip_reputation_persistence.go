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
		addr = canonicalIP(addr)
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
		return record, true, changed
	})
	return err
}
