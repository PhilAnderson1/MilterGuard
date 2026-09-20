package milter

import (
	"context"
	"database/sql"
	"net/netip"
)

func (s *correspondentStore) snapshot() map[string]correspondentEntry {
	result := make(map[string]correspondentEntry)
	if s == nil || s.db == nil {
		return result
	}
	rows, err := s.db.Query(context.Background(), `SELECT id, local_address, correspondent,
		learned_at_ms, last_activity_at_ms, whitelist_type, legitimate_email_count FROM correspondents`)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		entry, err := scanCorrespondent(rows)
		if err != nil {
			return result
		}
		result[entry.LocalAddress+"\x00"+entry.Correspondent] = entry
	}
	if rows.Err() != nil {
		return map[string]correspondentEntry{}
	}
	return result
}

func (s *ipReputationStore) snapshot() map[netip.Addr]rejectedIPRecord {
	result := map[netip.Addr]rejectedIPRecord{}
	if s == nil || s.db == nil {
		return result
	}
	rows, err := s.db.Query(context.Background(), `SELECT id,ip,block_level,blocked_until_ms,legitimate_count,last_activity_at_ms FROM ip_reputation`)
	if err != nil {
		return result
	}
	for rows.Next() {
		var r rejectedIPRecord
		var id, activity int64
		var level sql.NullString
		var blocked sql.NullInt64
		if rows.Scan(&id, &r.IP, &level, &blocked, &r.LegitimateCount, &activity) != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		r.ID, r.BlockLevel, r.LastActivityAt = uint64(id), level.String, timeFromMillis(activity)
		if blocked.Valid {
			r.BlockedUntil = timeFromMillis(blocked.Int64)
		}
		addr, err := netip.ParseAddr(r.IP)
		if err != nil {
			rows.Close()
			return map[netip.Addr]rejectedIPRecord{}
		}
		result[addr] = r
	}
	rows.Close()
	for addr, record := range result {
		strikeRows, err := s.db.Query(context.Background(), `SELECT struck_at_ms FROM ip_strikes WHERE ip_reputation_id=? ORDER BY struck_at_ms,id`, record.ID)
		if err != nil {
			return map[netip.Addr]rejectedIPRecord{}
		}
		for strikeRows.Next() {
			var milliseconds int64
			if strikeRows.Scan(&milliseconds) != nil {
				strikeRows.Close()
				return map[netip.Addr]rejectedIPRecord{}
			}
			record.Strikes = append(record.Strikes, timeFromMillis(milliseconds))
		}
		strikeRows.Close()
		result[addr] = record
	}
	return result
}

func (ss *session) executeEmailCommand(command emailCommand, admin bool) (commandResult, error) {
	return ss.server.commands.execute(context.Background(), command, CommandActor{Administrator: admin, DefaultRecipient: ss.envelopeSender})
}
