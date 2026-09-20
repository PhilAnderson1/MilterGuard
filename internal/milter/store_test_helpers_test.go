package milter

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type correspondentEntry = stores.Correspondent
type rejectionHistoryEntry = stores.Rejection
type domainRegistrationRecord = stores.DomainRegistration

const (
	whitelistAuthenticatedOutbound = stores.CorrespondentKindAuthenticatedOutbound
	whitelistRepeatedLegitimate    = stores.CorrespondentKindRepeatedLegitimateInbound
	whitelistManual                = stores.CorrespondentKindManual
	rejectedIPBlockShort           = stores.IPBlockLevelShort
	rejectedIPBlockRepeat          = stores.IPBlockLevelRepeat
)

func (s *correspondentStore) learn(ctx context.Context, local string, recipients []string) error {
	return s.LearnAuthenticated(ctx, local, recipients)
}

func (s *correspondentStore) touchInbound(ctx context.Context, correspondent string, recipients []string) error {
	return s.TouchInbound(ctx, correspondent, recipients)
}

func (s *correspondentStore) recordInboundClassification(ctx context.Context, correspondent string, recipients []string, complete bool, classification string, score, minimum float64, aligned bool) error {
	return s.RecordInboundClassification(ctx, stores.InboundClassification{Correspondent: correspondent, Recipients: recipients,
		RecipientsComplete: complete, Classification: classification, Score: score, UnwantedMinScore: minimum, DKIMAligned: aligned})
}

func (s *correspondentStore) match(ctx context.Context, correspondent string, recipients []string) stores.CorrespondentMatch {
	result, _ := s.Match(ctx, correspondent, recipients)
	return result
}

func (s *correspondentStore) listAllowlist(ctx context.Context, recipient string, since time.Time) ([]stores.Correspondent, error) {
	page, err := s.ListCorrespondents(ctx, stores.CorrespondentListQuery{Recipients: commandRecipientScope(recipient), ActiveSince: since, Limit: maxEmailCommandListRows})
	return page.Entries, err
}

func (s *correspondentStore) addManual(ctx context.Context, sender, recipient string) (bool, error) {
	return s.AddManual(ctx, sender, recipient)
}

func (s *correspondentStore) deleteManual(ctx context.Context, sender, recipient string) (int, error) {
	return s.DeleteManual(ctx, sender, commandRecipientScope(recipient))
}

func (s *correspondentStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }

func (s *rejectionHistoryStore) addWithID(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) (uint64, error) {
	return s.AddRejection(ctx, stores.NewRejection{VisibleSender: visible, EnvelopeSender: envelope, Subject: subject, Recipients: recipients, Reasons: reasons})
}
func (s *rejectionHistoryStore) add(ctx context.Context, visible, envelope, subject string, recipients, reasons []string) error {
	_, err := s.addWithID(ctx, visible, envelope, subject, recipients, reasons)
	return err
}

func (s *rejectionHistoryStore) list(ctx context.Context, recipient string, since time.Time) ([]stores.Rejection, error) {
	page, err := s.ListRejections(ctx, stores.RejectionListQuery{Recipients: commandRecipientScope(recipient), RejectedSince: since, Limit: maxEmailCommandListRows})
	return page.Entries, err
}

func (s *rejectionHistoryStore) getByID(ctx context.Context, id uint64, recipient string, admin bool) (stores.Rejection, bool, error) {
	scope := stores.RecipientScope{Address: recipient}
	if admin {
		scope = stores.RecipientScope{All: true}
	}
	return s.RejectionByID(ctx, id, scope)
}

func (s *rejectionHistoryStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }
func (s *rejectionHistoryStore) size(ctx context.Context) int {
	count, _ := s.Count(ctx)
	return count
}

func (s *ipReputationStore) recordLegitimate(ctx context.Context, addr netip.Addr) {
	_ = s.RecordLegitimate(ctx, addr)
}
func (s *ipReputationStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }
func (s *ipReputationStore) size(ctx context.Context) int {
	count, _ := s.Count(ctx)
	return count
}
func (s *ipReputationStore) manualAdd(ctx context.Context, addr netip.Addr) (stores.IPBlock, error) {
	return s.AddManualBlock(ctx, addr)
}
func (s *ipReputationStore) manualDelete(ctx context.Context, addr netip.Addr) (bool, error) {
	return s.Delete(ctx, addr)
}
func (s *ipReputationStore) listActive(ctx context.Context, since time.Time) ([]stores.IPBlock, error) {
	page, err := s.ListActiveBlocks(ctx, stores.IPBlockListQuery{ActiveSince: since, Limit: maxEmailCommandListRows})
	return page.Entries, err
}

func (s *domainRegistrationStore) get(ctx context.Context, domain string) (stores.DomainRegistration, bool, error) {
	return s.repository.DomainRegistration(ctx, domain)
}

func (s *domainRegistrationStore) put(ctx context.Context, record stores.DomainRegistration) error {
	return s.repository.PutDomainRegistration(ctx, record)
}

func (s *domainRegistrationStore) cleanup(ctx context.Context) (int64, error) { return s.Cleanup(ctx) }
func (s *domainRegistrationStore) size(ctx context.Context) int {
	count, _ := s.Count(ctx)
	return count
}

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
