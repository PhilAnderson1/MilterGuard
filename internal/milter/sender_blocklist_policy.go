package milter

import (
	"context"
	"net/mail"
	"slices"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const senderBlocklistReason = "Visible sender matched manual recipient blocklist"
const maxSenderBlockAddresses = 100

type pendingSenderBlocklist struct {
	blockedRecipients   []string
	remainingRecipients []string
	matchedSender       string
	matchedKind         stores.SenderBlockKind
}

func strictVisibleFromMailboxes(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		addresses, err := mail.ParseAddressList(value)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if normalized := mailaddr.Normalize(address.Address); normalized != "" {
				seen[normalized] = true
			}
		}
	}
	mailboxes := make([]string, 0, len(seen))
	for mailbox := range seen {
		mailboxes = append(mailboxes, mailbox)
	}
	slices.Sort(mailboxes)
	return mailboxes
}

func normalizedRecipients(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		if normalized := mailaddr.Normalize(value); normalized != "" {
			seen[normalized] = true
		}
	}
	recipients := make([]string, 0, len(seen))
	for recipient := range seen {
		recipients = append(recipients, recipient)
	}
	slices.Sort(recipients)
	return recipients
}

func senderBlockKindName(kind stores.SenderBlockKind) string {
	if kind == stores.SenderBlockExactMailbox {
		return "exact_mailbox"
	}
	return "domain"
}

func (ss *session) applySenderBlocklist(ctx context.Context) (bool, bool) {
	if ss.authentication.Authenticated || ss.deps.policy.senderBlocklist == nil {
		return false, true
	}
	mailboxes := normalizedRecipients(ss.senderBlocklistFrom)
	if len(mailboxes) == 0 {
		return false, true
	}
	if ss.senderBlocklistFromTruncated {
		ss.deps.log.WarnContext(ctx, "sender blocklist not enforced because the visible sender set exceeded its safety limit",
			"message_id", ss.message.Header("Message-ID"), "sender_limit", maxSenderBlockAddresses)
		return false, true
	}
	if !ss.recipientSetComplete() {
		ss.deps.log.WarnContext(ctx, "sender blocklist not enforced because the SMTP recipient set is incomplete",
			"message_id", ss.message.Header("Message-ID"))
		return false, true
	}
	recipients := normalizedRecipients(ss.envelopeRecipients)
	match, err := ss.deps.policy.senderBlocklist.MatchSenderBlocks(ctx, stores.SenderBlockMatchQuery{
		VisibleSenders: mailboxes, Recipients: recipients,
		IncludeSubdomains: ss.deps.policy.senderBlocklistCfg.IncludeSubdomains,
	})
	if err != nil {
		ss.deps.log.ErrorContext(ctx, "sender blocklist lookup failed; continuing normal message processing", "error", err)
		return false, true
	}
	if len(match.BlockedRecipients) == 0 {
		return false, true
	}
	blocked := make(map[string]bool, len(match.BlockedRecipients))
	for _, recipient := range match.BlockedRecipients {
		blocked[recipient] = true
	}
	remaining := make([]string, 0, len(recipients)-len(blocked))
	for _, recipient := range recipients {
		if !blocked[recipient] {
			remaining = append(remaining, recipient)
		}
	}
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"), "mode", ss.deps.mode,
		"matched_sender", match.MatchedSender, "match_kind", senderBlockKindName(match.MatchedKind),
		"affected_recipient_count", len(match.BlockedRecipients), "proposed_action", actionReject.String(),
	}
	attrs = ss.appendDecisionSubject(attrs)
	if ss.deps.mode != "enforce" {
		attrs = append(attrs, "actual_action", "continue", "result", "monitor_only")
		ss.deps.log.InfoContext(ctx, "sender blocklist policy decision", attrs...)
		return false, true
	}
	if len(remaining) == 0 {
		err := writeFrame(ss.conn, responseForAction(actionReject, ss.deps.policy.senderBlocklistCfg.RejectMessage))
		attrs = append(attrs, "actual_action", actionReject.String(), "result", "full_rejection", "response_sent", err == nil)
		if err != nil {
			attrs = append(attrs, "response_error", err)
			ss.deps.log.ErrorContext(ctx, "sender blocklist policy response failed", attrs...)
			return true, false
		}
		ss.deps.log.InfoContext(ctx, "sender blocklist policy decision", attrs...)
		persistCtx, cancel := postDecisionContext(ctx)
		ss.deps.policy.recordRejection(persistCtx, ss.message, match.MatchedSender, ss.envelopeSender,
			match.BlockedRecipients, []string{senderBlocklistReason}, "sender_blocklist")
		cancel()
		ss.deps.activity.recordSenderBlocklist(ctx, stores.ActivityOutcomeRejected, 1)
		ss.resetMessage(phaseConnection)
		return true, true
	}
	if ss.negotiatedActions&actionDeleteRecipient == 0 {
		attrs = append(attrs, "actual_action", "continue", "result", "not_enforced", "reason", "delete-recipient capability unavailable")
		ss.deps.log.WarnContext(ctx, "sender blocklist could not remove selected recipients; continuing with all recipients", attrs...)
		return false, true
	}
	ss.pendingSenderBlocks = &pendingSenderBlocklist{
		blockedRecipients: append([]string(nil), match.BlockedRecipients...), remainingRecipients: remaining,
		matchedSender: match.MatchedSender, matchedKind: match.MatchedKind,
	}
	ss.deps.log.DebugContext(ctx, "sender blocklist recipient removal deferred until final message acceptance",
		append(attrs, "actual_action", "pending_recipient_removal", "remaining_recipient_count", len(remaining))...)
	return false, true
}

func (ss *session) writePolicyResponse(selected action, rejectMessage string) error {
	if selected == actionAccept && ss.pendingSenderBlocks != nil {
		for _, recipient := range ss.pendingSenderBlocks.blockedRecipients {
			if err := writeFrame(ss.conn, deleteRecipientResponse(recipient)); err != nil {
				return err
			}
		}
	}
	return writeFrame(ss.conn, responseForAction(selected, rejectMessage))
}

func (ss *session) completeSenderBlocklistRemoval(ctx context.Context) {
	pending := ss.pendingSenderBlocks
	if pending == nil {
		return
	}
	ss.deps.log.InfoContext(ctx, "sender blocklist policy decision",
		"message_id", ss.message.Header("Message-ID"), "mode", ss.deps.mode,
		"matched_sender", pending.matchedSender, "match_kind", senderBlockKindName(pending.matchedKind),
		"affected_recipient_count", len(pending.blockedRecipients), "proposed_action", actionReject.String(),
		"actual_action", "remove_recipient", "result", "partial_recipient_removal")
	persistCtx, cancel := postDecisionContext(ctx)
	ss.deps.policy.recordRejection(persistCtx, ss.message, pending.matchedSender, ss.envelopeSender,
		pending.blockedRecipients, []string{senderBlocklistReason}, "sender_blocklist")
	cancel()
	ss.deps.activity.recordSenderBlocklist(ctx, stores.ActivityOutcomeAccepted, len(pending.blockedRecipients))
}
