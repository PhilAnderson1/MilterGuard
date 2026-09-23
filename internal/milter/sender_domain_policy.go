package milter

import (
	"context"
	"net/mail"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const authenticatedOnlySenderDomainSource = "authenticated_only_sender_domain"

func (ss *session) applyAuthenticatedOnlySenderDomain(ctx context.Context) (bool, bool) {
	if ss.authentication.Authenticated {
		return false, true
	}
	domain := authenticatedOnlyFromDomain(ss.message, ss.deps.filtering.AuthenticatedOnlySenderDomains)
	if domain == "" {
		return false, true
	}
	return true, ss.finishAuthenticatedOnlySenderDomain(ctx, domain)
}

func authenticatedOnlyFromDomain(msg *message.Message, configured []string) string {
	for _, value := range msg.Headers["from"] {
		addresses, err := mail.ParseAddressList(value)
		if err != nil {
			addresses = recoverFromAddresses(value)
		}
		for _, address := range addresses {
			if domain := allowedSenderDomain(emailAddressDomain(address.Address), configured); domain != "" {
				return domain
			}
		}
	}
	return ""
}

// recoverFromAddresses preserves individually usable mailboxes when malformed
// junk causes net/mail to reject an otherwise useful address list. The normal
// parser always runs first, so splitting cannot alter valid quoted display
// names or comments. Each recovered fragment must still parse as a mailbox;
// raw protected-domain text is never treated as an address.
func recoverFromAddresses(value string) []*mail.Address {
	fragments := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' })
	addresses := make([]*mail.Address, 0, len(fragments))
	for _, fragment := range fragments {
		fragment = strings.TrimSpace(fragment)
		if fragment == "" {
			continue
		}
		if address, err := mail.ParseAddress(fragment); err == nil && address.Address != "" {
			addresses = append(addresses, address)
			continue
		}
		if mailbox, ok := mailaddr.Mailbox(fragment); ok {
			addresses = append(addresses, &mail.Address{Address: mailbox})
		}
	}
	return addresses
}

func (ss *session) finishAuthenticatedOnlySenderDomain(ctx context.Context, domain string) bool {
	selected := selectActionForMode(actionReject, ss.deps.mode)

	var err error
	if selected == actionAccept {
		if ss.deps.filtering.AddEmailHeaders || ss.deps.mode == "tag" {
			err = ss.writeTagHeaders("unwanted", nil, acceptedModeLabel(ss.deps.mode))
		} else {
			err = ss.writeAcceptedResultHeaders(nil)
		}
	}
	if err == nil {
		err = writeFrame(ss.conn, responseForAction(selected, ss.deps.filtering.RejectMessage))
	}

	reason := "Visible From domain " + domain + " may only be used by authenticated SMTP submissions"
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.deps.mode,
		"sender_domain", domain,
		"proposed_action", actionReject.String(),
		"actual_action", selected.String(),
		"source", authenticatedOnlySenderDomainSource,
		"response_sent", err == nil,
	}
	attrs = ss.appendDecisionSubject(attrs)
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "authenticated-only sender domain policy response failed", attrs...)
		return false
	}
	ss.deps.log.InfoContext(ctx, "authenticated-only sender domain policy decision", attrs...)
	if selected == actionReject {
		persistCtx, cancel := postDecisionContext(ctx)
		ss.deps.policy.recordRejection(persistCtx, ss.message, ss.visibleSender, ss.envelopeSender, ss.envelopeRecipients, []string{reason}, authenticatedOnlySenderDomainSource)
		cancel()
		// DNS can take the full wait budget, so keep it separate from the
		// subsequent reputation write's persistence deadline.
		dnsCtx, cancelDNS := postDecisionContext(ctx)
		dns := ss.awaitConnectionDNS(dnsCtx)
		cancelDNS()
		strikeCtx, cancelStrike := postDecisionContext(ctx)
		ss.deps.policy.ipReputation.add(strikeCtx, ss.peerIP, dns)
		cancelStrike()
	}
	ss.resetMessage(phaseConnection)
	return true
}
