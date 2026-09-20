package milter

import (
	"context"
	"net/mail"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const authenticatedOnlySenderDomainSource = "authenticated_only_sender_domain"

func (ss *session) applyAuthenticatedOnlySenderDomain(ctx context.Context) (bool, bool) {
	if ss.authentication.Authenticated {
		return false, true
	}
	domain := authenticatedOnlyFromDomain(ss.message, ss.deps.policy.filtering.AuthenticatedOnlySenderDomains)
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
		if mailbox, ok := message.MailboxAddress(fragment); ok {
			addresses = append(addresses, &mail.Address{Address: mailbox})
		}
	}
	return addresses
}

func (ss *session) finishAuthenticatedOnlySenderDomain(ctx context.Context, domain string) bool {
	selected := actionReject
	if ss.deps.policy.mode != "enforce" {
		selected = actionAccept
	}

	var err error
	if selected == actionAccept {
		if ss.deps.policy.filtering.AddEmailHeaders || ss.deps.policy.mode == "tag" {
			actionName := "accepted-monitor-mode"
			if ss.deps.policy.mode == "tag" {
				actionName = "accepted-tag-mode"
			}
			err = ss.writeTagHeaders("unwanted", nil, actionName)
		} else {
			err = ss.writeAcceptedResultHeaders(nil)
		}
	}
	if err == nil {
		response := []byte{responseAccept}
		if selected == actionReject {
			response = replyCode("550", "5.7.1", ss.deps.policy.filtering.RejectMessage)
		}
		err = writeFrame(ss.conn, response)
	}

	reason := "Visible From domain " + domain + " may only be used by authenticated SMTP submissions"
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.deps.policy.mode,
		"sender_domain", domain,
		"proposed_action", actionReject.String(),
		"actual_action", selected.String(),
		"source", authenticatedOnlySenderDomainSource,
		"response_sent", err == nil,
	}
	if ss.deps.analysis.logging.IncludeSubject {
		attrs = append(attrs, "subject", ss.message.DecodedHeader("Subject"))
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "authenticated-only sender domain policy response failed", attrs...)
		return false
	}
	ss.deps.log.InfoContext(ctx, "authenticated-only sender domain policy decision", attrs...)
	if selected == actionReject {
		ss.deps.policy.recordRejection(ctx, ss.message, ss.visibleSender, ss.envelopeSender, ss.envelopeRecipients, []string{reason}, authenticatedOnlySenderDomainSource)
		ss.deps.policy.ipReputation.add(ctx, ss.peerIP, ss.awaitConnectionDNS(ctx))
	}
	ss.resetMessage(phaseConnection)
	return true
}
