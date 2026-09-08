package milter

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/netip"
	"net/smtp"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type emailCommand struct {
	kind      string
	verb      string
	sender    string
	recipient string
	canonical string
	ip        netip.Addr
}

func (ss *session) isCommandRecipient(recipient string) bool {
	return ss.server.cfg.EmailCommands.Enabled && normalizeEmailAddress(recipient) == normalizeEmailAddress(ss.server.cfg.EmailCommands.Recipient)
}

func (ss *session) commandIdentityAuthorization() (bool, string) {
	if !ss.authentication.Authenticated {
		return false, "SMTP authentication is required"
	}
	if ss.isCommandAdministrator(ss.authentication.Identity) {
		return true, ""
	}
	cfg := ss.server.cfg.EmailCommands
	if !cfg.AllowAuthenticatedUsers {
		return false, "this authenticated user is not authorized to use email commands"
	}
	if cfg.VerifySenderViaAliases {
		if err := senderOwnedViaAliases(cfg.AliasesFile, ss.envelopeSender, ss.authentication.Identity, cfg.Recipient); err != nil {
			return false, "the envelope sender is not owned by the authenticated user"
		}
	}
	return true, ""
}

func (ss *session) isInternalMessage() bool {
	marker := strings.TrimSpace(ss.message.Header("X-MilterGuard-Internal"))
	return marker != "" && marker == ss.server.internalToken &&
		(!ss.peerIP.IsValid() || ss.peerIP.IsLoopback() || !connectionAddressRoutable(ss.peerIP))
}

func (ss *session) handleEmailCommand(ctx context.Context) (bool, bool) {
	cfg := ss.server.cfg.EmailCommands
	if !cfg.Enabled {
		return false, true
	}
	commandRecipient := normalizeEmailAddress(cfg.Recipient)
	hasCommandRecipient := false
	for _, recipient := range ss.envelopeRecipients {
		if normalizeEmailAddress(recipient) == commandRecipient {
			hasCommandRecipient = true
		}
	}
	if !hasCommandRecipient {
		return false, true
	}
	if len(ss.envelopeRecipients) != 1 || ss.envelopeRecipientsTruncated {
		return true, ss.rejectEmailCommand(ctx, "command address must be the sole recipient", false)
	}
	if !ss.authentication.Authenticated {
		return true, ss.rejectEmailCommand(ctx, "authentication required", false)
	}

	identity := strings.TrimSpace(ss.authentication.Identity)
	admin := false
	for _, configured := range cfg.Administrators {
		if strings.EqualFold(strings.TrimSpace(configured), identity) {
			admin = true
			break
		}
	}
	if !admin && !cfg.AllowAuthenticatedUsers {
		return true, ss.rejectEmailCommand(ctx, "authenticated user is not authorized", false)
	}
	if !admin && cfg.VerifySenderViaAliases {
		if err := senderOwnedViaAliases(cfg.AliasesFile, ss.envelopeSender, identity, cfg.Recipient); err != nil {
			ss.server.log.WarnContext(ctx, "email command sender ownership verification failed", "authenticated_identity", identity, "envelope_sender", ss.envelopeSender, "error", err)
			return true, ss.rejectEmailCommand(ctx, "envelope sender is not owned by the authenticated user", false)
		}
	}
	replyTo := normalizeEmailAddress(ss.envelopeSender)
	if replyTo == "" {
		return true, ss.rejectEmailCommand(ctx, "authenticated envelope sender is invalid", false)
	}

	text, err := commandMessageText(ss.message, cfg.MaxMessageBytes)
	if err != nil {
		return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, err.Error())
	}
	command, help, err := parseEmailCommand(text, replyTo, admin)
	if err != nil {
		return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, err.Error())
	}
	if help {
		queued := ss.queueCommandReply(replyTo, "MilterGuard command help", commandHelp(admin))
		return true, ss.discardEmailCommand(ctx, identity, "HELP", "help sent", replyTo, "", queued)
	}
	if command.kind == "rejections" {
		entries := ss.server.rejectionHistory.list(command.recipient)
		body := formatRejectionHistory(entries)
		queued := ss.queueCommandReply(replyTo, "MilterGuard rejection history", body)
		outcome := fmt.Sprintf("listed %d rejection entries", len(entries))
		return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, "", command.recipient, queued)
	}
	if command.kind == "whitelist_list" {
		entries := ss.server.correspondents.listAllowlist(command.recipient)
		body := formatAllowlist(entries, includeAllowlistRecipient(admin, command.recipient))
		queued := ss.queueCommandReply(replyTo, "MilterGuard correspondent allowlist", body)
		outcome := fmt.Sprintf("listed %d allowlist entries", len(entries))
		return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, "", command.recipient, queued)
	}
	if command.kind == "ip_list" || command.kind == "ip_list_lookup" {
		entries := ss.server.ipReputation.listActive()
		lookup := command.kind == "ip_list_lookup"
		var queued bool
		if lookup {
			queued = ss.queueCommandReplyFunc(replyTo, "MilterGuard active IP blocks", func() string {
				return formatActiveIPBlocks(ss.server.resolveActiveIPHostnames(context.Background(), entries), true)
			})
		} else {
			queued = ss.queueCommandReply(replyTo, "MilterGuard active IP blocks", formatActiveIPBlocks(entries, false))
		}
		outcome := fmt.Sprintf("listed %d active IP blocks", len(entries))
		return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, "", "", queued)
	}
	if command.kind == "ip_add" {
		block, operationErr := ss.server.ipReputation.manualAdd(command.ip)
		if operationErr != nil {
			return true, ss.completeFailedEmailCommand(ctx, identity, replyTo, command, operationErr)
		}
		outcome := fmt.Sprintf("blocked %s until %s", block.IP, block.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		queued := ss.queueCommandReply(replyTo, "MilterGuard command completed", command.canonical+"\n\n"+outcome+".\n")
		return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, "", "", queued)
	}
	if command.kind == "ip_delete" {
		removed, operationErr := ss.server.ipReputation.manualDelete(command.ip)
		if operationErr != nil {
			return true, ss.completeFailedEmailCommand(ctx, identity, replyTo, command, operationErr)
		}
		outcome := "IP address was not present"
		if removed {
			outcome = "IP reputation record deleted"
		}
		queued := ss.queueCommandReply(replyTo, "MilterGuard command completed", command.canonical+"\n\n"+outcome+".\n")
		return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, "", "", queued)
	}

	var outcome string
	if command.verb == "ADD" {
		created, operationErr := ss.server.correspondents.addManual(command.sender, command.recipient)
		if operationErr != nil {
			return true, ss.completeFailedEmailCommand(ctx, identity, replyTo, command, operationErr)
		}
		if created {
			outcome = "allowlist entry added"
		} else {
			outcome = "allowlist entry already existed and was refreshed"
		}
	} else {
		removed, operationErr := ss.server.correspondents.deleteManual(command.sender, command.recipient)
		if operationErr != nil {
			return true, ss.completeFailedEmailCommand(ctx, identity, replyTo, command, operationErr)
		}
		outcome = fmt.Sprintf("removed %d allowlist entries", removed)
	}
	queued := ss.queueCommandReply(replyTo, "MilterGuard command completed", command.canonical+"\n\n"+outcome+".\n")
	return true, ss.discardEmailCommand(ctx, identity, command.canonical, outcome, command.sender, command.recipient, queued)
}

func commandMessageText(m *message.Message, maxBytes int64) (string, error) {
	if m.BodyTruncated || m.RetainedBytes() > maxBytes {
		return "", fmt.Errorf("command message is too large")
	}
	if strings.TrimSpace(m.Header("Content-Disposition")) != "" {
		return "", fmt.Errorf("attachments are not allowed")
	}
	mediaType := "text/plain"
	if value := strings.TrimSpace(m.Header("Content-Type")); value != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(value)
		if err != nil {
			return "", fmt.Errorf("invalid Content-Type")
		}
	}
	if mediaType != "text/plain" && mediaType != "text/html" && mediaType != "multipart/alternative" {
		return "", fmt.Errorf("command email must contain plain text or HTML without attachments")
	}
	text := m.CommandText()
	if strings.ContainsRune(text, '\x00') {
		return "", fmt.Errorf("command body contains invalid characters")
	}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line, nil
		}
	}
	return "", fmt.Errorf("command body is empty")
}

func parseEmailCommand(text, authenticatedSender string, admin bool) (emailCommand, bool, error) {
	fields := strings.Fields(text)
	if len(fields) == 1 && strings.EqualFold(fields[0], "HELP") {
		return emailCommand{}, true, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "IP") {
		if !admin {
			return emailCommand{}, false, fmt.Errorf("IP commands are restricted to administrators")
		}
		if len(fields) == 2 && strings.EqualFold(fields[1], "LIST") {
			return emailCommand{kind: "ip_list", canonical: "IP LIST"}, false, nil
		}
		if len(fields) == 3 && strings.EqualFold(fields[1], "LIST") && strings.EqualFold(fields[2], "LOOKUP") {
			return emailCommand{kind: "ip_list_lookup", canonical: "IP LIST LOOKUP"}, false, nil
		}
		if len(fields) != 3 || (!strings.EqualFold(fields[1], "ADD") && !strings.EqualFold(fields[1], "DELETE")) {
			return emailCommand{}, false, fmt.Errorf("IP command must be IP LIST, IP LIST LOOKUP, IP ADD address, or IP DELETE address")
		}
		addr, err := netip.ParseAddr(fields[2])
		if err != nil {
			return emailCommand{}, false, fmt.Errorf("IP command requires a valid IPv4 or IPv6 address")
		}
		addr = canonicalIP(addr)
		verb := strings.ToUpper(fields[1])
		return emailCommand{kind: "ip_" + strings.ToLower(verb), canonical: "IP " + verb + " " + addr.String(), ip: addr}, false, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "REJECTIONS") {
		if len(fields) > 2 {
			return emailCommand{}, false, fmt.Errorf("REJECTIONS accepts at most one recipient")
		}
		recipient := authenticatedSender
		if len(fields) == 2 {
			recipient = fields[1]
			if recipient == "*" {
				if !admin {
					return emailCommand{}, false, fmt.Errorf("wildcard rejection history is restricted to administrators")
				}
			} else {
				recipient = normalizeEmailAddress(recipient)
				if recipient == "" {
					return emailCommand{}, false, fmt.Errorf("rejection-history recipient must be a valid email address")
				}
				if !admin && recipient != authenticatedSender {
					return emailCommand{}, false, fmt.Errorf("users may view only their own rejection history")
				}
			}
		}
		canonical := "REJECTIONS"
		if len(fields) == 2 {
			canonical += " " + recipient
		}
		return emailCommand{kind: "rejections", recipient: recipient, canonical: canonical}, false, nil
	}
	if len(fields) >= 2 && strings.EqualFold(fields[0], "WHITELIST") && strings.EqualFold(fields[1], "LIST") {
		if len(fields) > 3 {
			return emailCommand{}, false, fmt.Errorf("WHITELIST LIST accepts at most one recipient")
		}
		recipient := authenticatedSender
		if len(fields) == 3 {
			recipient = fields[2]
			if recipient == "*" {
				if !admin {
					return emailCommand{}, false, fmt.Errorf("wildcard allowlist listing is restricted to administrators")
				}
			} else {
				recipient = normalizeEmailAddress(recipient)
				if recipient == "" {
					return emailCommand{}, false, fmt.Errorf("allowlist recipient must be a valid email address")
				}
				if !admin && recipient != authenticatedSender {
					return emailCommand{}, false, fmt.Errorf("users may view only their own allowlist")
				}
			}
		}
		canonical := "WHITELIST LIST"
		if len(fields) == 3 {
			canonical += " " + recipient
		}
		return emailCommand{kind: "whitelist_list", recipient: recipient, canonical: canonical}, false, nil
	}
	if len(fields) != 3 && len(fields) != 4 {
		return emailCommand{}, false, fmt.Errorf("invalid command; send HELP for syntax")
	}
	if !strings.EqualFold(fields[0], "WHITELIST") {
		return emailCommand{}, false, fmt.Errorf("unknown command; send HELP for syntax")
	}
	verb := strings.ToUpper(fields[1])
	if verb != "ADD" && verb != "DELETE" {
		return emailCommand{}, false, fmt.Errorf("operation must be ADD or DELETE")
	}
	sender := normalizeEmailAddress(fields[2])
	if sender == "" {
		return emailCommand{}, false, fmt.Errorf("sender must be a valid email address")
	}
	recipient := authenticatedSender
	if len(fields) == 4 {
		recipient = fields[3]
	}
	if recipient == "*" {
		if !admin || verb != "DELETE" {
			return emailCommand{}, false, fmt.Errorf("wildcard deletion is restricted to administrators")
		}
	} else {
		recipient = normalizeEmailAddress(recipient)
		if recipient == "" {
			return emailCommand{}, false, fmt.Errorf("recipient must be a valid email address")
		}
		if !admin && recipient != authenticatedSender {
			return emailCommand{}, false, fmt.Errorf("users may modify only their authenticated envelope sender address")
		}
	}
	canonical := fmt.Sprintf("WHITELIST %s %s %s", verb, sender, recipient)
	return emailCommand{kind: "whitelist", verb: verb, sender: sender, recipient: recipient, canonical: canonical}, false, nil
}

func commandHelp(admin bool) string {
	text := "Send one command on the first visible line:\n\nWHITELIST ADD sender@example.com\nWHITELIST DELETE sender@example.com\nWHITELIST LIST\nREJECTIONS\nHELP\n\nThe local address is taken from your authenticated envelope sender.\n"
	if admin {
		text += "\nAdministrator commands:\nIP LIST\nIP LIST LOOKUP\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\n\nAdministrators may append a local recipient address to whitelist commands. They may use * with WHITELIST DELETE or REJECTIONS.\n"
	}
	return text
}

func formatAllowlist(entries []correspondentEntry, includeRecipient bool) string {
	if len(entries) == 0 {
		return "No whitelisted correspondent addresses were found.\n"
	}
	var body strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&body, "Sender: %s\n", entry.Correspondent)
		if includeRecipient {
			fmt.Fprintf(&body, "Recipient: %s\n", entry.LocalAddress)
		}
		fmt.Fprintf(&body, "Added: %s\n\n", allowlistAddedDescription(entry.WhitelistType))
	}
	return body.String()
}

func includeAllowlistRecipient(admin bool, recipient string) bool {
	return admin && recipient == "*"
}

func allowlistAddedDescription(whitelistType string) string {
	switch whitelistType {
	case whitelistManual:
		return "manually"
	case whitelistAuthenticatedOutbound:
		return "learned from authenticated outbound email"
	case whitelistRepeatedLegitimate:
		return "learned from repeated legitimate inbound emails"
	default:
		return "unknown"
	}
}

func formatActiveIPBlocks(entries []activeIPBlock, includeHostname bool) string {
	if len(entries) == 0 {
		return "No active IP blocks were found.\n"
	}
	var body strings.Builder
	for _, entry := range entries {
		if includeHostname {
			hostname := entry.Hostname
			if hostname == "" {
				hostname = "not found"
			}
			fmt.Fprintf(&body, "IP: %s (%s) Type: %s Expires: %s\n", entry.IP, hostname, entry.Level, entry.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		} else {
			fmt.Fprintf(&body, "IP: %s Type: %s Expires: %s\n", entry.IP, entry.Level, entry.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	}
	return body.String()
}

func formatRejectionHistory(entries []rejectionHistoryEntry) string {
	if len(entries) == 0 {
		return "No retained rejected-email records were found.\n"
	}
	var body strings.Builder
	for _, entry := range entries {
		reason := entry.Reason
		if reason == "" {
			reason = "Unavailable (record predates reason logging)"
		}
		fmt.Fprintf(&body, "From: %s\nTo: %s\nDate: %s\nRejection ID: %d\nReason: %s\n\n", entry.Sender, strings.Join(entry.Recipients, ", "), entry.RejectedAt.UTC().Format("2006-01-02 15:04:05 UTC"), entry.ID, reason)
	}
	return body.String()
}

func (ss *session) completeInvalidEmailCommand(ctx context.Context, identity, replyTo, reason string) bool {
	queued := ss.queueCommandReply(replyTo, "MilterGuard command rejected", reason+".\n\n"+commandHelp(ss.isCommandAdministrator(identity)))
	return ss.discardEmailCommand(ctx, identity, "invalid", reason, replyTo, "", queued)
}

func (ss *session) completeFailedEmailCommand(ctx context.Context, identity, replyTo string, command emailCommand, err error) bool {
	queued := ss.queueCommandReply(replyTo, "MilterGuard command failed", command.canonical+"\n\nThe command could not be completed. Check the server log.\n")
	ss.server.log.ErrorContext(ctx, "email command operation failed", "authenticated_identity", identity, "command", command.canonical, "error", err)
	return ss.discardEmailCommand(ctx, identity, command.canonical, "operation failed", command.sender, command.recipient, queued)
}

func (ss *session) isCommandAdministrator(identity string) bool {
	for _, configured := range ss.server.cfg.EmailCommands.Administrators {
		if strings.EqualFold(strings.TrimSpace(configured), identity) {
			return true
		}
	}
	return false
}

func (ss *session) rejectEmailCommand(ctx context.Context, reason string, replyQueued bool) bool {
	err := writeFrame(ss.conn, replyCode("550", "5.7.1", "MilterGuard command rejected: "+reason))
	ss.server.log.WarnContext(ctx, "email command rejected", "message_id", ss.message.Header("Message-ID"), "authenticated_identity", ss.authentication.Identity, "result", reason, "discarded", false, "confirmation_queued", replyQueued, "response_sent", err == nil)
	if err != nil {
		return false
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) discardEmailCommand(ctx context.Context, identity, command, result, sender, recipient string, confirmationQueued bool) bool {
	err := writeFrame(ss.conn, []byte{responseDiscard})
	attrs := []any{"message_id", ss.message.Header("Message-ID"), "authenticated_identity", identity, "command", command, "sender", sender, "recipient", recipient, "result", result, "discarded", err == nil, "confirmation_queued", confirmationQueued, "response_sent", err == nil}
	if command == "invalid" {
		ss.server.log.WarnContext(ctx, "email command processed", attrs...)
	} else {
		ss.server.log.InfoContext(ctx, "email command processed", attrs...)
	}
	if err != nil {
		return false
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) queueCommandReply(recipient, subject, body string) bool {
	return ss.queueCommandReplyFunc(recipient, subject, func() string { return body })
}

func (ss *session) queueCommandReplyFunc(recipient, subject string, body func() string) bool {
	if !ss.server.cfg.EmailCommands.SendReplies {
		return false
	}
	cfg := ss.server.cfg.EmailCommands
	token := ss.server.internalToken
	log := ss.server.log
	select {
	case ss.server.replySlots <- struct{}{}:
	default:
		log.Error("email command confirmation queue is full", "recipient", recipient)
		return false
	}
	go func() {
		defer func() { <-ss.server.replySlots }()
		from := normalizeEmailAddress(cfg.Recipient)
		date := time.Now().UTC().Format(time.RFC1123Z)
		payload := fmt.Sprintf("From: MilterGuard <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nAuto-Submitted: auto-replied\r\nX-Auto-Response-Suppress: All\r\nX-MilterGuard-Internal: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s", from, recipient, subject, date, token, body())
		err := submitSMTP(cfg.SMTPHost, recipient, []byte(payload))
		if err != nil {
			log.Error("cannot send email command confirmation", "recipient", recipient, "smtp_host", cfg.SMTPHost, "error", err)
			return
		}
		log.Debug("email command confirmation submitted", "recipient", recipient)
	}()
	return true
}

func submitSMTP(address, recipient string, payload []byte) error {
	conn, err := net.DialTimeout("tcp", address, 15*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Mail(""); err != nil {
		return err
	}
	if err := client.Rcpt(recipient); err != nil {
		return err
	}
	data, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := data.Write(payload); err != nil {
		_ = data.Close()
		return err
	}
	if err := data.Close(); err != nil {
		return err
	}
	return client.Quit()
}
