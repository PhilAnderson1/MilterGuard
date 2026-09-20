package milter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const internalMessageHeader = "X-MilterGuard-Internal"

const (
	maxCommandsPerMessage      = 100
	maxRejectionReplyBodyRunes = 50000
	maxEmailCommandListRows    = 1000
	maxEmailCommandReplyBytes  = 1 << 20
)

const (
	commandListTruncatedNotice  = "Results were limited to 1,000 matching records.\n"
	commandReplyTruncatedNotice = "\nCommand reply was truncated at 1 MiB.\n"
)

type commandPeriod string

const (
	periodDay   commandPeriod = "day"
	periodWeek  commandPeriod = "week"
	periodMonth commandPeriod = "month"
	periodYear  commandPeriod = "year"
	periodAll   commandPeriod = "all"
)

type emailCommand struct {
	kind        string
	verb        string
	sender      string
	recipient   string
	canonical   string
	ip          netip.Addr
	period      commandPeriod
	errorText   string
	rejectionID uint64
}

type commandReplyAttachment struct {
	Filename   string
	MediaType  string
	Contents   []byte
	SourcePath string
}

type commandReplyContent struct {
	Text        string
	Attachments []commandReplyAttachment
}

type commandResult func() commandReplyContent

func textCommandResult(render func() string) commandResult {
	return func() commandReplyContent { return commandReplyContent{Text: render()} }
}

func parseCommandPeriod(value string) (commandPeriod, bool) {
	switch commandPeriod(strings.ToLower(value)) {
	case periodDay, periodWeek, periodMonth, periodYear, periodAll:
		return commandPeriod(strings.ToLower(value)), true
	default:
		return "", false
	}
}

func (p commandPeriod) cutoff(now time.Time) time.Time {
	switch p {
	case periodDay:
		return now.Add(-24 * time.Hour)
	case periodMonth:
		return now.AddDate(0, -1, 0)
	case periodYear:
		return now.AddDate(-1, 0, 0)
	case periodAll:
		return time.Time{}
	default:
		return now.Add(-7 * 24 * time.Hour)
	}
}

func (ss *session) isCommandRecipient(recipient string) bool {
	return ss.server.cfg.EmailCommands.Enabled && normalizeEmailAddress(recipient) == ss.server.commandRecipient
}

func (ss *session) isInternalMessage() bool {
	marker := strings.TrimSpace(ss.message.Header(internalMessageHeader))
	return marker != "" && marker == ss.server.internalToken &&
		(!ss.peerIP.IsValid() || ss.peerIP.IsLoopback() || !connectionAddressRoutable(ss.peerIP))
}

func (ss *session) handleEmailCommand(ctx context.Context) (bool, bool) {
	cfg := ss.server.cfg.EmailCommands
	if !cfg.Enabled {
		return false, true
	}
	hasCommandRecipient := false
	for _, recipient := range ss.envelopeRecipients {
		if normalizeEmailAddress(recipient) == ss.server.commandRecipient {
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

	lines, err := commandMessageLines(ss.message, cfg.MaxMessageBytes)
	if err != nil {
		return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, err.Error())
	}
	commands := make([]emailCommand, 0, len(lines))
	for _, line := range lines {
		command, parseErr := ss.server.commands.parse(line, CommandActor{Administrator: admin, DefaultRecipient: replyTo})
		if parseErr != nil {
			if len(commands) == 0 {
				return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, parseErr.Error())
			}
			if recognizedCommandLine(line) {
				commands = append(commands, emailCommand{kind: "parse_error", canonical: line, errorText: parseErr.Error()})
			}
			break
		}
		commands = append(commands, command)
		if len(commands) == maxCommandsPerMessage {
			break
		}
	}
	if len(commands) == 0 {
		return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, "command body is empty")
	}

	parts := make([]commandResult, 0, len(commands))
	canonicals := make([]string, 0, len(commands))
	for _, command := range commands {
		body, operationErr := ss.server.commands.execute(ctx, command, CommandActor{Administrator: admin, DefaultRecipient: replyTo})
		canonicals = append(canonicals, command.canonical)
		if operationErr != nil {
			ss.server.log.ErrorContext(ctx, "email command operation failed", "authenticated_identity", identity, "command", command.canonical, "error", operationErr)
			parts = append(parts, textCommandResult(func() string { return "The command could not be completed. Check the server log.\n" }))
			continue
		}
		parts = append(parts, body)
	}
	queued := ss.queueCommandReplyContentFunc(replyTo, "MilterGuard command results", func() commandReplyContent {
		var body strings.Builder
		var attachments []commandReplyAttachment
		attached := make(map[string]bool)
		for i, command := range commands {
			prefix := command.canonical + "\n\n"
			if !appendBoundedCommandReply(&body, prefix) {
				break
			}
			result := parts[i]()
			text := result.Text
			if !strings.HasSuffix(result.Text, "\n") {
				text += "\n"
			}
			text += "\n"
			if !appendBoundedCommandReply(&body, text) {
				break
			}
			for _, attachment := range result.Attachments {
				if !attached[attachment.Filename] {
					attachments = append(attachments, attachment)
					attached[attachment.Filename] = true
				}
			}
		}
		return commandReplyContent{Text: body.String(), Attachments: attachments}
	})
	return true, ss.discardEmailCommand(ctx, identity, strings.Join(canonicals, "; "), fmt.Sprintf("processed %d commands", len(commands)), "", "", queued)
}

func commandMessageLines(m *message.Message, maxBytes int64) ([]string, error) {
	// Any Content-Disposition occurrence disqualifies a command message. This
	// is an existence check rather than MIME parsing, so retaining all values
	// prevents a later duplicate from hiding an attachment declaration.
	if strings.TrimSpace(m.Header("Content-Disposition")) != "" {
		return nil, fmt.Errorf("attachments are not allowed")
	}
	mediaType := "text/plain"
	if value := strings.TrimSpace(m.FirstHeader("Content-Type")); value != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(value)
		if err != nil {
			return nil, fmt.Errorf("invalid Content-Type")
		}
	}
	if mediaType != "text/plain" && mediaType != "text/html" && mediaType != "multipart/alternative" {
		return nil, fmt.Errorf("command email must contain plain text or HTML without attachments")
	}
	text := m.CommandText(maxBytes)
	if strings.ContainsRune(text, '\x00') {
		return nil, fmt.Errorf("command body contains invalid characters")
	}
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("command body is empty")
	}
	return lines, nil
}

func recognizedCommandLine(line string) bool {
	fields := strings.Fields(line)
	return len(fields) > 0 && (strings.EqualFold(fields[0], "HELP") || strings.EqualFold(fields[0], "IP") ||
		strings.EqualFold(fields[0], "REJECTION") || strings.EqualFold(fields[0], "REJECTIONS") || strings.EqualFold(fields[0], "WHITELIST"))
}

func parseEmailCommand(text, authenticatedSender string, admin bool) (emailCommand, bool, error) {
	fields := strings.Fields(text)
	if len(fields) == 1 && strings.EqualFold(fields[0], "HELP") {
		return emailCommand{}, true, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "REJECTION") {
		if len(fields) != 2 {
			return emailCommand{}, false, fmt.Errorf("REJECTION requires one positive rejection ID")
		}
		id, err := strconv.ParseUint(fields[1], 10, 63)
		if err != nil || id == 0 {
			return emailCommand{}, false, fmt.Errorf("REJECTION requires one positive rejection ID")
		}
		return emailCommand{kind: "rejection", canonical: "REJECTION " + strconv.FormatUint(id, 10), rejectionID: id}, false, nil
	}
	if len(fields) >= 1 && strings.EqualFold(fields[0], "IP") {
		if !admin {
			return emailCommand{}, false, fmt.Errorf("IP commands are restricted to administrators")
		}
		if len(fields) >= 2 && strings.EqualFold(fields[1], "LIST") {
			kind, canonical, periodIndex := "ip_list", "IP LIST", 2
			if len(fields) >= 3 && strings.EqualFold(fields[2], "LOOKUP") {
				kind, canonical, periodIndex = "ip_list_lookup", "IP LIST LOOKUP", 3
			}
			period, err := listCommandPeriod(fields, periodIndex)
			if err != nil {
				return emailCommand{}, false, fmt.Errorf("IP LIST period must be day, week, month, year, or all")
			}
			return emailCommand{kind: kind, canonical: canonical + " " + string(period), period: period}, false, nil
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
		if len(fields) > 3 {
			return emailCommand{}, false, fmt.Errorf("REJECTIONS accepts at most one recipient and one period")
		}
		recipient := authenticatedSender
		period := periodWeek
		end := len(fields)
		if len(fields) > 1 {
			if parsed, ok := parseCommandPeriod(fields[len(fields)-1]); ok {
				period, end = parsed, len(fields)-1
			}
		}
		if end == 2 {
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
		} else if end > 2 {
			return emailCommand{}, false, fmt.Errorf("REJECTIONS accepts at most one recipient and one period")
		}
		canonical := "REJECTIONS"
		if end == 2 {
			canonical += " " + recipient
		}
		canonical += " " + string(period)
		return emailCommand{kind: "rejections", recipient: recipient, canonical: canonical, period: period}, false, nil
	}
	if len(fields) >= 2 && strings.EqualFold(fields[0], "WHITELIST") && strings.EqualFold(fields[1], "LIST") {
		if len(fields) > 4 {
			return emailCommand{}, false, fmt.Errorf("WHITELIST LIST accepts at most one recipient and one period")
		}
		recipient := authenticatedSender
		period := periodWeek
		end := len(fields)
		if len(fields) > 2 {
			if parsed, ok := parseCommandPeriod(fields[len(fields)-1]); ok {
				period, end = parsed, len(fields)-1
			}
		}
		if end == 3 {
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
		} else if end > 3 {
			return emailCommand{}, false, fmt.Errorf("WHITELIST LIST accepts at most one recipient and one period")
		}
		canonical := "WHITELIST LIST"
		if end == 3 {
			canonical += " " + recipient
		}
		canonical += " " + string(period)
		return emailCommand{kind: "whitelist_list", recipient: recipient, canonical: canonical, period: period}, false, nil
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

func listCommandPeriod(fields []string, index int) (commandPeriod, error) {
	if len(fields) == index {
		return periodWeek, nil
	}
	if len(fields) != index+1 {
		return "", fmt.Errorf("too many arguments")
	}
	period, ok := parseCommandPeriod(fields[index])
	if !ok {
		return "", fmt.Errorf("invalid period")
	}
	return period, nil
}

func (p *CommandProcessor) executeCommand(parent context.Context, command emailCommand, actor CommandActor) (commandResult, error) {
	ctx, cancel := context.WithTimeout(parent, commandDatabaseTimeout)
	defer cancel()
	s := p.server
	admin := actor.Administrator
	cutoff := command.period.cutoff(time.Now().UTC())
	switch command.kind {
	case "parse_error":
		return textCommandResult(func() string { return command.errorText + ".\n" }), nil
	case "help":
		return textCommandResult(func() string { return commandHelp(admin, actor.DefaultRecipient) }), nil
	case "rejections":
		page, err := p.rejections.ListRejections(ctx, stores.RejectionListQuery{
			Recipients: commandRecipientScope(command.recipient), RejectedSince: cutoff, Limit: maxEmailCommandListRows,
		})
		entries := page.Entries
		if actor.NewestLast {
			reverseSlice(entries)
		}
		return textCommandResult(func() string { return formatRejectionHistory(entries, page.Truncated) }), err
	case "rejection":
		scope := stores.RecipientScope{Address: actor.DefaultRecipient}
		if admin {
			scope = stores.RecipientScope{All: true}
		}
		entry, found, err := p.rejections.RejectionByID(ctx, command.rejectionID, scope)
		if err != nil {
			return nil, err
		}
		if !found {
			return textCommandResult(func() string { return "Rejection record not found.\n" }), nil
		}
		return func() commandReplyContent { return s.rejectionDetail(entry) }, nil
	case "whitelist_list":
		page, err := p.correspondents.ListCorrespondents(ctx, stores.CorrespondentListQuery{
			Recipients: commandRecipientScope(command.recipient), ActiveSince: cutoff, Limit: maxEmailCommandListRows,
		})
		if err != nil {
			return nil, err
		}
		entries := page.Entries
		if actor.NewestLast {
			reverseSlice(entries)
		}
		return textCommandResult(func() string {
			return formatAllowlist(entries, includeAllowlistRecipient(admin, command.recipient), page.Truncated)
		}), nil
	case "ip_list", "ip_list_lookup":
		page, err := p.ipReputation.ListActiveBlocks(ctx, stores.IPBlockListQuery{ActiveSince: cutoff, Limit: maxEmailCommandListRows})
		if err != nil {
			return nil, err
		}
		entries, truncated := page.Entries, page.Truncated
		if actor.NewestLast {
			reverseSlice(entries)
		}
		lookup := command.kind == "ip_list_lookup"
		if lookup {
			entries = s.resolveActiveIPHostnames(ctx, entries)
		}
		return textCommandResult(func() string {
			return formatActiveIPBlocks(entries, lookup, truncated)
		}), nil
	case "ip_add":
		block, err := p.ipReputation.AddManualBlock(ctx, command.ip)
		outcome := fmt.Sprintf("blocked %s until %s", block.Address, block.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		return textCommandResult(func() string { return outcome + ".\n" }), err
	case "ip_delete":
		removed, err := p.ipReputation.Delete(ctx, command.ip)
		outcome := "IP address was not present"
		if removed {
			outcome = "IP reputation record deleted"
		}
		return textCommandResult(func() string { return outcome + ".\n" }), err
	case "whitelist":
		var outcome string
		if command.verb == "ADD" {
			created, err := p.correspondents.AddManual(ctx, command.sender, command.recipient)
			if created {
				outcome = "allowlist entry added"
			} else {
				outcome = "allowlist entry already existed and was refreshed"
			}
			return textCommandResult(func() string { return outcome + ".\n" }), err
		}
		removed, err := p.correspondents.DeleteManual(ctx, command.sender, commandRecipientScope(command.recipient))
		outcome = fmt.Sprintf("removed %d allowlist entries", removed)
		return textCommandResult(func() string { return outcome + ".\n" }), err
	default:
		return nil, fmt.Errorf("unsupported command")
	}
}

func reverseSlice[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func commandHelp(admin bool, defaultRecipient ...string) string {
	terminalAdmin := admin && len(defaultRecipient) > 0 && defaultRecipient[0] == "*"
	text := "Send one or more commands, one per line:\n\nWHITELIST ADD sender@example.com\nWHITELIST DELETE sender@example.com\nWHITELIST LIST [day|week|month|year|all]\nREJECTIONS [day|week|month|year|all]\nREJECTION id\nHELP\n\nListing commands default to the previous week. The local address is taken from your authenticated envelope sender.\n"
	if terminalAdmin {
		text = "Enter one command at a time:\n\nWHITELIST ADD sender@example.com recipient@example.com\nWHITELIST DELETE sender@example.com [recipient@example.com|*]\nWHITELIST LIST [recipient@example.com|*] [day|week|month|year|all]\nREJECTIONS [recipient@example.com|*] [day|week|month|year|all]\nREJECTION id\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\nHELP\nEXIT\n\nListing commands default to the previous week and all local recipients. WHITELIST ADD requires an explicit local recipient.\n"
		return text
	}
	if admin {
		text += "\nAdministrator commands:\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\n\nAdministrators may append a local recipient address before the period in WHITELIST LIST and REJECTIONS commands, and to modification commands. They may use * with WHITELIST DELETE, WHITELIST LIST, or REJECTIONS. For example:\n\nWHITELIST LIST * month\nREJECTIONS * year\n"
	}
	return text
}

func commandRecipientScope(recipient string) stores.RecipientScope {
	if recipient == "*" {
		return stores.RecipientScope{All: true}
	}
	return stores.RecipientScope{Address: recipient}
}

func (s *Server) rejectionDetail(entry stores.Rejection) commandReplyContent {
	processedBody := "Saved message is not available."
	var attachments []commandReplyAttachment
	if s.rejectedMail != nil {
		contents, err := s.rejectedMail.ReadWithRecordID(entry.ID, entry.RejectedAt, s.cfg.Milter.MaxMessageSize)
		switch {
		case err == nil:
			sourcePath := filepath.Join(s.cfg.RejectionHistory.MessageDirectory,
				entry.RejectedAt.UTC().Format("2006"), entry.RejectedAt.UTC().Format("01"),
				entry.RejectedAt.UTC().Format("02"), strconv.FormatUint(entry.ID, 10)+".eml")
			attachments = append(attachments, commandReplyAttachment{
				Filename:   fmt.Sprintf("rejection-%d.eml", entry.ID),
				MediaType:  "application/octet-stream",
				Contents:   contents,
				SourcePath: sourcePath,
			})
			archived, parseErr := message.ParseArchived(contents, s.cfg.Milter.MaxMessageSize)
			if parseErr == nil {
				processedBody = archived.ProcessedBody(maxRejectionReplyBodyRunes)
				if strings.TrimSpace(processedBody) == "" {
					processedBody = "No readable message text was found."
				}
			} else {
				s.log.Warn("cannot process saved rejected message", "rejection_id", entry.ID, "error", parseErr)
			}
		case errors.Is(err, rejectedmail.ErrMessageNotFound):
		default:
			s.log.Warn("cannot read saved rejected message", "rejection_id", entry.ID, "error", err)
		}
	}
	return commandReplyContent{Text: formatRejectionDetail(entry, processedBody), Attachments: attachments}
}

func formatRejectionDetail(entry stores.Rejection, processedBody string) string {
	subject := entry.Subject
	if subject == "" {
		subject = "Unavailable"
	}
	reason := entry.Reason
	if reason == "" {
		reason = "Unavailable"
	}
	return fmt.Sprintf("Rejection ID: %d\nFrom: %s\nTo: %s\nSubject: %s\nDate: %s\nReason for rejection: %s\n\nProcessed email body text:\n%s\n",
		entry.ID, entry.Sender, strings.Join(entry.Recipients, ", "), subject,
		entry.RejectedAt.UTC().Format("2006-01-02 15:04:05 UTC"), reason, processedBody)
}

func formatAllowlist(entries []stores.Correspondent, includeRecipient, truncated bool) string {
	if len(entries) == 0 {
		return "No whitelisted correspondent addresses were found.\n"
	}
	entries, additionallyTruncated := limitEmailCommandRows(entries)
	truncated = truncated || additionallyTruncated
	var body strings.Builder
	for _, entry := range entries {
		var record strings.Builder
		fmt.Fprintf(&record, "Sender: %s\n", entry.Correspondent)
		if includeRecipient {
			fmt.Fprintf(&record, "Recipient: %s\n", entry.LocalAddress)
		}
		fmt.Fprintf(&record, "Added: %s\n\n", allowlistAddedDescription(entry.WhitelistType))
		if !appendBoundedCommandReply(&body, record.String()) {
			return body.String()
		}
	}
	if truncated {
		appendBoundedCommandReply(&body, commandListTruncatedNotice)
	}
	return body.String()
}

func includeAllowlistRecipient(admin bool, recipient string) bool {
	return admin && recipient == "*"
}

func allowlistAddedDescription(whitelistType stores.CorrespondentKind) string {
	switch whitelistType {
	case stores.CorrespondentKindManual:
		return "manually"
	case stores.CorrespondentKindAuthenticatedOutbound:
		return "learned from authenticated outbound email"
	case stores.CorrespondentKindRepeatedLegitimateInbound:
		return "learned from repeated legitimate inbound emails"
	default:
		return "unknown"
	}
}

func formatActiveIPBlocks(entries []stores.IPBlock, includeHostname, truncated bool) string {
	if len(entries) == 0 {
		return "No active IP blocks were found.\n"
	}
	var body strings.Builder
	for _, entry := range entries {
		var record string
		if includeHostname {
			hostname := entry.Hostname
			if hostname == "" {
				hostname = "not found"
			}
			record = fmt.Sprintf("IP: %s (%s) Type: %s Expires: %s\n", entry.Address, hostname, entry.Level, entry.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		} else {
			record = fmt.Sprintf("IP: %s Type: %s Expires: %s\n", entry.Address, entry.Level, entry.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
		if !appendBoundedCommandReply(&body, record) {
			return body.String()
		}
	}
	if truncated {
		appendBoundedCommandReply(&body, commandListTruncatedNotice)
	}
	return body.String()
}

func formatRejectionHistory(entries []stores.Rejection, truncated bool) string {
	if len(entries) == 0 {
		return "No retained rejected-email records were found.\n"
	}
	entries, additionallyTruncated := limitEmailCommandRows(entries)
	truncated = truncated || additionallyTruncated
	var body strings.Builder
	for _, entry := range entries {
		subject := entry.Subject
		if subject == "" {
			subject = "Unavailable (record predates subject logging)"
		}
		reason := entry.Reason
		if reason == "" {
			reason = "Unavailable (record predates reason logging)"
		}
		record := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\nDate: %s\nRejection ID: %d\nReason: %s\n\n", entry.Sender, strings.Join(entry.Recipients, ", "), subject, entry.RejectedAt.UTC().Format("2006-01-02 15:04:05 UTC"), entry.ID, reason)
		if !appendBoundedCommandReply(&body, record) {
			return body.String()
		}
	}
	if truncated {
		appendBoundedCommandReply(&body, commandListTruncatedNotice)
	}
	return body.String()
}

func limitEmailCommandRows[T any](entries []T) ([]T, bool) {
	if len(entries) <= maxEmailCommandListRows {
		return entries, false
	}
	return entries[:maxEmailCommandListRows], true
}

func appendBoundedCommandReply(body *strings.Builder, text string) bool {
	remaining := maxEmailCommandReplyBytes - body.Len()
	if len(text) <= remaining {
		body.WriteString(text)
		return true
	}
	contentLimit := maxEmailCommandReplyBytes - len(commandReplyTruncatedNotice)
	if body.Len() > contentLimit {
		end := contentLimit
		existing := body.String()
		for end > 0 && !utf8.ValidString(existing[:end]) {
			end--
		}
		preserved := strings.Clone(existing[:end])
		body.Reset()
		body.WriteString(preserved)
	} else if available := contentLimit - body.Len(); available > 0 {
		end := min(available, len(text))
		for end > 0 && !utf8.ValidString(text[:end]) {
			end--
		}
		body.WriteString(text[:end])
	}
	body.WriteString(commandReplyTruncatedNotice)
	return false
}

func (ss *session) completeInvalidEmailCommand(ctx context.Context, identity, replyTo, reason string) bool {
	queued := ss.queueCommandReply(replyTo, "MilterGuard command rejected", reason+".\n\n"+commandHelp(ss.isCommandAdministrator(identity)))
	return ss.discardEmailCommand(ctx, identity, "invalid", reason, replyTo, "", queued)
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
	return ss.queueCommandReplyContentFunc(recipient, subject, func() commandReplyContent {
		return commandReplyContent{Text: body}
	})
}

func (ss *session) queueCommandReplyContentFunc(recipient, subject string, content func() commandReplyContent) bool {
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
		defer func() {
			if panicValue := recover(); panicValue != nil {
				ss.server.logRecoveredWorkerPanic(context.Background(), "email command reply", panicValue, "recipient", recipient)
			}
		}()
		from := normalizeEmailAddress(cfg.Recipient)
		date := time.Now().UTC().Format(time.RFC1123Z)
		reply := content()
		payload, err := buildBoundedCommandReplyPayload(from, recipient, subject, date, token, reply, ss.server.cfg.Milter.MaxMessageSize)
		if err == nil {
			err = submitSMTP(cfg.SMTPHost, cfg.SMTPTLS, recipient, payload)
		}
		if err != nil {
			log.Error("cannot send email command confirmation", "recipient", recipient, "smtp_host", cfg.SMTPHost, "error", err)
			return
		}
		log.Debug("email command confirmation submitted", "recipient", recipient)
	}()
	return true
}

func buildBoundedCommandReplyPayload(from, recipient, subject, date, token string, reply commandReplyContent, maxBytes int64) ([]byte, error) {
	reply.Text = boundedCommandReplyText(reply.Text)
	payload, err := buildCommandReplyPayload(from, recipient, subject, date, token, reply)
	if err != nil || len(reply.Attachments) == 0 || maxBytes <= 0 || int64(len(payload)) <= maxBytes {
		return payload, err
	}
	reply.Text += "\nOne or more original saved messages were too large to attach.\n"
	reply.Attachments = nil
	return buildCommandReplyPayload(from, recipient, subject, date, token, reply)
}

func boundedCommandReplyText(text string) string {
	if len(text) <= maxEmailCommandReplyBytes {
		return text
	}
	var bounded strings.Builder
	appendBoundedCommandReply(&bounded, text)
	return bounded.String()
}

func buildCommandReplyPayload(from, recipient, subject, date, token string, reply commandReplyContent) ([]byte, error) {
	var payload bytes.Buffer
	fmt.Fprintf(&payload, "From: MilterGuard <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nAuto-Submitted: auto-replied\r\nX-Auto-Response-Suppress: All\r\n%s: %s\r\n", from, recipient, subject, date, internalMessageHeader, token)
	if len(reply.Attachments) == 0 {
		payload.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		payload.WriteString(reply.Text)
		return payload.Bytes(), nil
	}

	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	fmt.Fprintf(&payload, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", writer.Boundary())
	textHeader := make(textproto.MIMEHeader)
	textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
	textHeader.Set("Content-Transfer-Encoding", "8bit")
	part, err := writer.CreatePart(textHeader)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(part, reply.Text); err != nil {
		return nil, err
	}
	for _, attachment := range reply.Attachments {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType(attachment.MediaType, map[string]string{"name": attachment.Filename}))
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Filename}))
		header.Set("Content-Transfer-Encoding", "base64")
		part, err = writer.CreatePart(header)
		if err != nil {
			return nil, err
		}
		if err := writeMIMEBase64(part, attachment.Contents); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if _, err := multipartBody.WriteTo(&payload); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func writeMIMEBase64(writer io.Writer, contents []byte) error {
	encoded := base64.StdEncoding.EncodeToString(contents)
	for len(encoded) > 76 {
		if _, err := io.WriteString(writer, encoded[:76]+"\r\n"); err != nil {
			return err
		}
		encoded = encoded[76:]
	}
	_, err := io.WriteString(writer, encoded+"\r\n")
	return err
}

func submitSMTP(address, tlsMode, recipient string, payload []byte) error {
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
	startTLS, _ := client.Extension("STARTTLS")
	useTLS, err := smtpTLSDecision(tlsMode, host, startTLS)
	if err != nil {
		return err
	}
	if useTLS {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
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

func smtpTLSDecision(mode, host string, advertised bool) (bool, error) {
	if mode == "required" && !advertised {
		return false, errors.New("SMTP server does not advertise STARTTLS")
	}
	return advertised && (mode == "required" || (mode == "opportunistic" && !smtpHostIsLoopback(host))), nil
}

func smtpHostIsLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
