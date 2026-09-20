package milter

import (
	"context"
	"fmt"
	"mime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
)

const internalMessageHeader = "X-MilterGuard-Internal"

const (
	maxCommandsPerMessage     = 100
	maxEmailCommandReplyBytes = 1 << 20
)

const (
	commandReplyTruncatedNotice = "\nCommand reply was truncated at 1 MiB.\n"
)

type commandReplyContent struct {
	Text        string
	Attachments []smtpreply.Attachment
}

func (ss *session) isCommandRecipient(recipient string) bool {
	return ss.deps.commands.cfg.Enabled && normalizeEmailAddress(recipient) == ss.deps.commands.recipient
}

func (ss *session) isInternalMessage() bool {
	marker := strings.TrimSpace(ss.message.Header(internalMessageHeader))
	return marker != "" && marker == ss.deps.commands.internalToken &&
		(!ss.peerIP.IsValid() || ss.peerIP.IsLoopback() || !netsafety.AddressRoutable(ss.peerIP))
}

// handleEmailCommand recognizes the configured command recipient, authorizes
// the authenticated sender, executes each command line, and queues one reply.
// Its booleans report whether it handled the message and whether the Milter
// connection may remain open.
func (ss *session) handleEmailCommand(ctx context.Context) (bool, bool) {
	cfg := ss.deps.commands.cfg
	if !cfg.Enabled {
		return false, true
	}
	hasCommandRecipient := false
	for _, recipient := range ss.envelopeRecipients {
		if normalizeEmailAddress(recipient) == ss.deps.commands.recipient {
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
			ss.deps.log.WarnContext(ctx, "email command sender ownership verification failed", "authenticated_identity", identity, "envelope_sender", ss.envelopeSender, "error", err)
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
	actor := admincmd.Actor{Administrator: admin, DefaultRecipient: replyTo}
	commands := make([]admincmd.Command, 0, len(lines))
	for _, line := range lines {
		command, parseErr := ss.deps.commands.processor.Parse(line, actor)
		if parseErr != nil {
			if len(commands) == 0 {
				return true, ss.completeInvalidEmailCommand(ctx, identity, replyTo, parseErr.Error())
			}
			if admincmd.RecognizedLine(line) {
				commands = append(commands, admincmd.ParseError(line, parseErr.Error()))
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

	parts := make([]admincmd.DeferredResponse, 0, len(commands))
	canonicals := make([]string, 0, len(commands))
	for _, command := range commands {
		body, operationErr := ss.deps.commands.processor.Execute(ctx, command, actor)
		canonicals = append(canonicals, command.Canonical())
		if operationErr != nil {
			ss.deps.log.ErrorContext(ctx, "email command operation failed", "authenticated_identity", identity, "command", command.Canonical(), "error", operationErr)
			parts = append(parts, func() admincmd.Response {
				return admincmd.Response{Text: "The command could not be completed. Check the server log.\n"}
			})
			continue
		}
		parts = append(parts, body)
	}
	queued := ss.deps.commands.queueReplyContentFunc(replyTo, "MilterGuard command results", func() commandReplyContent {
		var body strings.Builder
		var attachments []smtpreply.Attachment
		attached := make(map[string]bool)
		for i, command := range commands {
			prefix := command.Canonical() + "\n\n"
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
					attachments = append(attachments, smtpreply.Attachment{
						Filename: attachment.Filename, MediaType: attachment.MediaType, Contents: attachment.Contents,
					})
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
	queued := ss.deps.commands.queueReply(replyTo, "MilterGuard command rejected", reason+".\n\n"+admincmd.Help(ss.isCommandAdministrator(identity)))
	return ss.discardEmailCommand(ctx, identity, "invalid", reason, replyTo, "", queued)
}

func (ss *session) isCommandAdministrator(identity string) bool {
	for _, configured := range ss.deps.commands.cfg.Administrators {
		if strings.EqualFold(strings.TrimSpace(configured), identity) {
			return true
		}
	}
	return false
}

func (ss *session) rejectEmailCommand(ctx context.Context, reason string, replyQueued bool) bool {
	err := writeFrame(ss.conn, replyCode("550", "5.7.1", "MilterGuard command rejected: "+reason))
	ss.deps.log.WarnContext(ctx, "email command rejected", "message_id", ss.message.Header("Message-ID"), "authenticated_identity", ss.authentication.Identity, "result", reason, "discarded", false, "confirmation_queued", replyQueued, "response_sent", err == nil)
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
		ss.deps.log.WarnContext(ctx, "email command processed", attrs...)
	} else {
		ss.deps.log.InfoContext(ctx, "email command processed", attrs...)
	}
	if err != nil {
		return false
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (s *emailCommandService) queueReply(recipient, subject, body string) bool {
	return s.queueReplyContentFunc(recipient, subject, func() commandReplyContent {
		return commandReplyContent{Text: body}
	})
}

// queueReplyContentFunc reserves a bounded reply slot and defers expensive
// response rendering and SMTP submission to a panic-contained worker.
func (s *emailCommandService) queueReplyContentFunc(recipient, subject string, content func() commandReplyContent) bool {
	if !s.cfg.SendReplies {
		return false
	}
	cfg := s.cfg
	token := s.internalToken
	log := s.log
	select {
	case s.replySlots <- struct{}{}:
	default:
		log.Error("email command confirmation queue is full", "recipient", recipient)
		return false
	}
	go func() {
		defer func() { <-s.replySlots }()
		defer func() {
			if panicValue := recover(); panicValue != nil {
				logRecoveredWorkerPanic(s.log, context.Background(), "email command reply", panicValue, "recipient", recipient)
			}
		}()
		from := normalizeEmailAddress(cfg.Recipient)
		date := time.Now().UTC().Format(time.RFC1123Z)
		reply := content()
		message, err := buildBoundedCommandReplyMessage(from, recipient, subject, date, token, reply, s.maxMessageSize)
		if err == nil {
			err = s.sender.Send(context.Background(), message)
		}
		if err != nil {
			log.Error("cannot send email command confirmation", "recipient", recipient, "smtp_host", cfg.SMTPHost, "error", err)
			return
		}
		log.Debug("email command confirmation submitted", "recipient", recipient)
	}()
	return true
}

func buildBoundedCommandReplyMessage(from, recipient, subject, date, token string, reply commandReplyContent, maxBytes int64) (smtpreply.Message, error) {
	reply.Text = boundedCommandReplyText(reply.Text)
	message := commandReplyMessage(from, recipient, subject, date, token, reply)
	payload, err := smtpreply.Build(message)
	if err != nil || len(reply.Attachments) == 0 || maxBytes <= 0 || int64(len(payload)) <= maxBytes {
		return message, err
	}
	reply.Text += "\nOne or more original saved messages were too large to attach.\n"
	reply.Attachments = nil
	return commandReplyMessage(from, recipient, subject, date, token, reply), nil
}

func boundedCommandReplyText(text string) string {
	if len(text) <= maxEmailCommandReplyBytes {
		return text
	}
	var bounded strings.Builder
	appendBoundedCommandReply(&bounded, text)
	return bounded.String()
}

func commandReplyMessage(from, recipient, subject, date, token string, reply commandReplyContent) smtpreply.Message {
	return smtpreply.Message{
		From: from, To: recipient, Subject: subject, Date: date, Text: reply.Text,
		Headers:     []smtpreply.Header{{Name: internalMessageHeader, Value: token}},
		Attachments: reply.Attachments,
	}
}
