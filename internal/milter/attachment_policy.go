package milter

import (
	"context"
	"errors"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type attachmentPolicyResult struct {
	handled       bool
	cancelled     bool
	proposed      action
	path          string
	detection     string
	err           error
	rejectMessage string
}

const invalidMIMERejectMessage = "Message rejected because it has an invalid MIME structure and cannot be safely inspected"

func (ss *session) applyAttachments(ctx context.Context) (bool, bool) {
	result := ss.deps.attachments.evaluate(ctx, ss.message)
	if !result.handled {
		return false, true
	}
	if result.cancelled {
		return true, false
	}
	if result.err != nil && result.proposed == actionAccept {
		ss.deps.log.WarnContext(ctx, "attachment inspection incomplete; continuing with AI analysis",
			"message_id", ss.message.Header("Message-ID"), "error", result.err)
		return false, true
	}
	return true, ss.finishAttachmentDecision(ctx, result.proposed, result.path, result.detection, result.err, result.rejectMessage)
}

// evaluate runs the attachment scanner under its concurrency limit and maps
// findings or incomplete inspection to the configured deterministic action.
func (s *attachmentPolicyService) evaluate(ctx context.Context, msg *message.Message) attachmentPolicyResult {
	if s == nil || s.scanner == nil {
		return attachmentPolicyResult{}
	}
	if msg.MIMEHeadersTruncated {
		return attachmentPolicyResult{
			handled: true, proposed: invalidMIMEConfiguredAction(s.cfg.InvalidMIMEAction), path: "message",
			detection: "invalid MIME structure", err: errors.New("structural MIME header exceeds the safe parsing limit"),
			rejectMessage: invalidMIMERejectMessage,
		}
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return attachmentPolicyResult{handled: true, cancelled: true, err: ctx.Err()}
	}
	finding, scanErr := s.scanner.ScanContext(
		ctx,
		msg.FirstHeader("Content-Type"),
		msg.FirstHeader("Content-Transfer-Encoding"),
		msg.FirstHeader("Content-Disposition"),
		msg.BodyBytes(),
	)
	if finding != nil {
		return attachmentPolicyResult{handled: true, proposed: actionReject, path: finding.Path, detection: finding.Detection}
	}
	if scanErr == nil && msg.BodyTruncated {
		scanErr = errors.New("message body was truncated before attachment inspection completed")
	}
	if scanErr == nil {
		return attachmentPolicyResult{}
	}
	actionName := s.cfg.UnscannableAction
	var typedError *attachment.ScanError
	if errors.As(scanErr, &typedError) {
		if typedError.Malformed {
			return attachmentPolicyResult{
				handled: true, proposed: invalidMIMEConfiguredAction(s.cfg.InvalidMIMEAction), path: attachmentErrorPath(scanErr),
				detection: "invalid MIME structure", err: scanErr,
				rejectMessage: invalidMIMERejectMessage,
			}
		}
		if typedError.Encrypted {
			actionName = s.cfg.EncryptedArchiveAction
		}
	}
	proposed := attachmentConfiguredAction(actionName)
	return attachmentPolicyResult{
		handled: true, proposed: proposed, path: attachmentErrorPath(scanErr),
		detection: "attachment inspection incomplete", err: scanErr,
	}
}

// finishAttachmentDecision applies operating mode, writes any accepted-message
// headers, records deterministic rejections, and sends the Milter response.
func (ss *session) finishAttachmentDecision(ctx context.Context, proposed action, path, detection string, scanErr error, rejectMessage string) bool {
	selected := selectActionForMode(proposed, ss.deps.attachments.mode)
	if rejectMessage == "" {
		rejectMessage = ss.deps.attachments.cfg.RejectMessage
	}
	response := responseForAction(selected, rejectMessage)
	var err error
	if selected == actionAccept {
		if proposed != actionAccept && (ss.deps.attachments.filtering.AddEmailHeaders || ss.deps.attachments.mode == "tag") {
			classification := "unwanted"
			if scanErr != nil {
				classification = "unavailable"
			}
			err = ss.writeTagHeaders(classification, nil, acceptedModeLabel(ss.deps.attachments.mode))
		} else {
			err = ss.writeAcceptedResultHeaders(nil)
		}
	}
	if err == nil {
		err = writeFrame(ss.conn, response)
	}
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.deps.attachments.mode,
		"attachment_path", path,
		"detection", detection,
		"proposed_action", proposed.String(),
		"actual_action", selected.String(),
		"response_sent", err == nil,
	}
	if scanErr != nil {
		attrs = append(attrs, "inspection_error", scanErr)
	}
	if ss.deps.analysis.logging.IncludeSubject {
		attrs = append(attrs, "subject", ss.message.DecodedHeader("Subject"))
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "attachment policy response failed", attrs...)
		return false
	}
	ss.deps.log.InfoContext(ctx, "attachment policy decision", attrs...)
	if selected == actionReject {
		reason := detection
		if path != "" {
			reason += ": " + path
		}
		persistCtx, cancel := postDecisionContext(ctx)
		ss.deps.attachments.policy.recordRejection(persistCtx, ss.message, ss.visibleSender, ss.envelopeSender, ss.envelopeRecipients, []string{reason}, "attachment_policy")
		cancel()
	}
	ss.resetMessage(phaseConnection)
	return true
}

func attachmentConfiguredAction(value string) action {
	switch value {
	case "reject":
		return actionReject
	case "tempfail":
		return actionTempfail
	default:
		return actionAccept
	}
}

func invalidMIMEConfiguredAction(value string) action {
	if value == "accept" {
		return actionAccept
	}
	return actionReject
}

func attachmentErrorPath(err error) string {
	var scanErr *attachment.ScanError
	if errors.As(err, &scanErr) && strings.TrimSpace(scanErr.Path) != "" {
		return scanErr.Path
	}
	return "message"
}
