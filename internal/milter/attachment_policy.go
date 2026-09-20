package milter

import (
	"context"
	"errors"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type attachmentPolicyResult struct {
	handled   bool
	cancelled bool
	proposed  action
	path      string
	detection string
	err       error
}

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
	return true, ss.finishAttachmentDecision(ctx, result.proposed, result.path, result.detection, result.err)
}

// evaluate runs the attachment scanner under its concurrency limit and maps
// findings or incomplete inspection to the configured deterministic action.
func (s *attachmentPolicyService) evaluate(ctx context.Context, msg *message.Message) attachmentPolicyResult {
	if s == nil || s.scanner == nil {
		return attachmentPolicyResult{}
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
	if errors.As(scanErr, &typedError) && typedError.Encrypted {
		actionName = s.cfg.EncryptedArchiveAction
	}
	proposed := attachmentConfiguredAction(actionName)
	return attachmentPolicyResult{
		handled: true, proposed: proposed, path: attachmentErrorPath(scanErr),
		detection: "attachment inspection incomplete", err: scanErr,
	}
}

// finishAttachmentDecision applies operating mode, writes any accepted-message
// headers, records deterministic rejections, and sends the Milter response.
func (ss *session) finishAttachmentDecision(ctx context.Context, proposed action, path, detection string, scanErr error) bool {
	selected := proposed
	if ss.deps.attachments.mode != "enforce" {
		selected = actionAccept
	}
	response := []byte{responseAccept}
	switch selected {
	case actionReject:
		response = replyCode("550", "5.7.1", ss.deps.attachments.cfg.RejectMessage)
	case actionTempfail:
		response = []byte{responseTempfail}
	}
	var err error
	if selected == actionAccept {
		if proposed != actionAccept && (ss.deps.attachments.filtering.AddEmailHeaders || ss.deps.attachments.mode == "tag") {
			classification := "unwanted"
			if scanErr != nil {
				classification = "unavailable"
			}
			action := "accepted-monitor-mode"
			if ss.deps.attachments.mode == "tag" {
				action = "accepted-tag-mode"
			}
			err = ss.writeTagHeaders(classification, nil, action)
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
		ss.deps.attachments.policy.recordRejection(ctx, ss.message, ss.visibleSender, ss.envelopeSender, ss.envelopeRecipients, []string{reason}, "attachment_policy")
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

func attachmentErrorPath(err error) string {
	var scanErr *attachment.ScanError
	if errors.As(err, &scanErr) && strings.TrimSpace(scanErr.Path) != "" {
		return scanErr.Path
	}
	return "message"
}
