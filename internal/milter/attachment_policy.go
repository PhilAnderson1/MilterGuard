package milter

import (
	"context"
	"errors"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
)

func (ss *session) applyAttachments(ctx context.Context) (bool, bool) {
	if ss.server.attachments == nil {
		return false, true
	}
	select {
	case ss.server.attachmentSlots <- struct{}{}:
		defer func() { <-ss.server.attachmentSlots }()
	case <-ctx.Done():
		return true, false
	}
	finding, scanErr := ss.server.attachments.Scan(
		ss.message.Header("Content-Type"),
		ss.message.Header("Content-Transfer-Encoding"),
		ss.message.Header("Content-Disposition"),
		ss.message.BodyBytes(),
	)
	if finding != nil {
		return true, ss.finishAttachmentDecision(ctx, actionReject, finding.Path, finding.Detection, nil)
	}
	if scanErr == nil && ss.message.BodyTruncated {
		scanErr = errors.New("message body was truncated before attachment inspection completed")
	}
	if scanErr == nil {
		return false, true
	}
	actionName := ss.server.cfg.Attachments.UnscannableAction
	var typedError *attachment.ScanError
	if errors.As(scanErr, &typedError) && typedError.Encrypted {
		actionName = ss.server.cfg.Attachments.EncryptedArchiveAction
	}
	proposed := attachmentConfiguredAction(actionName)
	if proposed == actionAccept {
		ss.server.log.WarnContext(ctx, "attachment inspection incomplete; continuing with AI analysis",
			"message_id", ss.message.Header("Message-ID"), "error", scanErr)
		return false, true
	}
	return true, ss.finishAttachmentDecision(ctx, proposed, attachmentErrorPath(scanErr), "attachment inspection incomplete", scanErr)
}

func (ss *session) finishAttachmentDecision(ctx context.Context, proposed action, path, detection string, scanErr error) bool {
	selected := proposed
	if ss.server.cfg.Mode != "enforce" {
		selected = actionAccept
	}
	response := []byte{responseAccept}
	switch selected {
	case actionReject:
		response = replyCode("550", "5.7.1", ss.server.cfg.Attachments.RejectMessage)
	case actionTempfail:
		response = []byte{responseTempfail}
	}
	var err error
	if selected == actionAccept {
		if proposed != actionAccept && (ss.server.cfg.Filtering.AddEmailHeaders || ss.server.cfg.Mode == "tag") {
			classification := "unwanted"
			if scanErr != nil {
				classification = "unavailable"
			}
			action := "accepted-monitor-mode"
			if ss.server.cfg.Mode == "tag" {
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
		"mode", ss.server.cfg.Mode,
		"attachment_path", path,
		"detection", detection,
		"proposed_action", proposed.String(),
		"actual_action", selected.String(),
		"response_sent", err == nil,
	}
	if scanErr != nil {
		attrs = append(attrs, "inspection_error", scanErr)
	}
	if ss.server.cfg.Logging.IncludeSubject {
		attrs = append(attrs, "subject", ss.message.DecodedHeader("Subject"))
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.server.log.ErrorContext(ctx, "attachment policy response failed", attrs...)
		return false
	}
	ss.server.log.InfoContext(ctx, "attachment policy decision", attrs...)
	if selected == actionReject {
		reason := detection
		if path != "" {
			reason += ": " + path
		}
		ss.server.recordRejection(ctx, ss.message, ss.visibleSender, ss.envelopeSender, ss.envelopeRecipients, []string{reason}, "attachment_policy")
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
