package milter

import (
	"context"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const postDecisionUpdateTimeout = 5 * time.Second

// postDecisionContext gives persistence work its own bounded lifetime after
// the final Milter response, independent of the message's analysis deadline.
func postDecisionContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), postDecisionUpdateTimeout)
}

// applyPostDecisionUpdates records adaptive trust and reputation evidence only
// after a completed enforce-mode decision. Analysis failures never count as
// legitimate evidence.
func (s *messagePolicyService) applyPostDecisionUpdates(ctx context.Context, current messageContext, result evaluationResult, inbound inboundEvidence) {
	ctx, cancel := postDecisionContext(ctx)
	defer cancel()
	if s.mode != "enforce" {
		return
	}
	if result.selected == actionReject {
		s.recordRejection(ctx, current.message, current.visibleSender, current.envelopeSender, current.envelopeRecipients, result.reasons, "ai")
		if !current.authenticated {
			s.ipReputation.add(ctx, current.peerIP, current.connectionDNS)
		}
	}
	if !current.authenticated && result.err == nil && result.classification == "legitimate" {
		if err := s.ipReputation.RecordLegitimate(ctx, current.peerIP); err != nil {
			s.log.ErrorContext(ctx, "cannot update sending IP reputation", "error", err)
		}
	}
	if result.selected == actionAccept && current.authenticated {
		s.learnAuthenticatedRecipients(ctx, current.envelopeSender, current.envelopeRecipients)
	}
	if !current.authenticated && result.err == nil && current.visibleSender != "" {
		s.recordInboundClassification(ctx, current, result, inbound.trustedDKIM)
	}
}

func (s *messagePolicyService) recordInboundClassification(ctx context.Context, current messageContext, result evaluationResult, dkimAligned bool) {
	if err := s.correspondents.RecordInboundClassification(ctx, stores.InboundClassification{
		Correspondent: current.visibleSender, Recipients: current.envelopeRecipients,
		RecipientsComplete: current.recipientsComplete, Classification: result.classification,
		Score: result.score, UnwantedMinScore: s.filtering.RejectScore, DKIMAligned: dkimAligned,
	}); err != nil {
		s.log.ErrorContext(ctx, "cannot update inbound correspondent learning", "error", err)
	}
}

func (s *messagePolicyService) touchInboundCorrespondent(ctx context.Context, sender string, recipients []string) {
	if err := s.correspondents.TouchInbound(ctx, sender, recipients); err != nil {
		s.log.ErrorContext(ctx, "cannot update correspondent activity", "error", err)
	}
}

func (s *messagePolicyService) learnAuthenticatedRecipients(ctx context.Context, sender string, recipients []string) {
	if err := s.correspondents.LearnAuthenticated(ctx, sender, recipients); err != nil {
		s.log.ErrorContext(ctx, "cannot update correspondent allowlist", "error", err)
	}
}

// recordRejection persists one rejection event and all affected recipients,
// then saves the original message under that record ID when archiving is on.
func (s *messagePolicyService) recordRejection(ctx context.Context, msg *message.Message, visibleSender, envelopeSender string, recipients, reasons []string, source string) {
	if msg == nil {
		return
	}
	rejectedAt := time.Now().UTC()
	recordID, err := s.rejectionHistory.AddRejection(ctx, stores.NewRejection{
		VisibleSender: visibleSender, EnvelopeSender: envelopeSender,
		Subject: msg.DecodedHeader("Subject"), Recipients: recipients,
		Reasons: reasons, RejectedAt: rejectedAt,
	})
	if err != nil {
		s.log.ErrorContext(ctx, "cannot save rejection history", "message_id", msg.Header("Message-ID"), "error", err)
		recordID = 0
	}
	if s.archive == nil {
		return
	}
	contents := msg.ArchiveBytes()
	s.saveRejectedMailCopy(ctx, msg, contents, source, recordID, rejectedAt)
}

func (s *messagePolicyService) saveRejectedMailCopy(ctx context.Context, msg *message.Message, contents []byte, source string, recordID uint64, rejectedAt time.Time) {
	var path string
	var err error
	if recordID == 0 {
		path, err = s.archive.Save(contents)
	} else {
		path, err = s.archive.SaveWithRecordIDAt(contents, recordID, rejectedAt)
	}
	if err != nil {
		s.log.WarnContext(ctx, "cannot save rejected message copy", "message_id", msg.Header("Message-ID"), "source", source, "rejection_id", recordID, "error", err)
		return
	}
	if recordID == 0 {
		s.log.WarnContext(ctx, "rejected message copy saved without rejection history record", "message_id", msg.Header("Message-ID"), "source", source, "file", path)
		return
	}
	s.log.DebugContext(ctx, "rejected message copy saved", "message_id", msg.Header("Message-ID"), "source", source, "rejection_id", recordID, "file", path)
}
