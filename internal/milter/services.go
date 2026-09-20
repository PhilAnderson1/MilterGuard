package milter

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// protocolOptions contains immutable values used directly by the Milter state
// machine. Feature policy belongs to the focused services below.
type protocolOptions struct {
	timeout          time.Duration
	maxMessageSize   int64
	progressInterval time.Duration
	mode             string
}

type analysisService struct {
	analyzer            Analyzer
	ai                  config.AIConfig
	filtering           config.FilteringConfig
	logging             config.LoggingConfig
	mode                string
	log                 *slog.Logger
	slots               chan struct{}
	domainLookupTimeout time.Duration
	milterTimeout       time.Duration
}

type messagePolicyService struct {
	filtering          config.FilteringConfig
	correspondentCfg   config.CorrespondentsConfig
	mode               string
	log                *slog.Logger
	ipReputation       *ipReputationStore
	correspondents     stores.CorrespondentRepository
	rejectionHistory   stores.RejectionHistoryRepository
	domainRegistration *domainRegistrationStore
	archive            *rejectedmail.Archive
}

type messageContext struct {
	message             *message.Message
	peerIP              netip.Addr
	connectionDNS       connectionDNSResult
	authenticated       bool
	visibleSender       string
	visibleSenderDomain string
	envelopeSender      string
	envelopeRecipients  []string
	recipientsComplete  bool
}

func (s *messagePolicyService) applyPostDecisionUpdates(ctx context.Context, current messageContext, result evaluationResult, inbound inboundEvidence) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), postDecisionUpdateTimeout)
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
	if !current.authenticated && result.err == nil {
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

type attachmentPolicyService struct {
	cfg       config.AttachmentsConfig
	filtering config.FilteringConfig
	mode      string
	log       *slog.Logger
	scanner   *attachment.Scanner
	slots     chan struct{}
	policy    *messagePolicyService
}

type emailCommandService struct {
	cfg            config.EmailCommandsConfig
	processor      *admincmd.Processor
	recipient      string
	internalToken  string
	replySlots     chan struct{}
	log            *slog.Logger
	maxMessageSize int64
}

type connectionDNSService struct {
	resolver dnsResolver
	timeout  time.Duration
	log      *slog.Logger
}

type sessionDependencies struct {
	protocol    protocolOptions
	analysis    *analysisService
	policy      *messagePolicyService
	attachments *attachmentPolicyService
	commands    *emailCommandService
	dns         *connectionDNSService
	log         *slog.Logger
}

type maintenanceService struct {
	ip              stores.PersistentIPReputationRepository
	correspondents  stores.CorrespondentRepository
	rejections      stores.RejectionHistoryRepository
	domains         *domainRegistrationStore
	database        *sqlstore.Store
	archive         *rejectedmail.Archive
	cleanupInterval time.Duration
	log             *slog.Logger
}
