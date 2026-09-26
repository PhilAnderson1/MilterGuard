package milter

import (
	"log/slog"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// protocolOptions contains immutable values used directly by the Milter state
// machine. Feature policy belongs to the focused services below.
type protocolOptions struct {
	timeout          time.Duration
	maxMessageSize   int64
	progressInterval time.Duration
	exactStorage     string
}

type analysisService struct {
	analyzer              Analyzer
	ai                    config.AIConfig
	log                   *slog.Logger
	slots                 chan struct{}
	domainLookupTimeout   time.Duration
	authenticationTimeout time.Duration
	milterTimeout         time.Duration
}

type messagePolicyService struct {
	correspondentCfg   config.CorrespondentsConfig
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

type attachmentPolicyService struct {
	cfg     config.AttachmentsConfig
	scanner *attachment.Scanner
	slots   chan struct{}
	policy  *messagePolicyService
}

type emailCommandService struct {
	cfg            config.EmailCommandsConfig
	processor      *admincmd.Processor
	recipient      string
	internalToken  string
	replySlots     chan struct{}
	sender         smtpreply.Sender
	log            *slog.Logger
	maxMessageSize int64
}

type connectionDNSService struct {
	resolver dnsResolver
	timeout  time.Duration
	log      *slog.Logger
}

type sessionDependencies struct {
	mode                 string
	filtering            config.FilteringConfig
	logging              config.LoggingConfig
	protocol             protocolOptions
	analysis             *analysisService
	policy               *messagePolicyService
	attachments          *attachmentPolicyService
	commands             *emailCommandService
	dns                  *connectionDNSService
	authenticationMode   string
	authentication       mailauth.Verifier
	shadowAuthentication mailauth.Verifier
	newExactMessage      func(string, int64) (mailauth.ExactMessage, error)
	log                  *slog.Logger
}

type maintenanceService struct {
	ip              stores.PersistentIPReputationRepository
	correspondents  stores.CorrespondentRepository
	rejections      stores.RejectionHistoryRepository
	domains         *domainRegistrationStore
	database        *sqlitedb.Store
	archive         *rejectedmail.Archive
	cleanupInterval time.Duration
	log             *slog.Logger
}
