package milter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth/moxverify"
	"github.com/PhilAnderson1/MilterGuard/internal/rdap"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/systemdns"
)

type runtimeComponents struct {
	sessions    *sessionDependencies
	maintenance *maintenanceService
	database    *sqlitedb.Store
	err         error
}

// buildRuntime constructs the shared services used by Milter sessions and the
// maintenance loop. It is the normal-service composition boundary: concrete
// repositories and network clients are created here and injected downstream.
func buildRuntime(cfg config.Config, analyzer Analyzer, log *slog.Logger) runtimeComponents {
	internalToken := ""
	var tokenErr error
	if cfg.EmailCommands.Enabled && cfg.EmailCommands.SendReplies {
		internalToken, tokenErr = generateInternalToken(rand.Reader)
	}

	var database *sqlitedb.Store
	var databaseErr error
	if correspondentFeaturesEnabled(cfg.Correspondents) || ipReputationFeaturesEnabled(cfg.IPReputation) ||
		rejectionHistoryEnabled(cfg.RejectionHistory) || domainRegistrationEnabled(cfg.DomainRegistration) {
		ctx, cancel := context.WithTimeout(context.Background(), databaseOpenTimeout)
		database, databaseErr = sqlitedb.Open(ctx, cfg.Persistence.DatabaseFile, sqlitedb.DefaultOptions())
		cancel()
	}

	ipRepository := newIPRepository(cfg.IPReputation, database, time.Now, log)
	correspondents := newCorrespondentRepository(cfg.Correspondents, database, time.Now, log)
	rejections := newRejectionRepository(cfg.RejectionHistory, database, time.Now, log)
	domainCache := newDomainRepository(cfg.DomainRegistration, database, time.Now)
	ipReputation := newIPReputationStore(cfg.IPReputation, ipRepository, log)
	var domainLookup domainRegistrationLookup
	if domainRegistrationEnabled(cfg.DomainRegistration) {
		domainLookup = rdap.New(cfg.DomainRegistration.Timeout.Value())
	}
	domainRegistration := newDomainRegistrationStore(cfg.DomainRegistration, domainCache, domainLookup, log)

	archive := newRejectedMailArchive(cfg.RejectionHistory, log)
	commands := commandProcessor(cfg, correspondents, rejections, ipReputation, archive, systemdns.NewResolver(), log)

	var attachmentScanner *attachment.Scanner
	if cfg.Attachments.BlockExecutables {
		attachmentScanner = attachment.New(attachment.Options{
			BlockedExtensions: cfg.Attachments.BlockedExtensions, InspectSignatures: cfg.Attachments.InspectSignatures,
			InspectArchives: cfg.Attachments.InspectArchives, MaxAttachmentBytes: cfg.Attachments.MaxAttachmentBytes,
			MaxArchiveDepth: cfg.Attachments.MaxArchiveDepth, MaxArchiveFiles: cfg.Attachments.MaxArchiveFiles,
			MaxArchiveUncompressedBytes: cfg.Attachments.MaxArchiveUncompressedBytes,
		})
	}

	authenticationTimeout := time.Duration(0)
	if cfg.Authentication.Mode == config.AuthenticationModeInternal {
		authenticationTimeout = cfg.Authentication.Timeout.Value()
	}
	analysis := &analysisService{
		analyzer: analyzer, ai: cfg.AI,
		log: log, slots: make(chan struct{}, cfg.AI.MaxConcurrent),
		domainLookupTimeout: cfg.DomainRegistration.Timeout.Value(), authenticationTimeout: authenticationTimeout,
		milterTimeout: cfg.Milter.Timeout.Value(),
	}
	policy := &messagePolicyService{
		correspondentCfg: cfg.Correspondents, log: log,
		ipReputation: ipReputation, correspondents: correspondents, rejectionHistory: rejections,
		domainRegistration: domainRegistration, archive: archive,
	}
	attachments := &attachmentPolicyService{
		cfg:     cfg.Attachments,
		scanner: attachmentScanner, slots: make(chan struct{}, attachmentConcurrency(cfg.Milter.MaxConnections)), policy: policy,
	}
	emailCommands := &emailCommandService{
		cfg: cfg.EmailCommands, processor: commands, recipient: mailaddr.Normalize(cfg.EmailCommands.Recipient),
		internalToken: internalToken, replySlots: make(chan struct{}, 4), log: log,
		maxMessageSize: cfg.Milter.MaxMessageSize,
		sender: smtpreply.New(smtpreply.Options{
			Address: cfg.EmailCommands.SMTPHost, TLSMode: cfg.EmailCommands.SMTPTLS, Timeout: commandReplySMTPTimeout,
		}),
	}
	authenticationMode := cfg.Authentication.Mode
	if authenticationMode == "" {
		authenticationMode = config.AuthenticationModeTrustedHeaders
	}
	var authentication mailauth.Verifier = mailauth.HeaderVerifier{}
	var authenticationErr error
	if authenticationMode == config.AuthenticationModeInternal {
		authentication, authenticationErr = moxverify.New(moxverify.Options{
			Timeout: cfg.Authentication.Timeout.Value(), MaxConcurrent: cfg.Authentication.MaxConcurrent, Logger: log,
		})
	}
	sessions := &sessionDependencies{
		mode: cfg.Mode, filtering: cfg.Filtering, logging: cfg.Logging,
		protocol: protocolOptions{
			timeout: cfg.Milter.Timeout.Value(), maxMessageSize: cfg.Milter.MaxMessageSize,
			progressInterval: defaultMilterProgressInterval, exactStorage: cfg.Authentication.MessageStorage,
		},
		analysis: analysis, policy: policy, attachments: attachments, commands: emailCommands,
		dns:                &connectionDNSService{resolver: systemdns.NewResolver(), timeout: cfg.Milter.ConnectionDNSTimeout.Value(), log: log},
		authenticationMode: authenticationMode,
		authentication:     authentication,
		newExactMessage:    mailauth.NewExactMessage,
		log:                log,
	}
	maintenance := &maintenanceService{
		ip: ipRepository, correspondents: correspondents, rejections: rejections,
		domains: domainRegistration, database: database, archive: archive,
		cleanupInterval: cfg.Persistence.CleanupInterval.Value(), log: log,
	}
	return runtimeComponents{sessions: sessions, maintenance: maintenance, database: database, err: errors.Join(tokenErr, databaseErr, authenticationErr)}
}

func attachmentConcurrency(maxConnections int) int {
	if maxConnections < 1 {
		return 1
	}
	if parallelism := runtime.GOMAXPROCS(0); parallelism < maxConnections {
		return parallelism
	}
	return maxConnections
}

func generateInternalToken(random io.Reader) (string, error) {
	var tokenBytes [32]byte
	if _, err := io.ReadFull(random, tokenBytes[:]); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInternalTokenGeneration, err)
	}
	return hex.EncodeToString(tokenBytes[:]), nil
}
