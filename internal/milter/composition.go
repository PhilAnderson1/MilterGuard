package milter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/rdap"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/smtpreply"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
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
		ctx, cancel := context.WithTimeout(context.Background(), maintenanceDatabaseTimeout)
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

	var archive *rejectedmail.Archive
	if cfg.RejectionHistory.SaveMessages && rejectionHistoryEnabled(cfg.RejectionHistory) {
		archive = rejectedmail.New(rejectedmail.Options{
			Directory: cfg.RejectionHistory.MessageDirectory,
			Retention: cfg.RejectionHistory.Expiry.Value(), MaxTotalBytes: cfg.RejectionHistory.MessageMaxTotalBytes,
		}, log)
	}
	commands := commandProcessor(cfg, correspondents, rejections, ipReputation, archive, net.DefaultResolver, log)

	var attachmentScanner *attachment.Scanner
	if cfg.Attachments.BlockExecutables {
		attachmentScanner = attachment.New(attachment.Options{
			BlockedExtensions: cfg.Attachments.BlockedExtensions, InspectSignatures: cfg.Attachments.InspectSignatures,
			InspectArchives: cfg.Attachments.InspectArchives, MaxAttachmentBytes: cfg.Attachments.MaxAttachmentBytes,
			MaxArchiveDepth: cfg.Attachments.MaxArchiveDepth, MaxArchiveFiles: cfg.Attachments.MaxArchiveFiles,
			MaxArchiveUncompressedBytes: cfg.Attachments.MaxArchiveUncompressedBytes,
		})
	}

	analysis := &analysisService{
		analyzer: analyzer, ai: cfg.AI, filtering: cfg.Filtering, logging: cfg.Logging,
		mode: cfg.Mode, log: log, slots: make(chan struct{}, cfg.AI.MaxConcurrent),
		domainLookupTimeout: cfg.DomainRegistration.Timeout.Value(), milterTimeout: cfg.Milter.Timeout.Value(),
	}
	policy := &messagePolicyService{
		filtering: cfg.Filtering, correspondentCfg: cfg.Correspondents, mode: cfg.Mode, log: log,
		ipReputation: ipReputation, correspondents: correspondents, rejectionHistory: rejections,
		domainRegistration: domainRegistration, archive: archive,
	}
	attachments := &attachmentPolicyService{
		cfg: cfg.Attachments, filtering: cfg.Filtering, mode: cfg.Mode, log: log,
		scanner: attachmentScanner, slots: make(chan struct{}, attachmentConcurrency(cfg.Milter.MaxConnections)), policy: policy,
	}
	emailCommands := &emailCommandService{
		cfg: cfg.EmailCommands, processor: commands, recipient: normalizeEmailAddress(cfg.EmailCommands.Recipient),
		internalToken: internalToken, replySlots: make(chan struct{}, 4), log: log,
		maxMessageSize: cfg.Milter.MaxMessageSize,
		sender: smtpreply.New(smtpreply.Options{
			Address: cfg.EmailCommands.SMTPHost, TLSMode: cfg.EmailCommands.SMTPTLS, Timeout: commandReplySMTPTimeout,
		}),
	}
	sessions := &sessionDependencies{
		protocol: protocolOptions{
			timeout: cfg.Milter.Timeout.Value(), maxMessageSize: cfg.Milter.MaxMessageSize,
			progressInterval: defaultMilterProgressInterval, mode: cfg.Mode,
		},
		analysis: analysis, policy: policy, attachments: attachments, commands: emailCommands,
		dns: &connectionDNSService{resolver: net.DefaultResolver, timeout: cfg.Milter.ConnectionDNSTimeout.Value(), log: log},
		log: log,
	}
	maintenance := &maintenanceService{
		ip: ipRepository, correspondents: correspondents, rejections: rejections,
		domains: domainRegistration, database: database, archive: archive,
		cleanupInterval: cfg.Persistence.CleanupInterval.Value(), log: log,
	}
	return runtimeComponents{sessions: sessions, maintenance: maintenance, database: database, err: errors.Join(tokenErr, databaseErr)}
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
