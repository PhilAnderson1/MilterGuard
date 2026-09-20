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
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

type runtimeComponents struct {
	sessions    *sessionDependencies
	maintenance *maintenanceService
	database    *sqlstore.Store
	err         error
}

func buildRuntime(cfg config.Config, analyzer Analyzer, log *slog.Logger) runtimeComponents {
	internalToken := ""
	var tokenErr error
	if cfg.EmailCommands.Enabled && cfg.EmailCommands.SendReplies {
		internalToken, tokenErr = generateInternalToken(rand.Reader)
	}

	var database *sqlstore.Store
	var databaseErr error
	if correspondentFeaturesEnabled(cfg.Correspondents) || ipReputationFeaturesEnabled(cfg.IPReputation) ||
		rejectionHistoryEnabled(cfg.RejectionHistory) || domainRegistrationEnabled(cfg.DomainRegistration) {
		ctx, cancel := context.WithTimeout(context.Background(), maintenanceDatabaseTimeout)
		database, databaseErr = sqlstore.Open(ctx, cfg.Persistence.DatabaseFile, sqlstore.DefaultOptions())
		cancel()
	}

	ipRepository := newIPRepository(cfg.IPReputation, database, time.Now, log)
	correspondents := newCorrespondentRepository(cfg.Correspondents, database, time.Now, log)
	rejections := newRejectionRepository(cfg.RejectionHistory, database, time.Now, log)
	domainCache := newDomainRepository(cfg.DomainRegistration, database, time.Now)
	ipReputation := newIPReputationStore(cfg.IPReputation, ipRepository, log)
	domainRegistration := newDomainRegistrationStore(cfg.DomainRegistration, domainCache, log)

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
