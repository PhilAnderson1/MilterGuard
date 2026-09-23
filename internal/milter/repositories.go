package milter

import (
	"log/slog"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	storesqlite "github.com/PhilAnderson1/MilterGuard/internal/stores/sqlite"
)

func correspondentFeaturesEnabled(cfg config.CorrespondentsConfig) bool {
	return cfg.LearnAuthenticatedRecipients || cfg.LearnLegitimateSenders || cfg.UseAllowlist
}

func rejectionHistoryEnabled(cfg config.RejectionHistoryConfig) bool { return cfg.Expiry.Value() > 0 }

func newRejectedMailArchive(cfg config.RejectionHistoryConfig, log *slog.Logger) *rejectedmail.Archive {
	if !cfg.SaveMessages || !rejectionHistoryEnabled(cfg) {
		return nil
	}
	return rejectedmail.New(rejectedmail.Options{
		Directory: cfg.MessageDirectory, Retention: cfg.Expiry.Value(), MaxTotalBytes: cfg.MessageMaxTotalBytes,
	}, log)
}

func newCorrespondentRepository(cfg config.CorrespondentsConfig, db *sqlitedb.Store, now func() time.Time, log *slog.Logger) stores.CorrespondentRepository {
	return storesqlite.NewCorrespondents(db, storesqlite.CorrespondentOptions{
		LearnAuthenticatedRecipients: cfg.LearnAuthenticatedRecipients,
		LearnLegitimateSenders:       cfg.LearnLegitimateSenders,
		UseAllowlist:                 cfg.UseAllowlist,
		Scope:                        cfg.Scope,
		MaxEntries:                   cfg.MaxEntries,
		StaleAfter:                   cfg.StaleAfter.Value(),
		ActivityUpdateInterval:       cfg.ActivityUpdateInterval.Value(),
		LegitimateSenderMinScore:     cfg.LegitimateSenderMinScore,
		LegitimateSenderMinMessages:  cfg.LegitimateSenderMinMessages,
		LegitimateSenderRequireDKIM:  cfg.LegitimateSenderRequireDKIM,
		Now:                          now,
	}, log)
}

func newRejectionRepository(cfg config.RejectionHistoryConfig, db *sqlitedb.Store, now func() time.Time, log *slog.Logger) stores.RejectionHistoryRepository {
	return storesqlite.NewRejections(db, storesqlite.RejectionOptions{
		Expiry: cfg.Expiry.Value(), MaxEntries: cfg.MaxEntries, Now: now,
	}, log)
}

func newDomainRepository(cfg config.DomainRegistrationConfig, db *sqlitedb.Store, now func() time.Time) stores.DomainRegistrationCache {
	return storesqlite.NewDomains(db, storesqlite.DomainOptions{
		MaxEntries: cfg.MaxEntries, ExpiryGrace: domainRegistrationExpiryGrace, Now: now,
	})
}

func newIPRepository(cfg config.IPReputationConfig, db *sqlitedb.Store, now func() time.Time, log *slog.Logger) stores.PersistentIPReputationRepository {
	return storesqlite.NewIPReputation(db, storesqlite.IPReputationOptions{
		BlockDuration:          cfg.BlockDuration.Value(),
		RepeatThreshold:        cfg.RepeatThreshold,
		RepeatWindow:           cfg.RepeatWindow.Value(),
		RepeatBlockDuration:    cfg.RepeatBlockDuration.Value(),
		RepeatRefreshOnAttempt: cfg.RepeatRefreshOnAttempt,
		LegitimatePerStrike:    cfg.LegitimatePerStrike,
		MaxEntries:             cfg.MaxEntries,
		Now:                    now,
	}, log)
}

func emailAddressDomain(address string) string {
	return mailaddr.Domain(address)
}
