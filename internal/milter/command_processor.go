package milter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	"github.com/PhilAnderson1/MilterGuard/internal/systemdns"
)

// commandProcessor binds administration logic to repositories, archive access,
// and optional reverse-DNS enrichment shared by terminal and email commands.
func commandProcessor(cfg config.Config, correspondents stores.CorrespondentAdminRepository,
	rejections stores.RejectionRepository, ipReputation stores.IPReputationRepository,
	archive *rejectedmail.Archive, resolver dnsResolver, log *slog.Logger) *admincmd.Processor {
	return admincmd.New(admincmd.Dependencies{
		Correspondents: correspondents, Rejections: rejections, IPReputation: ipReputation,
		MessageSource: commandArchiveSource{archive}, IPResolver: &commandIPResolver{resolver: resolver,
			timeout: cfg.Milter.ConnectionDNSTimeout.Value(), log: log},
		MaxMessageSize: cfg.Milter.MaxMessageSize, DatabaseTimeout: commandDatabaseTimeout,
		Logger: log,
	})
}

type commandArchiveSource struct{ archive *rejectedmail.Archive }

func (s commandArchiveSource) ReadWithRecordID(id uint64, rejectedAt time.Time, maxBytes int64) (admincmd.ArchivedMessage, error) {
	if s.archive == nil {
		return admincmd.ArchivedMessage{}, fs.ErrNotExist
	}
	stored, err := s.archive.ReadWithRecordID(id, rejectedAt, maxBytes)
	return admincmd.ArchivedMessage{Contents: stored.Contents, Path: stored.Path}, err
}

// OpenCommandProcessor opens only the persistence, archive and DNS capabilities
// required by standalone command mode. It does not construct a Milter server.
func OpenCommandProcessor(cfg config.Config, log *slog.Logger) (*admincmd.Processor, func() error, error) {
	ctx, cancel := context.WithTimeout(context.Background(), databaseOpenTimeout)
	database, err := sqlitedb.Open(ctx, cfg.Persistence.DatabaseFile, sqlitedb.DefaultOptions())
	cancel()
	if err != nil {
		return nil, nil, err
	}
	var closeOnce sync.Once
	var closeErr error
	closeProcessor := func() error {
		closeOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), commandDatabaseTimeout)
			defer cancel()
			_, checkpointErr := database.CheckpointPassive(ctx)
			closeErr = errors.Join(checkpointErr, database.Close())
		})
		return closeErr
	}
	correspondents := newCorrespondentRepository(cfg.Correspondents, database, time.Now, log)
	rejections := newRejectionRepository(cfg.RejectionHistory, database, time.Now, log)
	ipRepository := newIPRepository(cfg.IPReputation, database, time.Now, log)
	ipPolicy := newIPReputationStore(cfg.IPReputation, ipRepository, log)
	archive := newRejectedMailArchive(cfg.RejectionHistory, log)
	return commandProcessor(cfg, correspondents, rejections, ipPolicy, archive, systemdns.NewResolver(), log), closeProcessor, nil
}

type commandIPResolver struct {
	resolver dnsResolver
	timeout  time.Duration
	log      *slog.Logger
}

func (r *commandIPResolver) ResolveActiveIPHostnames(parent context.Context, entries []stores.IPBlock) []stores.IPBlock {
	if r == nil || len(entries) == 0 || r.resolver == nil || r.timeout <= 0 {
		return entries
	}
	indices := make(chan int)
	var wait sync.WaitGroup
	for range min(8, len(entries)) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range indices {
				addr := entries[index].Address
				if !addr.IsValid() || !netsafety.AddressRoutable(addr) {
					continue
				}
				ctx, cancel := context.WithTimeout(parent, r.timeout)
				names, err := r.reverseLookup(ctx, addr)
				cancel()
				if err != nil {
					continue
				}
				for _, candidate := range names {
					if hostname := netsafety.DNSHostname(candidate); hostname != "" {
						entries[index].Hostname = hostname
						break
					}
				}
			}
		}()
	}
	for index := range entries {
		select {
		case indices <- index:
		case <-parent.Done():
			close(indices)
			wait.Wait()
			return entries
		}
	}
	close(indices)
	wait.Wait()
	return entries
}

func (r *commandIPResolver) reverseLookup(ctx context.Context, addr netip.Addr) (names []string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logRecoveredWorkerPanic(r.log, ctx, "IP command reverse-DNS lookup", recovered, "remote_ip", addr.String())
			err = fmt.Errorf("reverse-DNS lookup panicked")
		}
	}()
	return r.resolver.LookupAddr(ctx, addr.String())
}
