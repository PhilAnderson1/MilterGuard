package milter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
)

const maintenanceDatabaseTimeout = 60 * time.Second
const rejectedMailCleanupInterval = 24 * time.Hour

// cleanupPersistentStores removes expired or excess repository records and
// passively checkpoints the WAL. Startup and the maintenance timer call it.
func (s *maintenanceService) cleanupPersistentStores(parent context.Context, trigger string) error {
	ctx, cancel := context.WithTimeout(parent, maintenanceDatabaseTimeout)
	defer cancel()
	ipDeleted, ipErr := s.ip.Cleanup(ctx)
	contactsDeleted, contactsErr := s.correspondents.Cleanup(ctx)
	rejectionsDeleted, rejectionsErr := s.rejections.Cleanup(ctx)
	domainsDeleted, domainsErr := s.domains.Cleanup(ctx)
	checkpoint, checkpointErr := sqlitedb.CheckpointResult{}, error(nil)
	if s.database != nil {
		checkpoint, checkpointErr = s.database.CheckpointPassive(ctx)
		if checkpointErr != nil && s.log != nil {
			s.log.Warn("SQLite WAL checkpoint failed", "trigger", trigger, "error", checkpointErr)
		}
	}

	if s.log != nil && s.log.Enabled(ctx, slog.LevelDebug) {
		ipRecords, ipCountErr := s.ip.Count(ctx)
		contactRecords, contactCountErr := s.correspondents.Count(ctx)
		rejectionRecords, rejectionCountErr := s.rejections.Count(ctx)
		domainRecords, domainCountErr := s.domains.Count(ctx)
		s.log.Debug("SQLite cleanup completed",
			"trigger", trigger,
			"ip_deleted", ipDeleted,
			"ip_records", ipRecords,
			"contacts_deleted", contactsDeleted,
			"contacts_records", contactRecords,
			"rejections_deleted", rejectionsDeleted,
			"rejections_records", rejectionRecords,
			"domains_deleted", domainsDeleted,
			"domains_records", domainRecords,
			"wal_busy", checkpoint.Busy,
			"wal_frames", checkpoint.LogFrames,
			"wal_checkpointed_frames", checkpoint.CheckpointedFrames)
		if countErr := errors.Join(
			wrapStoreError("count IP reputation", ipCountErr),
			wrapStoreError("count correspondents", contactCountErr),
			wrapStoreError("count rejections", rejectionCountErr),
			wrapStoreError("count domain registrations", domainCountErr),
		); countErr != nil {
			s.log.Warn("SQLite record counts failed", "trigger", trigger, "error", countErr)
		}
	}

	return errors.Join(
		wrapCleanupError("IP reputation", ipErr),
		wrapCleanupError("correspondents", contactsErr),
		wrapCleanupError("rejection history", rejectionsErr),
		wrapCleanupError("domain registrations", domainsErr),
	)
}

func wrapCleanupError(store string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("clean expired %s: %w", store, err)
}

func wrapStoreError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func (s *maintenanceService) startRejectedMailCleanup(ctx context.Context) {
	if s.archive == nil {
		return
	}
	s.runRejectedMailCleanup()
	go func() {
		ticker := time.NewTicker(rejectedMailCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runRejectedMailCleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// runRejectedMailCleanup applies archive retention and target-size limits. It
// is intentionally independent of SQLite rejection-history cleanup.
func (s *maintenanceService) runRejectedMailCleanup() {
	s.runMaintenance("rejected-mail cleanup", func() {
		if err := s.archive.Cleanup(); err != nil {
			s.log.Warn("cannot clean rejected mail archive", "error", err)
		}
	})
}

// runMaintenance contains panics from a background maintenance operation so a
// cleanup defect cannot terminate the mail-filtering service.
func (s *maintenanceService) runMaintenance(name string, operation func()) {
	defer func() {
		if panicValue := recover(); panicValue != nil {
			logRecoveredWorkerPanic(s.log, context.Background(), name, panicValue)
		}
	}()
	operation()
}
