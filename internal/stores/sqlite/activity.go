package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type activityRepository struct {
	db     *sqlitedb.Store
	expiry time.Duration
	now    func() time.Time
}

// NewActivity binds activity-event aggregation, expiry, and serving-process
// status to the shared SQLite database.
func NewActivity(db *sqlitedb.Store, options ActivityOptions) stores.ActivityRepository {
	return &activityRepository{db: db, expiry: options.Expiry, now: clock(options.Now)}
}

var _ stores.ActivityRepository = (*activityRepository)(nil)

func (r *activityRepository) available() bool {
	return r != nil && r.db != nil && r.expiry > 0
}

func (r *activityRepository) AddActivity(ctx context.Context, event stores.ActivityEvent) error {
	if !r.available() {
		return fmt.Errorf("activity repository is unavailable")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = r.now().UTC()
	}
	if math.IsNaN(event.TokenCost) || math.IsInf(event.TokenCost, 0) || event.TokenCost < 0 {
		return fmt.Errorf("activity token cost must be finite and nonnegative")
	}
	var failed, cost any
	if event.EventType == stores.ActivityEventScan {
		failed, cost = event.AnalysisFailed, event.TokenCost
	}
	_, err := r.db.Exec(ctx, `INSERT INTO activity
		(occurred_at_ms, event_type, outcome, analysis_failed, token_cost)
		VALUES (?, ?, ?, ?, ?)`, unixMillis(event.OccurredAt), event.EventType, event.Outcome, failed, cost)
	if err != nil {
		return fmt.Errorf("insert activity event: %w", err)
	}
	return nil
}

func (r *activityRepository) ActivitySummary(ctx context.Context, query stores.ActivityQuery) (stores.ActivitySummary, error) {
	if !r.available() {
		return stores.ActivitySummary{}, fmt.Errorf("activity repository is unavailable")
	}
	now := r.now().UTC()
	since := query.Since.UTC()
	retainedSince := now.Add(-r.expiry)
	if since.IsZero() || since.Before(retainedSince) {
		since = retainedSince
	}
	before := query.Before.UTC()
	if before.IsZero() || before.After(now) {
		before = now
	}
	var summary stores.ActivitySummary
	err := r.db.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE event_type = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND analysis_failed = 1),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		count(*) FILTER (WHERE event_type = ? AND outcome = ?),
		coalesce(sum(token_cost) FILTER (WHERE event_type = ?), 0)
		FROM activity WHERE occurred_at_ms >= ? AND occurred_at_ms < ?`,
		stores.ActivityEventScan,
		stores.ActivityEventScan, stores.ActivityOutcomeRejected,
		stores.ActivityEventScan, stores.ActivityOutcomeAccepted,
		stores.ActivityEventScan,
		stores.ActivityEventIPRejection, stores.ActivityOutcomeRejected,
		stores.ActivityEventCorrespondentAccept, stores.ActivityOutcomeAccepted,
		stores.ActivityEventTrustedDomainAccept, stores.ActivityOutcomeAccepted,
		stores.ActivityEventAttachmentRejection, stores.ActivityOutcomeRejected,
		stores.ActivityEventProtectedSenderDomainRejection, stores.ActivityOutcomeRejected,
		stores.ActivityEventScan,
		unixMillis(since), unixMillis(before)).Scan(
		&summary.ScanTotal, &summary.ScanRejections, &summary.ScanAccepted,
		&summary.AIEvaluationsFailed, &summary.IPRejections, &summary.CorrespondentAccepts,
		&summary.TrustedDomainAccepts, &summary.AttachmentRejections,
		&summary.ProtectedSenderDomainRejections, &summary.TokenCost)
	if err != nil {
		return stores.ActivitySummary{}, fmt.Errorf("aggregate activity: %w", err)
	}
	return summary, nil
}

func (r *activityRepository) CleanupActivity(ctx context.Context) (int64, error) {
	if !r.available() {
		return 0, nil
	}
	result, err := r.db.Exec(ctx, `DELETE FROM activity WHERE occurred_at_ms < ?`, unixMillis(r.now().UTC().Add(-r.expiry)))
	if err != nil {
		return 0, fmt.Errorf("delete expired activity: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted activity: %w", err)
	}
	return deleted, nil
}

func (r *activityRepository) CountActivity(ctx context.Context) (int, error) {
	if !r.available() {
		return 0, nil
	}
	var count int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM activity`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count activity: %w", err)
	}
	return count, nil
}

func (r *activityRepository) ServiceStatus(ctx context.Context) (stores.ServiceStatus, bool, error) {
	if !r.available() {
		return stores.ServiceStatus{}, false, fmt.Errorf("activity repository is unavailable")
	}
	var started int64
	var mode stores.ServiceMode
	err := r.db.QueryRow(ctx, `SELECT started_at_ms, mode FROM service_status WHERE id = 1`).Scan(&started, &mode)
	if err == sql.ErrNoRows {
		return stores.ServiceStatus{}, false, nil
	}
	if err != nil {
		return stores.ServiceStatus{}, false, fmt.Errorf("read service status: %w", err)
	}
	return stores.ServiceStatus{StartedAt: timeFromMillis(started), Mode: mode}, true, nil
}

func (r *activityRepository) SetServiceStatus(ctx context.Context, status stores.ServiceStatus) error {
	if !r.available() {
		return fmt.Errorf("activity repository is unavailable")
	}
	_, err := r.db.Exec(ctx, `INSERT INTO service_status (id, started_at_ms, mode)
		VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET
		started_at_ms = excluded.started_at_ms, mode = excluded.mode`, unixMillis(status.StartedAt), status.Mode)
	if err != nil {
		return fmt.Errorf("set service status: %w", err)
	}
	return nil
}

func (r *activityRepository) ClearServiceStatus(ctx context.Context) error {
	if !r.available() {
		return nil
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM service_status WHERE id = 1`); err != nil {
		return fmt.Errorf("clear service status: %w", err)
	}
	return nil
}
