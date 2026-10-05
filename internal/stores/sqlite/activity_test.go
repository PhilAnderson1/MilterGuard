package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func newTestActivityRepository(t *testing.T, now time.Time, expiry time.Duration) (*activityRepository, *sqlitedb.Store) {
	t.Helper()
	db, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "activity.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repository := NewActivity(db, ActivityOptions{Expiry: expiry, Now: func() time.Time { return now }}).(*activityRepository)
	return repository, db
}

func TestActivityRepositoryAggregatesAndAppliesRetention(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	repository, _ := newTestActivityRepository(t, now, 7*24*time.Hour)
	ctx := context.Background()
	events := []stores.ActivityEvent{
		{OccurredAt: now.Add(-time.Hour), EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeAccepted, TokenCost: .1},
		{OccurredAt: now.Add(-2 * time.Hour), EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeRejected, AnalysisFailed: true, TokenCost: .2},
		{OccurredAt: now.Add(-3 * time.Hour), EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeTempfailed, AnalysisFailed: true, TokenCost: .3},
		{OccurredAt: now.Add(-4 * time.Hour), EventType: stores.ActivityEventIPRejection, Outcome: stores.ActivityOutcomeRejected},
		{OccurredAt: now.Add(-5 * time.Hour), EventType: stores.ActivityEventWhitelistAccept, Outcome: stores.ActivityOutcomeAccepted},
		{OccurredAt: now.Add(-6 * time.Hour), EventType: stores.ActivityEventTrustedDomainAccept, Outcome: stores.ActivityOutcomeAccepted},
		{OccurredAt: now.Add(-7 * time.Hour), EventType: stores.ActivityEventAttachmentRejection, Outcome: stores.ActivityOutcomeRejected},
		{OccurredAt: now.Add(-8 * time.Hour), EventType: stores.ActivityEventProtectedSenderDomainRejection, Outcome: stores.ActivityOutcomeRejected},
		{OccurredAt: now.Add(-8 * 24 * time.Hour), EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeAccepted, TokenCost: 99},
	}
	for _, event := range events {
		if err := repository.AddActivity(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := repository.ActivitySummary(ctx, stores.ActivityQuery{Before: now})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ScanTotal != 3 || summary.ScanAccepted != 1 || summary.ScanRejections != 1 || summary.AIEvaluationsFailed != 2 ||
		summary.IPRejections != 1 || summary.WhitelistAccepts != 1 || summary.TrustedDomainAccepts != 1 ||
		summary.AttachmentRejections != 1 || summary.ProtectedSenderDomainRejections != 1 || summary.TokenCost != .6 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestActivityRepositoryAggregationHasNoListingLimit(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	repository, db := newTestActivityRepository(t, now, 24*time.Hour)
	_, err := db.Exec(context.Background(), `WITH RECURSIVE sequence(value) AS (
		VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < 1001
	) INSERT INTO activity (occurred_at_ms, event_type, outcome, analysis_failed, token_cost)
		SELECT ?, ?, ?, 0, 0 FROM sequence`, unixMillis(now.Add(-time.Hour)),
		stores.ActivityEventScan, stores.ActivityOutcomeAccepted)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := repository.ActivitySummary(context.Background(), stores.ActivityQuery{Before: now})
	if err != nil {
		t.Fatal(err)
	}
	if summary.ScanTotal != 1001 || summary.ScanAccepted != 1001 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestActivityRepositoryCleanupAndServiceStatus(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	repository, _ := newTestActivityRepository(t, now, 24*time.Hour)
	ctx := context.Background()
	for _, occurred := range []time.Time{now.Add(-25 * time.Hour), now.Add(-time.Hour)} {
		if err := repository.AddActivity(ctx, stores.ActivityEvent{OccurredAt: occurred, EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeAccepted}); err != nil {
			t.Fatal(err)
		}
	}
	deleted, err := repository.CleanupActivity(ctx)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup deleted %d, err = %v", deleted, err)
	}
	if count, err := repository.CountActivity(ctx); err != nil || count != 1 {
		t.Fatalf("count = %d, err = %v", count, err)
	}
	if _, found, err := repository.ServiceStatus(ctx); err != nil || found {
		t.Fatalf("initial status found=%t err=%v", found, err)
	}
	status := stores.ServiceStatus{StartedAt: now.Add(-time.Hour), Mode: stores.ServiceModeEnforce}
	if err := repository.SetServiceStatus(ctx, status); err != nil {
		t.Fatal(err)
	}
	got, found, err := repository.ServiceStatus(ctx)
	if err != nil || !found || !got.StartedAt.Equal(status.StartedAt) || got.Mode != status.Mode {
		t.Fatalf("status = %+v, found=%t err=%v", got, found, err)
	}
	if err := repository.ClearServiceStatus(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, err := repository.ServiceStatus(ctx); err != nil || found {
		t.Fatalf("cleared status found=%t err=%v", found, err)
	}
}

func TestActivityRepositoryEnforcesEventConstraints(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	repository, _ := newTestActivityRepository(t, now, time.Hour)
	for _, event := range []stores.ActivityEvent{
		{EventType: stores.ActivityEventWhitelistAccept, Outcome: stores.ActivityOutcomeRejected},
		{EventType: stores.ActivityEventAttachmentRejection, Outcome: stores.ActivityOutcomeAccepted},
		{EventType: 99, Outcome: stores.ActivityOutcomeAccepted},
	} {
		if err := repository.AddActivity(context.Background(), event); err == nil {
			t.Fatalf("invalid event was inserted: %+v", event)
		}
	}
}
