package milter

import (
	"context"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func activityOutcome(selected action, responseErr error) stores.ActivityOutcome {
	if responseErr != nil {
		return stores.ActivityOutcomeResponseFailed
	}
	switch selected {
	case actionReject:
		return stores.ActivityOutcomeRejected
	case actionTempfail:
		return stores.ActivityOutcomeTempfailed
	default:
		return stores.ActivityOutcomeAccepted
	}
}

func (s *activityService) record(parent context.Context, event stores.ActivityEvent) {
	if s == nil || s.repository == nil {
		return
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	ctx, cancel := postDecisionContext(parent)
	defer cancel()
	if err := s.repository.AddActivity(ctx, event); err != nil && s.log != nil {
		s.log.ErrorContext(ctx, "cannot record activity", "event_type", event.EventType, "error", err)
	}
}

func (s *activityService) recordScan(ctx context.Context, result evaluationResult, responseErr error) {
	s.record(ctx, stores.ActivityEvent{
		EventType: stores.ActivityEventScan, Outcome: activityOutcome(result.selected, responseErr),
		AnalysisFailed: result.err != nil, TokenCost: result.tokenCost,
	})
}

func (s *activityService) recordDeterministic(ctx context.Context, eventType stores.ActivityEventType, selected action, responseErr error) {
	s.record(ctx, stores.ActivityEvent{EventType: eventType, Outcome: activityOutcome(selected, responseErr)})
}
