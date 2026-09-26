package milter

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth/moxverify"
)

const maxShadowSummaryValues = 32

var errShadowAuthenticationPanic = errors.New("shadow authentication panic")

type shadowMethodSummary struct {
	present         bool
	outcome         mailauth.Outcome
	aligned         bool
	passDomains     []string
	errorCategories []string
	reasons         []string
}

type shadowMethodComparison struct {
	compared       bool
	outcomeMatch   bool
	alignmentMatch bool
	detailsMatch   bool
	trusted        shadowMethodSummary
	internal       shadowMethodSummary
}

type shadowComparison struct {
	matched           bool
	detailsMatched    bool
	comparedMethods   int
	differences       []string
	detailDifferences []string
	methods           map[mailauth.Method]shadowMethodComparison
}

func compareShadowAuthentication(trusted, internal mailauth.Evidence) shadowComparison {
	comparison := shadowComparison{matched: true, detailsMatched: true, methods: make(map[mailauth.Method]shadowMethodComparison, 3)}
	for _, method := range []mailauth.Method{mailauth.MethodSPF, mailauth.MethodDKIM, mailauth.MethodDMARC} {
		trustedSummary := summarizeShadowMethod(trusted, method)
		internalSummary := summarizeShadowMethod(internal, method)
		compared := trustedSummary.present
		outcomeMatch := !compared || trustedSummary.outcome == internalSummary.outcome
		alignmentMatch := !compared || trustedSummary.aligned == internalSummary.aligned
		detailsMatch := true
		if compared && outcomeMatch && trustedSummary.outcome == mailauth.OutcomePass && len(trustedSummary.passDomains) > 0 {
			detailsMatch = slices.Equal(trustedSummary.passDomains, internalSummary.passDomains)
		}
		methodComparison := shadowMethodComparison{
			compared: compared, outcomeMatch: outcomeMatch, alignmentMatch: alignmentMatch, detailsMatch: detailsMatch,
			trusted: trustedSummary, internal: internalSummary,
		}
		comparison.methods[method] = methodComparison
		if !compared {
			continue
		}
		comparison.comparedMethods++
		if !outcomeMatch || !alignmentMatch {
			comparison.matched = false
			comparison.differences = append(comparison.differences, string(method))
		}
		if !detailsMatch {
			comparison.detailsMatched = false
			comparison.detailDifferences = append(comparison.detailDifferences, string(method))
		}
	}
	return comparison
}

func summarizeShadowMethod(evidence mailauth.Evidence, method mailauth.Method) shadowMethodSummary {
	summary := shadowMethodSummary{outcome: mailauth.OutcomeNone}
	priority := -1
	passDomains := make(map[string]bool)
	errorCategories := make(map[string]bool)
	reasons := make(map[string]bool)
	for _, result := range evidence.Results {
		if result.Method != method {
			continue
		}
		summary.present = true
		if current := shadowOutcomePriority(result.Outcome); current > priority {
			priority = current
			summary.outcome = result.Outcome
		}
		if result.Outcome == mailauth.OutcomePass {
			if domain := mailauth.NormalizeDomain(result.Domain); domain != "" {
				passDomains[domain] = true
			}
		}
		if result.ErrorCategory != mailauth.ErrorNone {
			errorCategories[string(result.ErrorCategory)] = true
		}
		if result.Reason != "" {
			reasons[result.Reason] = true
		}
	}
	for domain := range passDomains {
		summary.passDomains = append(summary.passDomains, domain)
	}
	for category := range errorCategories {
		summary.errorCategories = append(summary.errorCategories, category)
	}
	for reason := range reasons {
		summary.reasons = append(summary.reasons, reason)
	}
	slices.Sort(summary.passDomains)
	slices.Sort(summary.errorCategories)
	slices.Sort(summary.reasons)
	if len(summary.passDomains) > maxShadowSummaryValues {
		summary.passDomains = summary.passDomains[:maxShadowSummaryValues]
	}
	if len(summary.errorCategories) > maxShadowSummaryValues {
		summary.errorCategories = summary.errorCategories[:maxShadowSummaryValues]
	}
	if len(summary.reasons) > maxShadowSummaryValues {
		summary.reasons = summary.reasons[:maxShadowSummaryValues]
	}
	switch method {
	case mailauth.MethodDKIM:
		summary.aligned = evidence.DKIMAligned
	case mailauth.MethodDMARC:
		summary.aligned = evidence.DMARCAligned
	}
	return summary
}

func shadowOutcomePriority(outcome mailauth.Outcome) int {
	for index, candidate := range []mailauth.Outcome{
		mailauth.OutcomeNone, mailauth.OutcomeNeutral, mailauth.OutcomeSoftfail,
		mailauth.OutcomeFail, mailauth.OutcomePolicy, mailauth.OutcomePermerror,
		mailauth.OutcomeTemperror, mailauth.OutcomePass,
	} {
		if outcome == candidate {
			return index
		}
	}
	return 0
}

func (ss *session) verifyShadowAuthentication(ctx context.Context, verifier mailauth.Verifier, transaction mailauth.Transaction) (evidence mailauth.Evidence, err error) {
	defer func() {
		if panicValue := recover(); panicValue != nil {
			logRecoveredWorkerPanic(ss.deps.log, ctx, "shadow authentication verification", panicValue)
			evidence = mailauth.Evidence{}
			err = fmt.Errorf("%w: %v", errShadowAuthenticationPanic, panicValue)
		}
	}()
	return verifier.Verify(ctx, transaction)
}

func (ss *session) logShadowAuthenticationComparison(ctx context.Context, trusted, internal mailauth.Evidence, shadowErr error, duration time.Duration) {
	comparison := compareShadowAuthentication(trusted, internal)
	completed := shadowErr == nil
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"completed", completed,
		"matched", completed && comparison.matched,
		"details_matched", completed && comparison.detailsMatched,
		"compared_methods", comparison.comparedMethods,
		"differences", comparison.differences,
		"detail_differences", comparison.detailDifferences,
		"duration_ms", duration.Milliseconds(),
		"shadow_error", shadowAuthenticationErrorCategory(shadowErr),
	}
	for _, method := range []mailauth.Method{mailauth.MethodSPF, mailauth.MethodDKIM, mailauth.MethodDMARC} {
		methodComparison := comparison.methods[method]
		attrs = append(attrs, shadowMethodLogGroup(string(method), methodComparison))
	}
	ss.deps.log.InfoContext(ctx, "authentication shadow comparison", attrs...)
}

func shadowMethodLogGroup(name string, comparison shadowMethodComparison) slog.Attr {
	return slog.Group(name,
		"compared", comparison.compared,
		"outcome_match", comparison.outcomeMatch,
		"alignment_match", comparison.alignmentMatch,
		"details_match", comparison.detailsMatch,
		"trusted_outcome", string(comparison.trusted.outcome),
		"internal_outcome", string(comparison.internal.outcome),
		"trusted_aligned", comparison.trusted.aligned,
		"internal_aligned", comparison.internal.aligned,
		"trusted_pass_domains", comparison.trusted.passDomains,
		"internal_pass_domains", comparison.internal.passDomains,
		"internal_error_categories", comparison.internal.errorCategories,
		"internal_reasons", comparison.internal.reasons,
	)
}

func shadowAuthenticationErrorCategory(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errShadowAuthenticationPanic):
		return "panic"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, moxverify.ErrMessageUnavailable):
		return "message-unavailable"
	default:
		return "verification"
	}
}
