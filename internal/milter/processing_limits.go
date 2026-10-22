package milter

import (
	"context"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

// Resource outcomes are recorded at extraction boundaries.
type htmlProcessingUsage struct {
	primaryCPUExceeded     bool
	fallbackCPUExceeded    bool
	memoryExceeded         bool
	primaryMemoryExceeded  bool
	fallbackMemoryExceeded bool
	primaryMemoryBytes     int64
	fallbackMemoryBytes    int64
}

func (u htmlProcessingUsage) cpuExceeded() bool { return u.primaryCPUExceeded || u.fallbackCPUExceeded }

type htmlProcessingOptions struct {
	action               string
	memoryBytes          int64
	maxCPUMilliseconds   int
	disableURLCompaction bool
}

// runWithHTMLProcessingLimits supplies the common cancellation, CPU, memory,
// and fallback policy used by both ordinary and command-message extraction.
func runWithHTMLProcessingLimits[T any](ctx context.Context, options htmlProcessingOptions, extract func(message.HTMLProcessingControl) T) (T, htmlProcessingUsage) {
	var usage htmlProcessingUsage
	continueAfterLimit := options.action == "fallback"
	control := message.HTMLProcessingControl{
		DisableURLCompaction:        options.disableURLCompaction,
		MemoryBytes:                 options.memoryBytes,
		StopOnMemoryLimit:           !continueAfterLimit,
		MemoryLimitExceeded:         func() { usage.memoryExceeded = true; usage.primaryMemoryExceeded = true },
		FallbackMemoryLimitExceeded: func() { usage.memoryExceeded = true; usage.fallbackMemoryExceeded = true },
		ObserveMemoryUsage:          func(used, _ int64) { usage.primaryMemoryBytes = used },
		ObserveFallbackMemoryUsage:  func(used, _ int64) { usage.fallbackMemoryBytes = used },
	}
	maximum := time.Duration(options.maxCPUMilliseconds) * time.Millisecond
	if maximum > 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	var budget resourceguard.CPUBudget
	checkCancellation := func() {
		if ctx.Err() != nil {
			termination.Fail(termination.Failure{Code: termination.Cancelled})
		}
	}
	check := checkCancellation
	if maximum > 0 {
		budget.Reset(maximum)
		check = func() {
			checkCancellation()
			budget.Check()
		}
	}
	control.CheckPrimary = check
	control.CheckFallback = check
	control.CPULimitExceeded = func(fallback bool) {
		if fallback {
			usage.fallbackCPUExceeded = true
		} else {
			usage.primaryCPUExceeded = true
		}
	}
	control.BeginFallback = func() bool {
		if ctx.Err() != nil || (usage.primaryCPUExceeded || usage.primaryMemoryExceeded) && !continueAfterLimit {
			return false
		}
		if maximum > 0 {
			budget.Reset(maximum)
		}
		return true
	}
	return extract(control), usage
}
