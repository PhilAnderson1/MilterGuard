package message

import (
	"context"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

// ProcessingUsage records resource outcomes at extraction boundaries.
type ProcessingUsage struct {
	PrimaryCPUExceeded     bool
	FallbackCPUExceeded    bool
	MemoryExceeded         bool
	PrimaryMemoryExceeded  bool
	FallbackMemoryExceeded bool
	PrimaryMemoryBytes     int64
	FallbackMemoryBytes    int64
}

func (u ProcessingUsage) CPUExceeded() bool { return u.PrimaryCPUExceeded || u.FallbackCPUExceeded }

// ProcessingLimits supplies resource allowances and fallback policy for one extraction.
// A non-positive CPU allowance disables CPU enforcement, but not cancellation.
type ProcessingLimits struct {
	AllowFallbackAfterLimit bool
	MemoryBytes             int64
	MaxCPUMilliseconds      int
	DisableURLCompaction    bool
	OnHTMLParserPanic       func()
}

// WithProcessingLimits supplies the common cancellation, CPU, memory,
// and fallback policy for live and archived message extraction. The extract
// callback must use message extraction APIs that establish termination boundaries.
// Controls are valid only during the synchronous callback on the calling goroutine.
func WithProcessingLimits[T any](ctx context.Context, options ProcessingLimits, extract func(HTMLProcessingControl) T) (T, ProcessingUsage) {
	var usage ProcessingUsage
	continueAfterLimit := options.AllowFallbackAfterLimit
	control := HTMLProcessingControl{
		DisableURLCompaction:        options.DisableURLCompaction,
		MemoryBytes:                 options.MemoryBytes,
		StopOnMemoryLimit:           !continueAfterLimit,
		MemoryLimitExceeded:         func() { usage.MemoryExceeded = true; usage.PrimaryMemoryExceeded = true },
		FallbackMemoryLimitExceeded: func() { usage.MemoryExceeded = true; usage.FallbackMemoryExceeded = true },
		HTMLParserPanic:             options.OnHTMLParserPanic,
		ObserveMemoryUsage:          func(used, _ int64) { usage.PrimaryMemoryBytes = used },
		ObserveFallbackMemoryUsage:  func(used, _ int64) { usage.FallbackMemoryBytes = used },
	}
	maximum := time.Duration(options.MaxCPUMilliseconds) * time.Millisecond
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
			usage.FallbackCPUExceeded = true
		} else {
			usage.PrimaryCPUExceeded = true
		}
	}
	control.BeginFallback = func() bool {
		if ctx.Err() != nil || (usage.PrimaryCPUExceeded || usage.PrimaryMemoryExceeded) && !continueAfterLimit {
			return false
		}
		if maximum > 0 {
			budget.Reset(maximum)
		}
		return true
	}
	return extract(control), usage
}
