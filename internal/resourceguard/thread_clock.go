package resourceguard

import (
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"golang.org/x/sys/unix"
)

// CPUBudget holds the active stage's absolute thread-CPU deadline. Its zero
// value is not ready for Check: callers must call Reset before installing or
// invoking Check and keep the operation on one OS thread. Only the coordinator
// may reset the deadline after an aborted stage has unwound.
type CPUBudget struct {
	deadline time.Duration
}

// threadCPUTime returns CPU time consumed by the calling OS thread.
func threadCPUTime() (time.Duration, bool) {
	var value unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &value)
	return time.Duration(value.Sec*1e9 + value.Nsec), err == nil
}

// ThreadCPUAvailable reports whether this operating environment supplies the
// per-thread CPU clock required for CPU-budget enforcement.
func ThreadCPUAvailable() bool {
	_, ok := threadCPUTime()
	return ok
}

// Reset arms the budget for primary work or an approved fallback from the
// current thread CPU time. The coordinator must call it before each such stage.
// Callers that disable CPU enforcement must not install Check.
func (b *CPUBudget) Reset(maximum time.Duration) {
	if maximum <= 0 {
		panic("resourceguard: non-positive CPU allowance")
	}
	if current, ok := threadCPUTime(); ok {
		const latest = time.Duration(1<<63 - 1)
		b.deadline = latest
		if current <= latest-maximum {
			b.deadline = current + maximum
		}
		return
	}
	// Startup normally rejects an unavailable clock. If a later reset cannot
	// read it, retain fail-open behaviour without adding work to the hot path.
	b.deadline = time.Duration(1<<63 - 1)
}

// Check reads the real thread CPU clock and terminates when the deadline is
// exceeded. Reset must have been called for the current primary or approved
// fallback stage; calling Check on a zero-value budget is invalid. Sampling and
// cancellation are separate from CPU enforcement.
func (b *CPUBudget) Check() {
	var value unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &value)
	current := time.Duration(value.Sec*1e9 + value.Nsec)
	if current > b.deadline {
		termination.Fail(termination.Failure{Code: termination.CPUExceeded})
	}
}
