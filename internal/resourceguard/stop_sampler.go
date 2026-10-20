package resourceguard

import (
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"github.com/PhilAnderson1/MilterGuard/internal/threadcpu"
)

// CPUBudget holds the active stage's absolute thread-CPU deadline. The zero
// value disables enforcement. Keep the operation on one OS thread; only the
// coordinator may reset the deadline after an aborted stage has unwound.
type CPUBudget struct {
	deadline time.Duration
}

// Reset starts primary work or approved fallback from the current thread CPU
// time. A zero allowance or an unavailable initial clock disables enforcement.
func (b *CPUBudget) Reset(maximum time.Duration) {
	b.deadline = 0
	if maximum <= 0 {
		return
	}
	if current, ok := threadcpu.Now(); ok {
		const latest = time.Duration(1<<63 - 1)
		b.deadline = latest
		if current <= latest-maximum {
			b.deadline = current + maximum
		}
	}
}

// Check reads the real thread CPU clock and terminates when the deadline is
// exceeded. An unavailable reading is ignored. Sampling and cancellation are
// separate from CPU enforcement.
func (b *CPUBudget) Check() {
	if b.deadline == 0 {
		return
	}
	if current, ok := threadcpu.Now(); ok && current > b.deadline {
		termination.Fail(termination.Failure{Code: termination.CPUExceeded})
	}
}

// StopSampler controls checkpoint frequency only. It belongs to one operation
// and is not concurrent. A nil callback (including the zero value) does nothing.
type StopSampler struct {
	remaining uint32
	reload    uint32
	check     func()
}

// NewStopSampler checks on calls 1, 1+every, 1+2*every, ... . A zero frequency
// is a configuration error, not a way to disable resource enforcement.
func NewStopSampler(every uint32, check func()) StopSampler {
	if every == 0 {
		panic("resourceguard: zero sampling frequency")
	}
	return StopSampler{reload: every - 1, check: check}
}

// Check invokes a checkpoint on calls 1, 1+every, 1+2*every, ... .
// The checkpoint is supplied once during initialization.
func (s *StopSampler) Check() {
	if s.remaining != 0 {
		s.remaining--
		return
	}
	s.remaining = s.reload
	if s.check != nil {
		s.check()
	}
}
