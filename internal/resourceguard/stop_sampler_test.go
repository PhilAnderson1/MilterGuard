package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"runtime"
	"testing"
	"time"
)

func TestStopSamplerFrequency(t *testing.T) {
	for _, frequency := range []uint32{1, 10, 256} {
		calls := 0
		sampler := NewStopSampler(frequency, func() { calls++ })
		for i := uint32(1); i <= frequency*3; i++ {
			sampler.Check()
			if calls != int((i-1)/frequency+1) {
				t.Fatalf("frequency=%d call=%d checks=%d", frequency, i, calls)
			}
		}
	}
	var zero StopSampler
	zero.Check()
	disabled := NewStopSampler(10, nil)
	disabled.Check()
}

func TestStopSamplerRejectsZeroFrequency(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("zero frequency accepted")
		}
	}()
	NewStopSampler(0, nil)
}
func TestStopSamplerUnwinds(t *testing.T) {
	var failure termination.Failure
	calls := 0
	sampler := NewStopSampler(10, func() {
		calls++
		if calls == 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	})
	func() {
		defer termination.Recover(&failure)
		for range 100 {
			sampler.Check()
		}

		t.Fatal("continued after CPU failure")
	}()
	if failure.Code != termination.CPUExceeded || calls != 2 {
		t.Fatalf("failure=%+v calls=%d", failure, calls)
	}
}

func TestCPUBudgetDeadlineAndFallbackReset(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ThreadCPUAvailable() {
		t.Skip("thread CPU clock unavailable")
	}
	budget := CPUBudget{deadline: 1}
	expectTermination(t, termination.CPUExceeded, budget.Check)
	budget.Reset(time.Second)
	budget.Check()
	budget.deadline = 1
	expectTermination(t, termination.CPUExceeded, budget.Check)
	budget.Reset(time.Second)
	budget.Check()
}

func TestCPUBudgetRejectsNonPositiveAllowance(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("non-positive CPU allowance accepted")
		}
	}()
	var budget CPUBudget
	budget.Reset(0)
}

func TestCPUBudgetDeadlineDoesNotOverflow(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if !ThreadCPUAvailable() {
		t.Skip("thread CPU clock unavailable")
	}
	var budget CPUBudget
	const latest = time.Duration(1<<63 - 1)
	budget.Reset(latest)
	if budget.deadline != latest {
		t.Fatalf("overflowed deadline: %v", budget.deadline)
	}
	budget.Check()
}
