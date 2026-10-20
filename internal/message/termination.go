package message

import (
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

// Stage boundaries belong to restartable operations, not parser helpers.
// The coordinator admits fallback once; callbacks only measure and terminate.
func runExtraction[T any](b *extractionBudget, work func() T) (result T, complete bool) {
	if b.terminal.Code != termination.None {
		return result, false
	}
	result, failure := attemptExtraction(b, work)
	fallback := b.fallback != nil
	if failure.Code == termination.None {
		return result, true
	}
	b.recordTermination(failure, fallback)
	if fallback || failure.Code == termination.Cancelled || !b.beginFallback() {
		b.terminal = failure
		return result, false
	}
	result, failure = attemptExtraction(b, work)
	if failure.Code == termination.None {
		return result, true
	}
	b.recordTermination(failure, true)
	return result, false
}

func (b *extractionBudget) recordTermination(f termination.Failure, fallback bool) {
	switch f.Code {
	case termination.CPUExceeded:
		b.cpuLimitExceeded = true
		if fallback {
			b.fallback.cpuStopped = true
		}
		if b.onCPULimit != nil {
			b.onCPULimit(fallback)
		}
	case termination.MemoryExceeded:
		if fallback {
			b.observeFallback()
		} else {
			b.noteMemoryLimit()
		}
	}
	if fallback || f.Code == termination.Cancelled {
		b.terminal = f
	}
}

func (b *extractionBudget) checkStage() {
	if b.fallback != nil {
		b.fallback.checkpoint()
		return
	}
	if b.checkPrimary != nil {
		b.checkPrimary()
	}
}

func (b *extractionBudget) newMemory(limit int64) *resourceguard.Memory {
	return resourceguard.NewMemory(limit)
}

// Admit the one escaping checkpoint callback inside the stage boundary.
// The callback belongs to the message and is reused across parts and stages.
func attemptExtraction[T any](b *extractionBudget, work func() T) (result T, failure termination.Failure) {
	defer termination.Recover(&failure)
	if b.stageStop == nil {
		b.stageStop = resourceguard.BindCheckpoint(b.allocationMemory(), b, (*extractionBudget).checkStage)
	}
	return work(), failure
}

// Remaining primary allowance includes MIME buffers and previously completed
// HTML/rendering operations. Fallback always has an independent ledger.
func (b *extractionBudget) remainingMemory() int64 {
	return remainingInt64(b.primaryMemory.Limit(), b.primaryMemory.Used())
}
