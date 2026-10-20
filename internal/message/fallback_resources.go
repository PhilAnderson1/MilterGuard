package message

import (
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

// Fallback receives only this stage's resources. It cannot inspect, charge, or
// reset the primary allowance. The caller owns admission and policy decisions.
type fallbackResources struct {
	prefix string

	check       func()
	memory      *resourceguard.Memory
	cpuStopped  bool
	textStop    func()
	textSampler resourceguard.StopSampler
}

// Tokenizer callbacks retain their existing sampling. Only helpers owned by
// this package share this sampler, avoiding nested sampling intervals.
func (r *fallbackResources) textStopCallback() func() {
	if r.textStop == nil {
		r.textSampler = resourceguard.NewStopSampler(10, r.check)
		r.textStop = resourceguard.BindCheckpoint(r.memory, r, func(r *fallbackResources) {
			r.textSampler.Check()
		})
	}
	return r.textStop
}

func (r *fallbackResources) checkpoint() {
	if r.check != nil {
		r.check()
	}
}

func (b *extractionBudget) beginFallback() bool {
	if b.terminal.Code != termination.None {
		return false
	}
	if b.fallback != nil {
		return true
	}
	if b.memoryStopped() || b.allowFallback != nil && !b.allowFallback() {
		return false
	}
	b.fallback = &fallbackResources{memory: b.newMemory(b.memoryBytesLimit), check: b.checkFallback}
	return true
}

func (b *extractionBudget) observeFallback() {
	if b.fallback == nil {
		return
	}
	if b.fallback.cpuStopped {
		b.cpuLimitExceeded = true
	}
	if b.fallback.memory.Exhausted() && !b.fallbackMemoryExceeded {
		b.fallbackMemoryExceeded = true
		if b.onFallbackMemoryLimit != nil {
			b.onFallbackMemoryLimit()
		}
	}
}

// Shared MIME/output work asks the coordinator for its current allocation
// owner. It never receives the primary ledger while fallback is active.
func (b *extractionBudget) allocationMemory() *resourceguard.Memory {
	if b.fallback != nil {
		return b.fallback.memory
	}
	return b.primaryMemory
}
