package message

import "github.com/PhilAnderson1/MilterGuard/internal/resourceguard"

// Fallback receives only this stage's resources. It cannot inspect, charge, or
// reset the primary allowance. The caller owns admission and policy decisions.
type fallbackResources struct {
	memory     *resourceguard.Memory
	shouldStop func() bool
	cpuStopped bool
}

func (r *fallbackResources) stopped() bool {
	if r.memory.Exhausted() || r.cpuStopped {
		return true
	}
	if r.shouldStop != nil && r.shouldStop() {
		r.cpuStopped = true
	}
	return r.cpuStopped
}

func (b *extractionBudget) beginFallback() bool {
	if b.fallback != nil {
		return true
	}
	if b.memoryStopped() || b.allowFallback != nil && !b.allowFallback() {
		return false
	}
	b.fallback = &fallbackResources{memory: resourceguard.NewMemory(b.memoryBytesLimit), shouldStop: b.fallbackShouldStop}
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
func (b *extractionBudget) fallbackMemory() *resourceguard.Memory {
	if b.fallback == nil {
		return nil
	}
	return b.fallback.memory
}
