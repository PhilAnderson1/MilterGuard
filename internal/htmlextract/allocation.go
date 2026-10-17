package htmlextract

import (
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// growSlice reserves the complete new backing array, not just its capacity
// delta: the monotonic budget counts allocations even after storage is replaced.
func growSlice[T any](slice []T, additional int, memory *resourceguard.Memory) ([]T, bool) {
	needed := len(slice) + additional
	if needed <= cap(slice) {
		return slice, true
	}
	capacity := max(needed, max(1, cap(slice)*2))
	var value T
	if !memory.Reserve(int64(capacity) * int64(unsafe.Sizeof(value))) {
		return slice, false
	}
	grown := make([]T, len(slice), capacity)
	copy(grown, slice)
	return grown, true
}

func (g *cpuGuard) allocationMemory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.memory
}
