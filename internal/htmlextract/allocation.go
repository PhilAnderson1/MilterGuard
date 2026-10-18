package htmlextract

import (
	"strings"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

const stringWorkChunk = 4096

// writeBudgetedString admits each complete replacement buffer. Rebuilding
// explicitly also lets large copies sample the existing CPU guard.
func writeBudgetedString(out *strings.Builder, text string, budget *cpuGuard) bool {
	write := func(s string) bool {
		for len(s) > stringWorkChunk {
			if budget.stopNow(true) {
				return false
			}
			out.WriteString(s[:stringWorkChunk])
			s = s[stringWorkChunk:]
		}
		out.WriteString(s)
		return true
	}
	if !growBuilder(out, len(text), budget) {
		return false
	}
	return write(text)
}

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

// indexByteWithBudget preserves the allocation-free standard-library scan while
// bounding the amount of input processed between cancellation samples.
func indexByteWithBudget(s string, target byte, budget *cpuGuard) int {
	for start := 0; start < len(s); start += stringWorkChunk {
		if len(s) > stringWorkChunk && budget.stopNow(true) {
			return -1
		}
		if i := strings.IndexByte(s[start:min(start+stringWorkChunk, len(s))], target); i >= 0 {
			return start + i
		}
	}
	return -1
}

func growBuilder(out *strings.Builder, additional int, budget *cpuGuard) bool {
	if budget.stopNow(false) {
		return false
	}
	if additional <= out.Cap()-out.Len() {
		return true
	}
	capacity := 2*out.Cap() + additional
	if !budget.reserve(int64(capacity)) {
		return false
	}
	previous := out.String()
	out.Reset()
	out.Grow(capacity)
	// Grow may expose more capacity than requested. Reconcile immediately,
	// before copying or allowing later writes to use that extra storage.
	// If it does not fit, only this allocation's excess has happened already;
	// the latched failure prevents further allocations through the guard.
	if !budget.reserve(int64(out.Cap() - capacity)) {
		out.Reset()
		return false
	}
	return writeBudgetedString(out, previous, budget)
}

func writeBudgetedBytes(out *strings.Builder, data []byte, budget *cpuGuard) bool {
	if !growBuilder(out, len(data), budget) {
		return false
	}
	for len(data) > stringWorkChunk {
		if budget.stopNow(true) {
			return false
		}
		out.Write(data[:stringWorkChunk])
		data = data[stringWorkChunk:]
	}
	out.Write(data)
	return true
}

// ownedString and the string transformation helpers return an empty result on
// resource failure. The shared guard latches failure; Analyze rejects the
// document rather than treating a partial helper result as a successful parse.
func ownedString(data []byte, budget *cpuGuard) string {
	var out strings.Builder
	if !writeBudgetedBytes(&out, data, budget) {
		return ""
	}
	return out.String()
}

// mapEntryAllocationBytes covers spare capacity, replacement tables and
// allocation overhead. The monotonic budget counts old tables even after map
// growth replaces them. This conservative allowance is not Go's exact layout.
func mapEntryAllocationBytes[K comparable, V any]() int64 {
	var key K
	var value V
	return 4*int64(unsafe.Sizeof(key)+unsafe.Sizeof(value)) + 64
}
