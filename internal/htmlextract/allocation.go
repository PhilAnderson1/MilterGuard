package htmlextract

import (
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

const stringWorkChunk = resourceguard.WorkChunk

func (g *cpuGuard) allocationMemory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.memory
}
func (g *cpuGuard) allocationStop() bool { return g.stopNow(true) }

// These adapters only translate the extractor's cancellation/failure convention.
func growSlice[T any](s []T, additional int, m *resourceguard.Memory, stops ...resourceguard.Stop) ([]T, bool) {
	var stop resourceguard.Stop
	if len(stops) != 0 {
		stop = stops[0]
	}
	return resourceguard.GrowSlice(m, s, additional, stop)
}
func growBuilder(out *strings.Builder, additional int, budget *cpuGuard) bool {
	return !budget.stopNow(false) && resourceguard.GrowText(budget.allocationMemory(), out, additional, budget.allocationStop)
}
func writeBudgetedString(out *strings.Builder, text string, budget *cpuGuard) bool {
	return !budget.stopNow(false) && resourceguard.WriteString(budget.allocationMemory(), out, text, budget.allocationStop)
}
func writeBudgetedBytes(out *strings.Builder, data []byte, budget *cpuGuard) bool {
	return !budget.stopNow(false) && resourceguard.WriteBytes(budget.allocationMemory(), out, data, budget.allocationStop)
}
func ownedString(data []byte, budget *cpuGuard) string {
	if budget.stopNow(false) {
		return ""
	}
	text, ok := resourceguard.CopyString(budget.allocationMemory(), data, budget.allocationStop)
	if !ok {
		return ""
	}
	return text
}
func concatString(left, right string, budget *cpuGuard) string {
	if budget.stopNow(false) {
		return ""
	}
	text, ok := resourceguard.Concat(budget.allocationMemory(), left, right, budget.allocationStop)
	if !ok {
		return ""
	}
	return text
}
func makeBudgetedBytes(size int, memory *resourceguard.Memory) ([]byte, bool) {
	return resourceguard.MakeBytes(memory, size)
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

// allocatedSlice is for grouped setup followed by an exhaustion check before
// any slice is used. Failure is latched in the shared extraction budget.
func allocatedSlice[T any](memory *resourceguard.Memory, length, capacity int) []T {
	out, _ := resourceguard.MakeSlice[T](memory, length, capacity)
	return out
}
func declarationList(budget *cpuGuard, values ...declaration) []declaration {
	out, ok := resourceguard.MakeSlice[declaration](budget.allocationMemory(), len(values), len(values))
	if !ok {
		return nil
	}
	copy(out, values)
	return out
}
