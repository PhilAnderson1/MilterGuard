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
func (g *cpuGuard) allocationStop() { g.checkpoint() }

// These adapters supply the extractor's ledger and checkpoint to shared owners.
func growSlice[T any](s []T, additional int, m *resourceguard.Memory, stops ...resourceguard.Stop) []T {
	var stop resourceguard.Stop

	if len(stops) != 0 {
		stop = stops[0]
	}

	return resourceguard.GrowSlice(m, s, additional, stop)
}
func growBuilder(out *strings.Builder, additional int, budget *cpuGuard) {
	resourceguard.GrowText(budget.allocationMemory(), out, additional, budget.allocationStop)
	return
}
func writeBudgetedString(out *strings.Builder, text string, budget *cpuGuard) {
	resourceguard.WriteString(budget.allocationMemory(), out, text, budget.allocationStop)
	return
}
func writeBudgetedBytes(out *strings.Builder, data []byte, budget *cpuGuard) {
	resourceguard.WriteBytes(budget.allocationMemory(), out, data, budget.allocationStop)
	return
}
func ownedString(data []byte, budget *cpuGuard) string {
	text := resourceguard.CopyString(budget.allocationMemory(), data, budget.allocationStop)

	return text
}
func concatString(left, right string, budget *cpuGuard) string {
	text := resourceguard.Concat(budget.allocationMemory(), left, right, budget.allocationStop)

	return text
}
func makeBudgetedBytes(size int, memory *resourceguard.Memory) []byte {
	return resourceguard.MakeBytes(memory, size)
}

// indexByteWithBudget preserves the allocation-free standard-library scan while
// bounding the amount of input processed between cancellation samples.
func indexByteWithBudget(s string, target byte, budget *cpuGuard) int {
	for start := 0; start < len(s); start += stringWorkChunk {
		if len(s) > stringWorkChunk {
			budget.checkpoint()
		}

		if i := strings.IndexByte(s[start:min(start+stringWorkChunk, len(s))], target); i >= 0 {
			return start + i
		}

	}
	return -1
}

// allocatedSlice admits required setup storage; refusal unwinds immediately.
func allocatedSlice[T any](memory *resourceguard.Memory, length, capacity int) []T {
	out := resourceguard.MakeSlice[T](memory, length, capacity)
	return out
}
func declarationList(budget *cpuGuard, values ...declaration) []declaration {
	out := resourceguard.MakeSlice[declaration](budget.allocationMemory(), len(values), len(values))

	copy(out, values)
	return out
}
