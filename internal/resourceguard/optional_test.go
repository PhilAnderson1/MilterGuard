package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"testing"
)

func TestOptionalReservationPreservesRequiredCapacity(t *testing.T) {
	m := NewMemory(10)
	if m.TryReserve(11) || m.Exhausted() || m.Used() != 0 {
		t.Fatal("optional rejection poisoned required allocation")
	}
	m.Reserve(10)
	if m.TryReserve(1) || m.Exhausted() {
		t.Fatal("full budget optional admission")
	}
	expectTermination(t, termination.MemoryExceeded, func() { m.Reserve(1) })
	for _, size := range []int64{0, 1} {
		expectTermination(t, termination.MemoryExceeded, func() { m.TryReserve(size) })
	}
	var unlimited *Memory
	if !unlimited.TryReserve(100) {
		t.Fatal("nil budget")
	}
}
