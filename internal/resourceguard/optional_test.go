package resourceguard

import "testing"

func TestOptionalReservationPreservesRequiredCapacity(t *testing.T) {
	m := NewMemory(10)
	if m.TryReserve(11) || m.Exhausted() || m.Used() != 0 || !m.Reserve(10) {
		t.Fatal("optional rejection poisoned required allocation")
	}
	if m.TryReserve(1) || m.Exhausted() {
		t.Fatal("full budget optional admission")
	}
	if m.Reserve(1) || !m.Exhausted() || m.TryReserve(0) || m.TryReserve(1) {
		t.Fatal("required failure must remain fatal")
	}
	var unlimited *Memory
	if !unlimited.TryReserve(100) {
		t.Fatal("nil budget")
	}
}
