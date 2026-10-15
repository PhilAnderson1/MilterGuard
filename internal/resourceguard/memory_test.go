package resourceguard

import "testing"

func TestMemoryIsMonotonicAndFailsClosed(t *testing.T) {
	memory := NewMemory(10)
	if !memory.Reserve(4) || memory.Used() != 4 {
		t.Fatalf("first reservation: used=%d", memory.Used())
	}
	if memory.Reserve(7) || !memory.Exhausted() {
		t.Fatalf("over-limit reservation succeeded or did not exhaust")
	}
	if memory.Used() != 10 || memory.Reserve(1) {
		t.Fatalf("exhausted budget reopened: used=%d", memory.Used())
	}
}
