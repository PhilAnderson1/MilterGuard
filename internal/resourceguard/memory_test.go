package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"testing"
)

func expectTermination(t *testing.T, code termination.Code, work func()) termination.Failure {
	t.Helper()
	var failure termination.Failure
	continued := false
	func() { defer termination.Recover(&failure); work(); continued = true }()
	if continued || failure.Code != code {
		t.Fatalf("continued=%v failure=%+v; want %v", continued, failure, code)
	}
	return failure
}

func TestMemoryIsMonotonicAndFailsClosed(t *testing.T) {
	memory := NewMemory(10)
	memory.Reserve(4)
	if memory.Used() != 4 {
		t.Fatalf("first reservation: used=%d", memory.Used())
	}
	failure := expectTermination(t, termination.MemoryExceeded, func() { memory.Reserve(7) })
	if !memory.Exhausted() || memory.Used() != 10 || memory.Charged() != 4 || failure.Limit != 10 {
		t.Fatalf("failure=%+v memory=%+v", failure, memory)
	}
	expectTermination(t, termination.MemoryExceeded, func() { memory.Reserve(1) })
}
