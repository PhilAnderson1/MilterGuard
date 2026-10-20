package resourceguard

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestRequiredMemoryUnwinds(t *testing.T) {
	tests := map[string]func(*Memory){
		"reserve": func(m *Memory) { m.Reserve(1024) },
		"object":  func(m *Memory) { New(m, [1024]byte{}) },
		"slice":   func(m *Memory) { MakeSlice[byte](m, 0, 1024) },
		"overflow": func(m *Memory) {
			MakeSlice[uint64](m, 0, int(^uint(0)>>1))
		},
		"later slice growth": func(m *Memory) {
			s := MakeSlice[byte](m, 1, 1)
			GrowSlice(m, s, 1024, nil)
		},
		"later string growth": func(m *Memory) {
			var b strings.Builder
			GrowText(m, &b, 1, nil)
			b.WriteByte('a')
			GrowText(m, &b, 1024, nil)
		},
		"required table": func(m *Memory) {
			var table Table[int, int]
			table.Set(m, 1, 2)
		},
	}
	for name, work := range tests {
		t.Run(name, func(t *testing.T) {
			m := NewMemory(64)
			var failure termination.Failure
			continued := false
			func() {
				defer termination.Recover(&failure)
				work(m)
				continued = true
			}()
			if continued || failure.Code != termination.MemoryExceeded || failure.Limit != 64 || !m.Exhausted() || m.Used() != 64 {
				t.Fatalf("continued=%v failure=%+v memory=%+v", continued, failure, m)
			}
		})
	}
}

func TestRequiredMemoryOptionalRefusal(t *testing.T) {
	m := NewMemory(64)
	var table Table[int, int]
	var tables []Table[int, int]
	if m.TryReserve(1024) || table.TrySet(m, 1, 2) || TryCacheEntry(m, &tables, 1, 0, 1, 2) {
		t.Fatal("oversized optional work admitted")
	}
	if _, ok := TryMakeSlice[byte](m, 0, 1024); ok {
		t.Fatal("oversized optional slice admitted")
	}
	if m.Exhausted() || m.Used() != 0 {
		t.Fatal("optional refusal poisoned required work")
	}
	m.Reserve(1)
}

func TestRequiredMemoryCannotResumeAfterBoundary(t *testing.T) {
	m := NewMemory(1)
	var failure termination.Failure
	func() {
		defer termination.Recover(&failure)
		m.Reserve(2)
	}()
	// Reporting is safe after an abort. Storage reuse, even within previously
	// allocated capacity, must not resume the failed operation.
	if !m.Exhausted() || m.Used() != 1 {
		t.Fatal("lost exhaustion")
	}
	for name, work := range map[string]func(){
		"zero reservation": func() { m.Reserve(0) },
		"optional":         func() { m.TryReserve(0) },
		"capacity reuse": func() {
			s := make([]byte, 0, 8)
			Append(m, s, nil, byte(1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stopped termination.Failure
			func() {
				defer termination.Recover(&stopped)
				work()
				t.Fatal("exhausted operation resumed")
			}()
			if stopped.Code != termination.MemoryExceeded {
				t.Fatalf("failure=%+v", stopped)
			}
		})
	}
}

func TestZeroReservationAfterExhaustionTerminates(t *testing.T) {
	m := NewMemory(1)
	expectTermination(t, termination.MemoryExceeded, func() { m.Reserve(2) })
	expectTermination(t, termination.MemoryExceeded, func() { m.Reserve(0) })
}
