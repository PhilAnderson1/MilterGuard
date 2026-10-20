package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"testing"
)

func TestStorageAdmissionAndReplacement(t *testing.T) {
	m := NewMemory(24)
	s := MakeSlice[uint64](m, 1, 1)
	s[0] = 7
	s = GrowSlice(m, s, 1, nil)
	if m.Used() != 24 || s[0] != 7 {
		t.Fatal("replacement must charge full array and preserve content")
	}
	original := s
	expectTermination(t, termination.MemoryExceeded, func() { s = GrowSlice(m, s, 2, nil) })
	if &s[0] != &original[0] || !m.Exhausted() {
		t.Fatal("failed growth changed storage")
	}
}
func TestStorageRejectsInvalidSizes(t *testing.T) {
	for _, size := range []int{-1, int(^uint(0) >> 1)} {
		m := NewMemory(100)
		expectTermination(t, termination.MemoryExceeded, func() { MakeSlice[uint64](m, 0, size) })
		if !m.Exhausted() {
			t.Fatal("invalid size did not exhaust", size)
		}
	}
	failure := expectTermination(t, termination.MemoryExceeded, func() { MakeSlice[byte](nil, 2, 1) })
	if failure.Limit != 0 {
		t.Fatalf("nil ledger failure: %+v", failure)
	}
}
func TestRetainedStringsSurviveGrowthAndReset(t *testing.T) {
	m := NewMemory(1 << 20)
	var b strings.Builder
	WriteString(m, &b, "first", nil)
	first := b.String()
	WriteString(m, &b, strings.Repeat("x", 100), nil)
	b.Reset()
	WriteString(m, &b, "other", nil)
	if first != "first" {
		t.Fatal("retained string mutated")
	}
}
func TestCopyCancellationDoesNotPublishReplacement(t *testing.T) {
	for _, code := range []termination.Code{termination.CPUExceeded, termination.Cancelled} {
		m := NewMemory(1 << 20)
		s := MakeSlice[byte](m, WorkChunk*3, WorkChunk*3)
		original := s
		calls := 0
		expectTermination(t, code, func() {
			s = GrowSlice(m, s, 1, func() {
				calls++
				if calls == 2 {
					termination.Fail(termination.Failure{Code: code})
				}
			})
		})
		if &s[0] != &original[0] || calls != 2 {
			t.Fatal("cancelled replacement published")
		}
	}
}
func TestTableReuseAndOptionalAdmission(t *testing.T) {
	m := NewMemory(1 << 20)
	var table Table[string, int]
	for _, key := range []string{"a", "b", "c"} {
		table.Set(m, key, 1)
	}
	used := m.Used()
	table.Reset()
	for _, key := range []string{"d", "e", "f"} {
		table.Set(m, key, 2)
	}
	if m.Used() != used {
		t.Fatal("refill lost allowance")
	}
	tight := NewMemory(1)
	var optional Table[int, int]
	if optional.TrySet(tight, 1, 2) || tight.Exhausted() || optional.Len() != 0 {
		t.Fatal("optional refusal poisoned required work")
	}
	expectTermination(t, termination.MemoryExceeded, func() { optional.Set(tight, 1, 2) })
	if !tight.Exhausted() || optional.Len() != 0 {
		t.Fatal("required failure published storage")
	}
}
func TestCacheSetupAdmissionIsAtomic(t *testing.T) {
	m := NewMemory(160)
	var caches []Table[int, int]
	if TryCacheEntry(m, &caches, 8, 0, 1, 2) || m.Exhausted() || m.Used() != 0 || caches != nil {
		t.Fatal("declined cache changed required budget or published storage")
	}
	m.Reserve(160)
}
func TestOwnedObjectsAndLibraryCopiesRejectBeforeUse(t *testing.T) {
	m := NewMemory(1)
	var object *[32]byte
	expectTermination(t, termination.MemoryExceeded, func() { object = New(m, [32]byte{}) })
	if object != nil {
		t.Fatal("object published")
	}
	m = NewMemory(1)
	var decoded []byte
	expectTermination(t, termination.MemoryExceeded, func() { decoded, _ = DecodeBase64(m, "aGVsbG8=") })
	if decoded != nil {
		t.Fatal("decoded copy published")
	}
	m = NewMemory(1 << 20)
	calls := 0
	expectTermination(t, termination.Cancelled, func() {
		decoded = CloneBytes(m, make([]byte, WorkChunk*3), func() {
			calls++
			if calls == 2 {
				termination.Fail(termination.Failure{Code: termination.Cancelled})
			}
		})
	})
	if decoded != nil || calls != 2 || m.Used() == 0 {
		t.Fatal("cancelled copy lost charge or published partial bytes")
	}
}
func TestRejectedObjectDoesNotAllocateStorage(t *testing.T) {
	m := NewMemory(1)
	var sink *[4096]byte
	baseline := testing.AllocsPerRun(100, func() {
		var failure termination.Failure
		defer termination.Recover(&failure)
		termination.Fail(termination.Failure{Code: termination.MemoryExceeded, Limit: 1})
	})
	allocations := testing.AllocsPerRun(100, func() {
		var failure termination.Failure
		defer termination.Recover(&failure)
		sink = New(m, [4096]byte{})
	})
	if allocations != baseline || sink != nil {
		t.Fatalf("rejected object allocated %g times; signal alone %g", allocations, baseline)
	}
}
