package resourceguard

import (
	"strings"
	"testing"
)

func TestStorageAdmissionAndReplacement(t *testing.T) {
	m := NewMemory(24)
	s, ok := MakeSlice[uint64](m, 1, 1)
	if !ok {
		t.Fatal("initial admission")
	}
	s[0] = 7
	s, ok = GrowSlice(m, s, 1, nil)
	if !ok || m.Used() != 24 || s[0] != 7 {
		t.Fatal("replacement must charge full array and preserve content")
	}
	original := s
	s, ok = GrowSlice(m, s, 2, nil)
	if ok || &s[0] != &original[0] || !m.Exhausted() {
		t.Fatal("failed growth changed storage")
	}
}
func TestStorageRejectsInvalidSizes(t *testing.T) {
	for _, size := range []int{-1, int(^uint(0) >> 1)} {
		m := NewMemory(100)
		if _, ok := MakeSlice[uint64](m, 0, size); ok || !m.Exhausted() {
			t.Fatal("invalid size accepted", size)
		}
	}
	if _, ok := MakeSlice[byte](nil, 2, 1); ok {
		t.Fatal("nil budget bypassed size validation")
	}
}
func TestRetainedStringsSurviveGrowthAndReset(t *testing.T) {
	m := NewMemory(1 << 20)
	var b strings.Builder
	if !WriteString(m, &b, "first", nil) {
		t.Fatal("write")
	}
	first := b.String()
	if !WriteString(m, &b, strings.Repeat("x", 100), nil) {
		t.Fatal("growth")
	}
	b.Reset()
	if !WriteString(m, &b, "other", nil) || first != "first" {
		t.Fatal("retained string mutated")
	}
}
func TestCopyCancellationDoesNotPublishReplacement(t *testing.T) {
	m := NewMemory(1 << 20)
	s, ok := MakeSlice[byte](m, WorkChunk*3, WorkChunk*3)
	if !ok {
		t.Fatal("initial")
	}
	calls := 0
	grown, ok := GrowSlice(m, s, 1, func() bool { calls++; return calls == 2 })
	if ok || &grown[0] != &s[0] || calls != 2 {
		t.Fatal("cancelled replacement published")
	}
}
func TestTableReuseAndOptionalAdmission(t *testing.T) {
	m := NewMemory(1 << 20)
	var table Table[string, int]
	for _, key := range []string{"a", "b", "c"} {
		if !table.Set(m, key, 1) {
			t.Fatal("insert")
		}
	}
	used := m.Used()
	table.Reset()
	for _, key := range []string{"d", "e", "f"} {
		if !table.Set(m, key, 2) {
			t.Fatal("refill")
		}
	}
	if m.Used() != used {
		t.Fatal("refill lost allowance")
	}
	tight := NewMemory(1)
	var optional Table[int, int]
	if optional.TrySet(tight, 1, 2) || tight.Exhausted() || optional.Len() != 0 {
		t.Fatal("optional failure poisoned required work")
	}
	if optional.Set(tight, 1, 2) || !tight.Exhausted() {
		t.Fatal("required failure did not latch")
	}
}

func TestCacheSetupAdmissionIsAtomic(t *testing.T) {
	m := NewMemory(160)
	var caches []Table[int, int]
	if TryCacheEntry(m, &caches, 8, 0, 1, 2) || m.Exhausted() || m.Used() != 0 || caches != nil {
		t.Fatal("declined cache changed required budget or published storage")
	}
	if !m.Reserve(160) {
		t.Fatal("optional rejection consumed required budget")
	}
}

func TestOwnedObjectsAndLibraryCopiesRejectBeforeUse(t *testing.T) {
	m := NewMemory(1)
	if p, ok := New(m, [32]byte{}); ok || p != nil || !m.Exhausted() {
		t.Fatal("object admitted without space")
	}
	m = NewMemory(1)
	if b, err := DecodeBase64(m, "aGVsbG8="); err != ErrMemory || b != nil {
		t.Fatal("decoded copy published after rejection")
	}
	m = NewMemory(1 << 20)
	calls := 0
	b, ok := CloneBytes(m, make([]byte, WorkChunk*3), func() bool { calls++; return calls == 2 })
	if ok || b != nil || calls != 2 || m.Used() == 0 {
		t.Fatal("cancelled copy lost charge or published partial bytes")
	}
}

func TestRejectedObjectDoesNotAllocate(t *testing.T) {
	m := NewMemory(1)
	var sink *[4096]byte
	allocations := testing.AllocsPerRun(100, func() { sink, _ = New(m, [4096]byte{}) })
	if allocations != 0 || sink != nil {
		t.Fatalf("rejected object allocated %g times", allocations)
	}
}
