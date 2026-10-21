package resourceguard

import (
	"regexp"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestRegexpSplitAllowance(t *testing.T) {
	const (
		limit     = 17
		allowance = int64(limit * 256)
	)
	re := regexp.MustCompile(`\s+and\s+`)

	memory := NewMemory(allowance)
	parts := RegexpSplit(memory, re, "screen and (min-width: 1px)", limit)
	if len(parts) != 2 || memory.Used() != allowance {
		t.Fatalf("parts=%q used=%d, want %d", parts, memory.Used(), allowance)
	}

	expectTermination(t, termination.MemoryExceeded, func() {
		RegexpSplit(NewMemory(allowance-1), re, "screen", limit)
	})
}
