package html

import (
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"testing"
)

func TestTokenizerWithLimitsAdmission(t *testing.T) {
	for _, limit := range []int64{1, 8192} {
		memory := resourceguard.NewMemory(limit)
		var z *Tokenizer
		expectTermination(t, termination.MemoryExceeded, func() {
			z = NewTokenizerWithLimits(strings.NewReader(strings.Repeat("x", 16384)), ResourceLimits{Memory: memory})
			z.Next()
		})
		if !memory.Exhausted() {
			t.Fatal("missing exhaustion")
		}
		if limit == 1 && z != nil {
			t.Fatal("initial tokenizer published before admission")
		}
	}
}
