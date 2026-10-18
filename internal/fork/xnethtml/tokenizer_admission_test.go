package html

import (
	"errors"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestTokenizerWithLimitsAdmission(t *testing.T) {
	for _, limit := range []int64{1, 8192} {
		memory := resourceguard.NewMemory(limit)
		z := NewTokenizerWithLimits(strings.NewReader(strings.Repeat("x", 16384)), ResourceLimits{Memory: memory})
		if limit == 1 && cap(z.buf) != 0 {
			t.Fatal("initial buffer allocated before admission")
		}
		var resourceErr *ResourceLimitError
		if token := z.Next(); token != ErrorToken || !errors.As(z.Err(), &resourceErr) || !memory.Exhausted() {
			t.Fatalf("limit=%d token=%v err=%v exhausted=%v", limit, token, z.Err(), memory.Exhausted())
		}
	}
}
