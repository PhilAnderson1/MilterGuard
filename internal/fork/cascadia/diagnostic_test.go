package cascadia

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestRejectedSelectorDoesNotAllocateDiagnostics(t *testing.T) {
	allocations := func(source string) float64 {
		return testing.AllocsPerRun(10, func() {
			memory := resourceguard.NewMemory(17000)
			_, err := ParseGroupWithMemory(source, memory)
			if err != ErrInvalidSelector || memory.Exhausted() {
				t.Fatalf("err=%v exhausted=%v", err, memory.Exhausted())
			}
		})
	}
	if small, large := allocations("a!"), allocations("a!"+strings.Repeat("\x01", 16000)); large > small {
		t.Fatalf("diagnostic allocation grew with rejected input: small=%v large=%v", small, large)
	}
	if small, large := allocations(":unknown"), allocations(":"+strings.Repeat("a", 16000)); large > small {
		t.Fatalf("diagnostic allocation grew with unknown name: small=%v large=%v", small, large)
	}
}

func TestSelectorMemoryErrorRemainsDistinct(t *testing.T) {
	_, err := ParseGroupWithMemory("a", resourceguard.NewMemory(1))
	if err != errSelectorMemory {
		t.Fatalf("got %v, want memory error", err)
	}
	_, err = ParseGroupWithMemory("a", resourceguard.NewMemory(0))
	if err != errSelectorMemory {
		t.Fatalf("source admission returned %v, want memory error", err)
	}
}
