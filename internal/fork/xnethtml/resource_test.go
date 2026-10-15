package html

import (
	"errors"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestSharedMemoryBudgetStopsTokenizerAndTreeBuilder(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	_, err := ParseWithOptions(strings.NewReader(`<div `+strings.Repeat(`a=x `, 100)+`>text</div>`), ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) || !memory.Exhausted() {
		t.Fatalf("err=%v exhausted=%v", err, memory.Exhausted())
	}
}

func TestResourceStopDuringLargeToken(t *testing.T) {
	checks := 0
	_, err := ParseWithOptions(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() bool { checks++; return checks > 1 }}))
	if !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("err=%v", err)
	}
}
