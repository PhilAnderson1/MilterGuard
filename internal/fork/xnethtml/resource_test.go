package html

import (
	"errors"
	"strconv"
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

func TestStandaloneTokenizerResourceStop(t *testing.T) {
	checks := 0
	z := NewTokenizerWithStop(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), func() bool {
		checks++
		return checks > 1
	})
	for z.Next() != ErrorToken {
	}
	if !errors.Is(z.Err(), ErrResourceStopped) {
		t.Fatalf("err=%v", z.Err())
	}
}

func TestAttributeContentIsChargedToMemoryBudget(t *testing.T) {
	used := func(value string) int64 {
		t.Helper()
		memory := resourceguard.NewMemory(1 << 20)
		_, err := ParseWithOptions(
			strings.NewReader(`<div data-value="`+value+`"></div>`),
			ParseOptionResourceLimits(ResourceLimits{Memory: memory}),
		)
		if err != nil {
			t.Fatal(err)
		}
		return memory.Used()
	}

	short := used("x")
	long := used(strings.Repeat("x", 2048))
	if difference := long - short; difference < 2047 {
		t.Fatalf("long attribute added %d charged bytes, want at least 2047", difference)
	}
}

func TestUniqueAttributeStructuralMemoryIsCharged(t *testing.T) {
	used := func(source string) int64 {
		t.Helper()
		memory := resourceguard.NewMemory(1 << 20)
		if _, err := ParseWithOptions(strings.NewReader(source), ParseOptionResourceLimits(ResourceLimits{Memory: memory})); err != nil {
			t.Fatal(err)
		}
		return memory.Used()
	}

	var source strings.Builder
	source.WriteString("<div ")
	for i := range 100 {
		source.WriteString("data-")
		source.WriteString(strconv.Itoa(i))
		source.WriteString("=x ")
	}
	source.WriteString("></div>")

	withoutAttributes := used("<div></div>")
	withAttributes := used(source.String())
	if difference := withAttributes - withoutAttributes; difference < 100*64 {
		t.Fatalf("100 unique attributes added %d charged bytes, want at least %d", difference, 100*64)
	}
}
