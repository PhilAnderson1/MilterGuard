package css

import (
	"errors"
	"strings"
	"testing"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestSharedMemoryBudgetStopsCSSParser(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	p := NewParserWithLimits(parse.NewInputString(`p{color:`+strings.Repeat(`x `, 200)+`}`), false, ResourceLimits{Memory: memory})
	for {
		g, _, _ := p.Next()
		if g == ErrorGrammar {
			break
		}
	}
	var limitErr *ResourceLimitError
	if !errors.As(p.Err(), &limitErr) || !memory.Exhausted() {
		t.Fatalf("err=%v exhausted=%v", p.Err(), memory.Exhausted())
	}
}

func TestProgressGuardStopsUnknownAtRuleBody(t *testing.T) {
	input := parse.NewInputString(`@unknown{` + strings.Repeat(`;`, 2_000) + `}`)
	stopOffset := -1
	p := NewParserWithLimits(input, false, ResourceLimits{ShouldStop: func() bool {
		if input.Offset() >= 1_024 {
			stopOffset = input.Offset()
			return true
		}
		return false
	}})
	for {
		grammar, _, _ := p.Next()
		if grammar == ErrorGrammar {
			break
		}
	}
	if !errors.Is(p.Err(), ErrResourceStopped) {
		t.Fatalf("err=%v, want %v", p.Err(), ErrResourceStopped)
	}
	if stopOffset < 0 || stopOffset > 1_024 {
		t.Fatalf("stopped at input offset %d, want no later than 1024", stopOffset)
	}
}
