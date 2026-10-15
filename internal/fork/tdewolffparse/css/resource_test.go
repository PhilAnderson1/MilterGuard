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
