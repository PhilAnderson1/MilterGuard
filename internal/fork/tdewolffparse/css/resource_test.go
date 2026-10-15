package css

import (
	"errors"
	"io"
	"strings"
	"testing"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
)

func parseToEndWithLimits(source string, inline bool, limits ResourceLimits) (*Parser, error) {
	p := NewParserWithLimits(parse.NewInputString(source), inline, limits, nil)
	for {
		grammar, _, _ := p.Next()
		if grammar == ErrorGrammar {
			return p, p.Err()
		}
	}
}

func requireResourceLimit(t *testing.T, err error, resource string) {
	t.Helper()
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error = %v, want ResourceLimitError", err)
	}
	if limitErr.Resource != resource {
		t.Fatalf("resource = %q, want %q", limitErr.Resource, resource)
	}
}

func TestResourceLimitBoundsRetainedConstructTokens(t *testing.T) {
	_, err := parseToEndWithLimits(strings.Repeat(";", 9), false, ResourceLimits{
		ConstructBytes:  100,
		ConstructTokens: 8,
	})
	requireResourceLimit(t, err, "construct tokens")
}

func TestResourceLimitBoundsAtKeywordBeforeCopy(t *testing.T) {
	_, err := parseToEndWithLimits("@"+strings.Repeat("x", 32)+";", false, ResourceLimits{
		ConstructBytes: 16,
	})
	requireResourceLimit(t, err, "construct bytes")
}

func TestResourceLimitBoundsCustomPropertyCopy(t *testing.T) {
	_, err := parseToEndWithLimits("--x:"+strings.Repeat("x", 32), true, ResourceLimits{
		ConstructBytes: 16,
	})
	requireResourceLimit(t, err, "construct bytes")
}

func TestResourceLimitBoundsParserDepth(t *testing.T) {
	_, err := parseToEndWithLimits(strings.Repeat("@media all{", 4)+"p{x:y}"+strings.Repeat("}", 4), false, ResourceLimits{
		ConstructBytes:  1_000,
		ConstructTokens: 1_000,
		Depth:           4,
	})
	requireResourceLimit(t, err, "depth")
}

func TestResourceLimitRejectsUnsafeTopLevelDelimiter(t *testing.T) {
	for _, source := range []string{")", "]"} {
		p, err := parseToEndWithLimits(source, false, ResourceLimits{ConstructBytes: 100, ConstructTokens: 100, Depth: 10})
		if !errors.Is(err, ErrUnsafeDelimiter) {
			t.Errorf("source %q: error = %v, want ErrUnsafeDelimiter", source, err)
		}
		if p.HasParseError() {
			t.Errorf("source %q: resource failure was reported as a recoverable parse error", source)
		}
	}
}

func TestResourceStopIsSampledWithinLargeToken(t *testing.T) {
	calls := 0
	p, err := parseToEndWithLimits("/*"+strings.Repeat("x", 8<<10)+"*/", false, ResourceLimits{
		ShouldStop: func() bool {
			calls++
			return true
		},
	})
	if !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("error = %v, want ErrResourceStopped", err)
	}
	if calls == 0 {
		t.Fatal("stop callback was not sampled")
	}
	if p.Offset() >= 8<<10 {
		t.Fatalf("parser consumed %d bytes before stopping", p.Offset())
	}
}

func TestParserWithoutResourceLimitsPreservesEOF(t *testing.T) {
	p := NewParser(parse.NewInputString("p{color:red}"), false)
	for {
		grammar, _, _ := p.Next()
		if grammar == ErrorGrammar {
			if !errors.Is(p.Err(), io.EOF) {
				t.Fatalf("error = %v, want EOF", p.Err())
			}
			break
		}
	}
}
