package css

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"errors"
	"io"
	"strings"
	"testing"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestErrorTokenRemainsZeroForUnwindSafety(t *testing.T) {
	if ErrorToken != 0 {
		t.Fatalf("ErrorToken=%d, want zero so lexer defers skip work during panic unwinding", ErrorToken)
	}
}

func TestSharedMemoryBudgetStopsCSSParser(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	expectTermination(t, termination.MemoryExceeded, func() {
		p := NewParserWithLimits(parse.NewInputString(`p{color:`+strings.Repeat(`x `, 200)+`}`), false, ResourceLimits{Memory: memory})
		for {
			g, _, _ := p.Next()
			if g == ErrorGrammar {
				t.Fatalf("resource failure returned parser error: %v", p.Err())
			}
		}
	})
	if !memory.Exhausted() {
		t.Fatal("lost exhaustion")
	}
}

func TestProgressGuardStopsUnknownAtRuleBody(t *testing.T) {
	input := parse.NewInputString(`@unknown{` + strings.Repeat(`;`, 2_000) + `}`)
	stopOffset := -1
	p := NewParserWithLimits(input, false, ResourceLimits{ShouldStop: func() {
		if input.Offset() >= 1_024 {
			stopOffset = input.Offset()
			if true {
				termination.
					Fail(termination.
						Failure{Code: termination.
						CPUExceeded,
					})
			}

			return
		}
		return
	}})
	expectTermination(t, termination.CPUExceeded, func() {
		for {
			grammar, _, _ := p.Next()
			if grammar == ErrorGrammar {
				t.Fatalf("resource stop returned grammar error: %v", p.Err())
			}
		}
	})

	if stopOffset < 0 || stopOffset > 1_024 {
		t.Fatalf("stopped at input offset %d, want no later than 1024", stopOffset)
	}
}

func TestCSSLexerDoesNotChargeBorrowedTokens(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	l := NewLexerWithLimits(parse.NewInputString(strings.Repeat(`()`, 200)), ResourceLimits{Memory: memory})
	setup := memory.Used()
	for {
		if token, _ := l.Next(); token == ErrorToken {
			break
		}
	}
	if !errors.Is(l.Err(), io.EOF) || memory.Used() != setup || memory.Exhausted() {
		t.Fatalf("borrowed tokens charged: err=%v used=%d", l.Err(), memory.Used())
	}
}

func TestProgressGuardStopsCSSLexerInsideLongToken(t *testing.T) {
	input := parse.NewInputString(strings.Repeat(`a`, 2_000))
	stopOffset := -1
	l := NewLexerWithLimits(input, ResourceLimits{ShouldStop: func() {
		if input.Offset() >= 1_024 {
			stopOffset = input.Offset()
			if true {
				termination.
					Fail(termination.
						Failure{Code: termination.
						CPUExceeded,
					})
			}

			return
		}
		return
	}})
	expectTermination(t, termination.CPUExceeded, func() { l.Next() })

	if stopOffset < 0 || stopOffset > 1_024 {
		t.Fatalf("stopped at input offset %d, want no later than 1024", stopOffset)
	}
}

func TestCSSLexerTokenCountLimit(t *testing.T) {
	l := NewLexer(parse.NewInputString("a"))
	l.tokens = maxCSSTokens
	if token, _ := l.Next(); token != ErrorToken {
		t.Fatalf("token=%v, want ErrorToken", token)
	}
	var limitErr *ResourceLimitError
	if !errors.As(l.Err(), &limitErr) || limitErr.Resource != "tokens" || limitErr.Limit != maxCSSTokens {
		t.Fatalf("limit error = %v", l.Err())
	}
}

func TestCSSParserNestingLimit(t *testing.T) {
	p := NewParser(parse.NewInputString("a{}"), false)
	p.state = make([]State, maxCSSParserStates)
	defer func() {
		recovered := recover()
		if _, ok := recovered.(resourceAbort); !ok {
			t.Fatalf("panic=%v, want resourceAbort", recovered)
		}
		var limitErr *ResourceLimitError
		if !errors.As(p.resourceErr, &limitErr) || limitErr.Resource != "parser nesting" || limitErr.Limit != maxCSSParserStates {
			t.Fatalf("limit error = %v", p.resourceErr)
		}
	}()
	p.pushState((*Parser).parseStylesheet)
}

func TestCSSComponentNestingLimit(t *testing.T) {
	p := NewParser(parse.NewInputString(""), false)
	p.level = maxCSSParserStates
	defer func() {
		recovered := recover()
		if _, ok := recovered.(resourceAbort); !ok {
			t.Fatalf("panic=%v, want resourceAbort", recovered)
		}
		var limitErr *ResourceLimitError
		if !errors.As(p.resourceErr, &limitErr) || limitErr.Resource != "component nesting" || limitErr.Limit != maxCSSParserStates {
			t.Fatalf("limit error = %v", p.resourceErr)
		}
	}()
	p.openComponentToken(LeftParenthesisToken)
}

func TestOneByteAtKeywordDoesNotPanic(t *testing.T) {
	p := NewParser(parse.NewInputString(""), false)
	p.data = []byte{'@'}
	if grammar := p.parseAtRule(); grammar != AtRuleGrammar {
		t.Fatalf("grammar=%v, want AtRuleGrammar", grammar)
	}
}
