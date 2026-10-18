package css

import (
	"errors"
	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"io"
	"strings"
	"testing"
)

func TestURLRecognitionNoCopyAndCancellation(t *testing.T) {
	l := NewLexer(parse.NewInputString(""))
	name := []byte(strings.Repeat("a", 1<<20))
	if a := testing.AllocsPerRun(10, func() { l.isURLName(name) }); a != 0 {
		t.Fatal(a)
	}
	for _, tc := range []struct {
		name string
		want bool
	}{{"url", true}, {`U\rL`, true}, {"urls", false}, {"other", false}} {
		if got := l.isURLName([]byte(tc.name)); got != tc.want {
			t.Fatal(tc)
		}
	}
	for _, parserOwned := range []bool{false, true} {
		input := parse.NewInputString("")
		limits := ResourceLimits{ShouldStop: func() bool { return true }}
		if parserOwned {
			l = NewParserWithLimits(input, false, limits).l
		} else {
			l = NewLexerWithLimits(input, limits)
		}
		if l.isURLName([]byte(strings.Repeat(`\`, 4096)+"url")) || !errors.Is(l.Err(), ErrResourceStopped) {
			t.Fatalf("parser=%v err=%v", parserOwned, l.Err())
		}
	}
}
func TestSyntaxErrorsDoNotAllocateDiagnostics(t *testing.T) {
	for _, guarded := range []bool{false, true} {
		allocations := func(source string, wantErrors int) float64 {
			// Exclude source ownership from the parser allocation comparison.
			data := make([]byte, len(source), len(source)+1)
			copy(data, source)
			return testing.AllocsPerRun(3, func() {
				input := parse.NewInputBytes(data)
				var p *Parser
				if guarded {
					p = NewParserWithLimits(input, true, ResourceLimits{})
				} else {
					p = NewParser(input, true)
				}
				count := 0
				for {
					grammar, _, _ := p.Next()
					if grammar != ErrorGrammar {
						continue
					}
					if !p.HasParseError() {
						if p.Err() != io.EOF {
							t.Fatalf("guarded=%v: %v", guarded, p.Err())
						}
						break
					}
					if p.Err() != ErrSyntax {
						t.Fatalf("unexpected syntax error: %v", p.Err())
					}
					count++
				}
				if count != wantErrors {
					t.Fatalf("got %d syntax errors, want %d", count, wantErrors)
				}
			})
		}
		baseline := allocations("1;", 1)
		if got := allocations(strings.Repeat("1;", 60000), 60000); got > baseline {
			t.Fatalf("guarded=%v: repeated errors allocated %v times, baseline %v", guarded, got, baseline)
		}
		baseline = allocations("\""+strings.Repeat("a", 64)+"\";", 1)
		if got := allocations("\""+strings.Repeat("a", 256<<10)+"\";", 1); got > baseline {
			t.Fatalf("guarded=%v: long error token allocated %v times, baseline %v", guarded, got, baseline)
		}
	}
}
func TestPostTokenWorkCancellation(t *testing.T) {
	for _, run := range []func(*Parser){
		func(p *Parser) { p.appendCustomCommentSpace(nil, []byte(strings.Repeat("x", 4096))) },
		func(p *Parser) { p.lowerCopy([]byte(strings.Repeat("A", 4096))) },
	} {
		p := NewParserWithLimits(parse.NewInputString(""), true, ResourceLimits{Memory: resourceguard.NewMemory(1 << 20), ShouldStop: func() bool { return true }})
		func() {
			defer func() {
				if _, ok := recover().(resourceAbort); !ok {
					t.Fatal("no resource abort")
				}
			}()
			run(p)
		}()
		if !errors.Is(p.Err(), ErrResourceStopped) {
			t.Fatal(p.Err())
		}
	}
}

func TestUnicodeRangeLookaheadIsBounded(t *testing.T) {
	for _, source := range []string{
		"u+" + strings.Repeat("a", 256<<10),
		"u+abc-" + strings.Repeat("a", 256<<10),
		"u+" + strings.Repeat("?", 256<<10),
		"u+abc" + strings.Repeat("?", 256<<10),
	} {
		input := parse.NewInputString(source)
		input.SetProgressCheck(func() error {
			t.Fatal("Unicode-range lookahead scanned 1024 bytes")
			return ErrResourceStopped
		})
		l := NewLexer(input)
		if l.consumeUnicodeRangeToken() || input.Offset() != 0 {
			t.Fatal("overlong range was not rejected and rewound")
		}
	}
	for _, source := range []string{"u+abcdef", "u+abcdef-123456", "u+??????", "u+abc???"} {
		input := parse.NewInputString(source)
		if !NewLexer(input).consumeUnicodeRangeToken() || input.Offset() != len(source) {
			t.Fatalf("valid range rejected: %q", source)
		}
	}
}

func TestTokenCompactionCannotSkipCheckpoints(t *testing.T) {
	source := "p:1" + strings.Repeat(" 1", 2000) + ";"
	input := parse.NewInputString(source)
	checksAfterLexing := 0
	p := NewParserWithLimits(input, true, ResourceLimits{ShouldStop: func() bool {
		if input.Offset() == len(source) {
			checksAfterLexing++
			return true
		}
		return false
	}})
	grammar, _, _ := p.Next()
	if grammar != ErrorGrammar || !errors.Is(p.Err(), ErrResourceStopped) || checksAfterLexing != 1 {
		t.Fatalf("grammar=%v err=%v post-lexing checks=%d", grammar, p.Err(), checksAfterLexing)
	}

	p = NewParser(parse.NewInputString(source), true)
	grammar, _, _ = p.Next()
	if grammar != DeclarationGrammar || len(p.Values()) != 4001 {
		t.Fatalf("compaction changed: grammar=%v tokens=%d", grammar, len(p.Values()))
	}
}
