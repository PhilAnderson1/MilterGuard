package css

import (
	"errors"
	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"io"
	"strings"
	"testing"
	"unsafe"
)

func consumeGuardedCSS(p *Parser) error {
	for {
		g, _, _ := p.Next()
		if g == ErrorGrammar {
			return p.Err()
		}
	}
}
func TestReusableTokenBufferDoesNotChargeEveryToken(t *testing.T) {
	source := `p{` + strings.Repeat(`color:red;`, 10000) + `}`
	memory := resourceguard.NewMemory(256 << 10)
	p := NewParserWithLimits(parse.NewInputString(source), false, ResourceLimits{Memory: memory})
	if err := consumeGuardedCSS(p); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if cap(p.buf) > 8 {
		t.Fatalf("reusable buffer grew per declaration: %d", cap(p.buf))
	}
	if memory.Used() >= int64(len(source)) {
		t.Fatalf("borrowed token processing charged as allocation: %d", memory.Used())
	}
	t.Logf("10000 declarations charged=%d bufferCapacity=%d", memory.Used(), cap(p.buf))
}
func TestCSSCopiesAndBufferGrowthUseSharedBudget(t *testing.T) {
	for _, source := range []string{
		`p{color:` + strings.Repeat(`x `, 2000) + `}`,
		`p{--custom:` + strings.Repeat(`x`, 2000) + `}`,
		`p{--custom:/*` + strings.Repeat(`x`, 2000) + `*/}`,
	} {
		memory := resourceguard.NewMemory(512)
		p := NewParserWithLimits(parse.NewInputString(source), false, ResourceLimits{Memory: memory})
		var limited *ResourceLimitError
		if err := consumeGuardedCSS(p); !errors.As(err, &limited) || !memory.Exhausted() {
			t.Fatalf("unaccounted storage: %v", err)
		}
	}
	memory := resourceguard.NewMemory(200)
	failures := 0
	for i := 0; i < 20; i++ {
		p := NewParserWithLimits(parse.NewInputString(`p{color:red}`), false, ResourceLimits{Memory: memory})
		if !errors.Is(consumeGuardedCSS(p), io.EOF) {
			failures++
			break
		}
	}
	if failures == 0 || !memory.Exhausted() {
		t.Fatal("new parser reset allocation budget")
	}
}
func TestInitialCSSStateAdmissionReturnsError(t *testing.T) {
	p := NewParserWithLimits(parse.NewInputString(`p{}`), false, ResourceLimits{Memory: resourceguard.NewMemory(1)})
	var limited *ResourceLimitError
	if !errors.As(consumeGuardedCSS(p), &limited) || p.state != nil {
		t.Fatal("initial state allocated before admission")
	}
}
func TestCSSStackGrowthReservesFullArrayBeforeAppend(t *testing.T) {
	memory := resourceguard.NewMemory(1 << 20)
	p := NewParserWithLimits(parse.NewInputString(""), false, ResourceLimits{Memory: memory})
	for len(p.state) < cap(p.state) {
		p.pushState((*Parser).parseStylesheet)
	}
	before, oldCap := memory.Used(), cap(p.state)
	p.pushState((*Parser).parseStylesheet)
	if memory.Used()-before != int64(cap(p.state))*int64(unsafe.Sizeof(State(nil))) {
		t.Fatal("growth charged only capacity delta")
	}
	memory = resourceguard.NewMemory(int64(oldCap) * int64(unsafe.Sizeof(State(nil))))
	p = NewParserWithLimits(parse.NewInputString(""), false, ResourceLimits{Memory: memory})
	for len(p.state) < cap(p.state) {
		p.pushState((*Parser).parseStylesheet)
	}
	defer func() {
		if _, ok := recover().(resourceAbort); !ok {
			t.Fatal("missing admission abort")
		}
		if cap(p.state) != oldCap || len(p.state) != oldCap {
			t.Fatal("stack grew before reservation")
		}
	}()
	p.pushState((*Parser).parseStylesheet)
}
func TestCSSLexerObservesExhaustedSharedBudget(t *testing.T) {
	memory := resourceguard.NewMemory(1)
	memory.Reserve(2)
	l := NewLexerWithLimits(parse.NewInputString("red"), ResourceLimits{Memory: memory})
	if token, _ := l.Next(); token != ErrorToken {
		t.Fatal("lexer continued exhausted operation")
	}
}
