package css

import (
	"errors"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"io"
	"strings"
	"testing"
	"unsafe"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
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
	for _, source := range []string{`p{color:` + strings.Repeat(`x `, 2000) + `}`, `p{--custom:` + strings.Repeat(`x`, 2000) + `}`, `p{--custom:/*` + strings.Repeat(`x`, 2000) + `*/}`} {
		memory := resourceguard.NewMemory(512)
		expectTermination(t, termination.MemoryExceeded, func() {
			p := NewParserWithLimits(parse.NewInputString(source), false, ResourceLimits{Memory: memory})
			consumeGuardedCSS(p)
		})
		if !memory.Exhausted() {
			t.Fatal("unaccounted storage")
		}
	}
	memory := resourceguard.NewMemory(200)
	expectTermination(t, termination.MemoryExceeded, func() {
		for i := 0; i < 20; i++ {
			p := NewParserWithLimits(parse.NewInputString(`p{color:red}`), false, ResourceLimits{Memory: memory})
			if err := consumeGuardedCSS(p); err != io.EOF {
				t.Fatal(err)
			}
		}
	})
}
func TestInitialCSSStateAdmissionUnwinds(t *testing.T) {
	var p *Parser
	expectTermination(t, termination.MemoryExceeded, func() {
		p = NewParserWithLimits(parse.NewInputString(`p{}`), false, ResourceLimits{Memory: resourceguard.NewMemory(1)})
	})
	if p != nil {
		t.Fatal("initial state published before admission")
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
	memory = resourceguard.NewMemory(before)
	p = NewParserWithLimits(parse.NewInputString(""), false, ResourceLimits{Memory: memory})
	for len(p.state) < cap(p.state) {
		p.pushState((*Parser).parseStylesheet)
	}
	expectTermination(t, termination.MemoryExceeded, func() { p.pushState((*Parser).parseStylesheet) })
	if cap(p.state) != oldCap || len(p.state) != oldCap {
		t.Fatal("stack grew before reservation")
	}
}
func TestCSSLexerObservesExhaustedSharedBudget(t *testing.T) {
	memory := resourceguard.NewMemory(1)
	expectTermination(t, termination.MemoryExceeded, func() { memory.Reserve(2) })
	expectTermination(t, termination.MemoryExceeded, func() { NewLexerWithLimits(parse.NewInputString("red"), ResourceLimits{Memory: memory}) })
}
