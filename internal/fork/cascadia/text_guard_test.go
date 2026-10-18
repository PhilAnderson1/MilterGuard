package cascadia

import (
	html "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
)

func TestTextPseudoClassesAreRejected(t *testing.T) {
	parsers := []func(string) error{
		func(s string) error { _, e := Parse(s); return e }, func(s string) error { _, e := ParseWithPseudoElement(s); return e },
		func(s string) error { _, e := ParseGroup(s); return e }, func(s string) error { _, e := ParseGroupWithPseudoElements(s); return e },
		func(s string) error { _, e := ParseGroupWithMemory(s, resourceguard.NewMemory(1<<20)); return e },
		func(s string) error {
			_, e := ParseGroupWithPseudoElementsAndMemory(s, resourceguard.NewMemory(1<<20))
			return e
		},
		func(s string) error { _, e := Compile(s); return e },
	}
	for _, s := range []string{`:contains("x")`, `.target:containsOwn(x)`, `div:has(:contains(x))`, `:not(:containsown(x))`} {
		for i, parse := range parsers {
			if e := parse(s); e != ErrInvalidSelector {
				t.Fatalf("parser %d accepted %s: %v", i, s, e)
			}
		}
	}
}
func TestEmptyPseudoClassInterruptsLongWhitespace(t *testing.T) {
	s, err := Parse(":empty")
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "p"}
	n.AppendChild(&html.Node{Type: html.TextNode, Data: strings.Repeat(" \u00a0", 10000)})
	calls := 0
	_, stopped := MatchWithStop(s, n, func() bool { calls++; return calls == 2 })
	if !stopped || calls != 2 {
		t.Fatalf("stopped=%v calls=%d", stopped, calls)
	}
	if !s.Match(n) {
		t.Fatal("Unicode whitespace semantics changed")
	}
	n.FirstChild.Data += "x"
	if s.Match(n) {
		t.Fatal("nonblank text matched empty")
	}
}
