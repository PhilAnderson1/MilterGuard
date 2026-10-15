package cascadia

import (
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

func TestMatchWithStopInterruptsDescendantSearch(t *testing.T) {
	selector, err := ParseGroup(`div:has(span)`)
	if err != nil {
		t.Fatal(err)
	}
	root := &html.Node{Type: html.ElementNode, Data: "div"}
	parent := root
	for range 2_000 {
		child := &html.Node{Type: html.ElementNode, Data: "div"}
		parent.AppendChild(child)
		parent = child
	}
	checks := 0
	matched, stopped := MatchWithStop(selector, root, func() bool {
		checks++
		return checks == 2
	})
	if matched || !stopped {
		t.Fatalf("matched=%v stopped=%v, want false/true", matched, stopped)
	}
}

func TestMatchWithStopPreservesMatchResult(t *testing.T) {
	selector, err := ParseGroup(`div > p.notice`)
	if err != nil {
		t.Fatal(err)
	}
	parent := &html.Node{Type: html.ElementNode, Data: "div"}
	child := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "notice"}}}
	parent.AppendChild(child)
	matched, stopped := MatchWithStop(selector, child, func() bool { return false })
	if !matched || stopped {
		t.Fatalf("matched=%v stopped=%v, want true/false", matched, stopped)
	}
}

func TestMatchControlSamplesAcrossMatches(t *testing.T) {
	selector, err := ParseGroup(`p`)
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "p"}
	checks := 0
	control := NewMatchControl(func() bool {
		checks++
		return false
	})
	for range 100 {
		matched, stopped := control.Match(selector, n)
		if !matched || stopped {
			t.Fatalf("matched=%v stopped=%v, want true/false", matched, stopped)
		}
	}
	if checks != 1 {
		t.Fatalf("CPU callback called %d times for 100 simple matches; want 1", checks)
	}
}
