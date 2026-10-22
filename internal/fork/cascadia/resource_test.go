package cascadia

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

func TestSelectorStructuralLimits(t *testing.T) {
	if _, err := ParseGroup(strings.Repeat("a", maxSelectorBytes+1)); err == nil {
		t.Fatal("oversized selector accepted")
	}
	if _, err := ParseGroup(strings.Repeat(".a", maxSelectorComponents+1)); err == nil {
		t.Fatal("selector with excessive components accepted")
	}
	nested := strings.Repeat(":not(", maxSelectorDepth+1) + "a" + strings.Repeat(")", maxSelectorDepth+1)
	if _, err := ParseGroup(nested); err == nil {
		t.Fatal("excessively nested selector accepted")
	}
}

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
	expectTermination(t, termination.CPUExceeded, func() {
		MatchWithStop(selector, root, func() {
			checks++
			if checks == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
	})
}

func TestMatchWithStopInterruptsLangAncestorSearch(t *testing.T) {
	selector, err := ParseGroup(`:lang(en)`)
	if err != nil {
		t.Fatal(err)
	}
	root := &html.Node{Type: html.ElementNode, Data: "div"}
	n := root
	for range 1_000 {
		child := &html.Node{Type: html.ElementNode, Data: "div"}
		n.AppendChild(child)
		n = child
	}
	checks := 0
	expectTermination(t, termination.CPUExceeded, func() {
		MatchWithStop(selector, n, func() {
			checks++
			if checks == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
	})
}

func TestMatchWithStopPreservesMatchResult(t *testing.T) {
	selector, err := ParseGroup(`div > p.notice`)
	if err != nil {
		t.Fatal(err)
	}
	parent := &html.Node{Type: html.ElementNode, Data: "div"}
	child := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "notice"}}}
	parent.AppendChild(child)
	matched := MatchWithStop(selector, child, func() {})
	if !matched {
		t.Fatal("expected selector match")
	}
}

func TestMatchControlSamplesAcrossMatches(t *testing.T) {
	selector, err := ParseGroup(`p`)
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "p"}
	checks := 0
	control := NewMatchControl(func() {
		checks++
		return
	})
	for range 100 {
		matched := control.Match(selector, n)
		if !matched {
			t.Fatal("expected selector match")
		}
	}
	if checks != 1 {
		t.Fatalf("CPU callback called %d times for 100 simple matches; want 1", checks)
	}
}

func TestAttributeValueMatchStopsDuringLongScan(t *testing.T) {
	selector, err := ParseGroup(`[data-value*="needle" i]`)
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "data-value", Val: strings.Repeat("x", 4096) + "needle"}}}
	checks := 0
	expectTermination(t, termination.CPUExceeded, func() {
		MatchWithStop(selector, n, func() {
			checks++
			if checks == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
	})
	if checks != 2 {
		t.Fatalf("CPU callback called %d times; want second check inside attribute value", checks)
	}
}

func TestAttributePresenceDoesNotCheckValue(t *testing.T) {
	selector, err := ParseGroup(`[data-value]`)
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "data-value", Val: "present"}}}
	checks := 0
	matched := MatchWithStop(selector, n, func() {
		checks++
		return
	})
	if !matched {
		t.Fatal("expected selector match")
	}
	if checks != 1 {
		t.Fatalf("CPU callback called %d times; presence selector should not inspect the value", checks)
	}
}

func TestCaseInsensitiveAttributeMatchingUsesASCIIFolding(t *testing.T) {
	for _, test := range []struct {
		selector string
		value    string
		want     bool
	}{
		{`[data-value="abc" i]`, "ABC", true},
		{`[data-value^="abc" i]`, "ABCdef", true},
		{`[data-value$="def" i]`, "abcDEF", true},
		{`[data-value*="cde" i]`, "abCDEf", true},
		{`[data-value*="aaaab" i]`, strings.Repeat("A", 1_000) + "B", true},
		{`[data-value="k" i]`, "K", false},
	} {
		selector, err := ParseGroup(test.selector)
		if err != nil {
			t.Fatalf("parse %q: %v", test.selector, err)
		}
		n := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "data-value", Val: test.value}}}
		if got := NewMatchControl(func() {}).Match(selector, n); got != test.want {
			t.Errorf("selector %q value %q: got %v, want %v", test.selector, test.value, got, test.want)
		}
	}
}
