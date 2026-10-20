package cascadia

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"strings"
	"testing"

	html "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/atom"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestCancelledCompositeResults(t *testing.T) {
	for _, source := range []string{"x" + strings.Repeat(" ~ i", 100), "x" + strings.Repeat(" i", 100), ":not(.missing)"} {
		sel, err := ParseGroup(source)
		if err != nil {
			t.Fatal(err)
		}
		parent := &html.Node{Type: html.ElementNode, Data: "i"}
		for i := 0; i < 300; i++ {
			parent.AppendChild(&html.Node{Type: html.ElementNode, Data: "i"})
		}
		calls := 0
		control := NewMatchControl(func() {
			calls++
			if true {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
		expectTermination(t, termination.CPUExceeded, func() { control.Match(sel, parent.LastChild) })

		if calls != 1 {
			t.Fatal(calls)
		}
	}
}

func TestSelectorIteratorCancellationAndBoundaries(t *testing.T) {
	for _, source := range []string{strings.Repeat(" ", 10000), strings.Repeat(" ,", 5000), "[x='" + strings.Repeat("x", 10000) + "']", strings.Repeat(`\a`, 5000)} {
		calls := 0
		it := NewSelectorListIteratorWithStop(source, func() {
			calls++
			if calls == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
		expectTermination(t, termination.CPUExceeded, func() { it.Next() })
		if calls != 2 {
			t.Fatalf("iterator calls=%d", calls)
		}
	}
	source := ` , a[x="a,b"], :not(.a,.b), x\,y , z\ `
	got, _ := SplitSelectorList(source, 10)
	want := []string{`a[x="a,b"]`, `:not(.a,.b)`, `x\,y`, `z\`}
	if len(got) != len(want) {
		t.Fatal(got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%q != %q", got, want)
		}
	}
}
func TestFallbackBoundsAndAdmission(t *testing.T) {
	source := strings.Repeat("A", maxSelectorBytes+1) + ":before"
	got, err := ConservativeFallbackWithMemory(source, resourceguard.NewMemory(1))
	if err != nil || got.Key.Kind != 0 || got.PositiveSource != "" || !got.GeneratedPseudo {
		t.Fatalf("%+v %v", got, err)
	}
	expectTermination(t, termination.MemoryExceeded, func() { ConservativeFallbackWithMemory("DIV:unsupported", resourceguard.NewMemory(1)) })
	if allocs := testing.AllocsPerRun(10, func() { ConservativeFallback(source) }); allocs != 0 {
		t.Fatal(allocs)
	}
}
func TestPseudoMatchingDoesNotCopy(t *testing.T) {
	for _, source := range []string{":checked", ":lang(" + strings.Repeat("a", 8192) + ")"} {
		sel, err := ParseGroup(source)
		if err != nil {
			t.Fatal(err)
		}
		n := &html.Node{Type: html.ElementNode, Data: "input", DataAtom: atom.Input, Attr: []html.Attribute{{Key: "checked"}, {Key: "type", Val: strings.Repeat("A", 1<<20)}, {Key: "lang", Val: "en"}}}
		control := NewMatchControl(nil)
		var matcher Matcher = sel
		if allocs := testing.AllocsPerRun(10, func() { control.Match(matcher, n) }); allocs != 0 {
			t.Fatalf("%s: %g", source, allocs)
		}
	}
}

func TestCancellationInsideNestedTraversal(t *testing.T) {
	for _, combinator := range []string{" ~ i", " i"} {
		sel, err := ParseGroup("x" + strings.Repeat(combinator, 100))
		if err != nil {
			t.Fatal(err)
		}
		root := &html.Node{Type: html.ElementNode, Data: "i"}
		target := root
		for i := 0; i < 500; i++ {
			n := &html.Node{Type: html.ElementNode, Data: "i"}
			if combinator == " i" {
				target.AppendChild(n)
			} else {
				root.AppendChild(n)
			}
			target = n
		}
		calls := 0
		control := NewMatchControl(func() {
			calls++
			if calls == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
		expectTermination(t, termination.CPUExceeded, func() { control.Match(sel, target) })
		if calls != 2 {
			t.Fatalf("%q: calls=%d", combinator, calls)
		}
	}
}
