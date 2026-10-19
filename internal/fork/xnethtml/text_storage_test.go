package html

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/atom"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
)

func TestTextStoragePublishesImmutablePrefixes(t *testing.T) {
	m := resourceguard.NewMemory(1 << 20)
	p := parser{guard: &resourceGuard{limits: ResourceLimits{Memory: m}}}
	a, b := &Node{Type: TextNode, Data: "a"}, &Node{Type: TextNode, Data: "b"}
	p.appendText(a, "1")
	retained := a.Data
	for range 10000 {
		p.appendText(a, "x")
	}
	if retained != "a1" || len(a.Data) != 10002 {
		t.Fatal("prefix changed or append lost")
	}
	p.appendText(b, "2")
	p.appendText(a, "3")
	if b.Data != "b2" || !strings.HasSuffix(a.Data, "x3") {
		t.Fatal("destination change lost text")
	}
	if m.Used() > 100000 {
		t.Fatalf("nonlinear allocation: %d", m.Used())
	}
}

func TestTextStorageRecoveryAndFragments(t *testing.T) {
	for _, prefix := range []string{"<p>", "<table>", "<b><i><table>"} {
		m := resourceguard.NewMemory(2 << 20)
		input := prefix + strings.Repeat("x", 32769) + strings.Repeat("</unknown>x", 10000)
		root, err := ParseWithOptions(strings.NewReader(input), ParseOptionResourceLimits(ResourceLimits{Memory: m}))
		if err != nil {
			t.Fatal(err)
		}
		var text strings.Builder
		var walk func(*Node)
		walk = func(n *Node) {
			if n.Type == TextNode {
				text.WriteString(n.Data)
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				walk(c)
			}
		}
		walk(root)
		if text.String() != strings.Repeat("x", 42769) {
			t.Fatal("recovery lost text")
		}
	}
	context := &Node{Type: ElementNode, Data: "div", DataAtom: atom.Div}
	nodes, err := ParseFragment(strings.NewReader("a</unknown>b"), context)
	if err != nil || len(nodes) != 1 || nodes[0].Data != "ab" {
		t.Fatalf("fragment: %v, %v", nodes, err)
	}
}
