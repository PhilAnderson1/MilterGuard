package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestForeignAncestorScopeKeepsTarget(t *testing.T) {
	for _, selector := range []string{"foreignObject div", "textPath div.target", "foreignObject textPath div#target"} {
		s := sheet{limits: DefaultLimits()}
		s.parseStylesheetCSS(selector + "{display:none}")
		s.buildSelectorIndex()
		node := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "class", Val: "target"}, {Key: "id", Val: "target"}}}
		refs := s.candidates(node)
		if len(refs) != 1 {
			t.Fatalf("%s: missing candidate", selector)
		}
		plan := s.rules[refs[0].rule].plans[refs[0].branch]
		if !plan.uncertain || !plan.scope.Match(node) {
			t.Fatalf("%s: target excluded", selector)
		}
		if plan.scope.Match(&html.Node{Type: html.ElementNode, Data: "span"}) {
			t.Fatalf("%s: lost ordinary target constraint", selector)
		}
	}
	for _, test := range []struct{ selector, want string }{{"foreignObject div", "unknown"}, {"foreignobject div", "concealed"}} {
		d := inspectHTML(t, `<style>`+test.selector+`{display:none}</style><foreignObject><div>T</div></foreignObject>`)
		if got := findText(t, d, "T").Label; got != test.want {
			t.Fatalf("%s: %s", test.selector, got)
		}
	}
}

func TestInertInlineStylesCannotAbandonActiveCascade(t *testing.T) {
	for _, container := range []string{"template", "object", "iframe", "noembed", "noframes"} {
		src := `<style>p{display:none}</style><p>T</p><` + container + `><template><div style="` + strings.Repeat("color:red;", 53000) + `">ignored</div></template></` + container + `>`
		d, err := Analyze([]byte(src), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if d.Usage.CSSLimitExceeded || findText(t, d, "T").Label != "concealed" {
			t.Fatalf("%s: inert CSS affected active text", container)
		}
	}
}

func TestOptionalMatchCacheDeclinesAtomically(t *testing.T) {
	for _, existing := range []bool{false, true} {
		m := resourceguard.NewMemory(160)
		s := sheet{memory: m, index: selectorIndex{count: 1}, runtime: sheetRuntime{cacheMatches: true}}
		first := &html.Node{}
		if existing {
			s.runtime.matchCaches = make([]resourceguard.Table[*html.Node, uint8], 1)
			s.runtime.matchCaches[0].Set(nil, first, 1)
			m.Reserve(150)
		}
		before := m.Used()
		s.cacheMatch(&selectorPlan{}, &html.Node{}, true)
		if m.Exhausted() || m.Used() != before {
			t.Fatalf("existing=%v: declined insertion consumed budget", existing)
		}
		m.Reserve(1)
		if existing {
			s.cacheMatch(&selectorPlan{}, first, true)
			if s.runtime.matchCaches[0].View()[first] != 2 {
				t.Fatal("existing result lost")
			}
		}
	}
}

func TestOptionalMatchCacheBoundaryDocument(t *testing.T) {
	src := `<style>` + strings.Repeat(`p{color:black}`, 50) + `@media(min-width:500px){p{color:red}}</style>` + strings.Repeat(`<p>T</p>`, 20500)
	limits := DefaultLimits()
	limits.MemoryBytes = 8 << 20
	d, err := Analyze([]byte(src), limits)
	if err != nil || len(d.Text) != 20500 {
		t.Fatalf("text=%d used=%d err=%v", len(d.Text), d.Usage.MemoryBytes, err)
	}
	t.Logf("complete text=%d charged=%d", len(d.Text), d.Usage.MemoryBytes)
}

func TestAncestorMatchingWithoutCacheCapacity(t *testing.T) {
	for _, selector := range []string{"div p.target", "div div p"} {
		sequence := 0
		plans, _, _ := planSelectorList(selector, &sequence, nil, maxSelectorBranches)
		plan := &plans[0]
		root := &html.Node{Type: html.ElementNode, Data: "div"}
		middle := &html.Node{Type: html.ElementNode, Data: "div"}
		root.AppendChild(middle)
		leaf := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "target"}}}
		middle.AppendChild(leaf)
		m := resourceguard.NewMemory(1)
		s := sheet{memory: m, selectorControl: cascadia.NewMatchControl(nil)}
		// Required traversal scratch is already owned; only optional caching is tight.
		s.runtime.ancestorNodes = make([]*html.Node, 0, 8)
		matched, complete := s.matchAncestorChain(plan, leaf, selectorMatchContext{}, testCPUGuard(cpuGuard{memory: m}))
		if !matched || !complete || m.Exhausted() || m.Used() != 0 {
			t.Fatalf("%s: matched=%v complete=%v budget=%d", selector, matched, complete, m.Used())
		}
	}
}

func TestMediaRetentionAccounting(t *testing.T) {
	m := resourceguard.NewMemory(1)
	s := sheet{memory: m, cpu: testCPUGuard(cpuGuard{memory: m})}
	expectTermination(t, termination.MemoryExceeded, func() { s.mediaCanApply("screen and (min-width:1px)") })
	if !m.Exhausted() {
		t.Fatal("temporary applicability parsing bypassed budget")
	}

	for _, query := range []string{"print", "screen and (min-width:1px), (max-width:10px)", "unsupported", strings.Repeat("x", 4097), strings.Repeat("screen and ", 17) + "screen"} {
		m := resourceguard.NewMemory(10000)

		if got := parseMediaBudgeted(query, m); !reflect.DeepEqual(got, parseMedia(query)) || m.Used() == 0 || m.Exhausted() {
			t.Fatalf("query %q accounting or semantics changed", query)
		}

	}
}

func TestManyExternalMediaAttributes(t *testing.T) {
	var src strings.Builder
	for i := 0; i < 10000; i++ {
		fmt.Fprintf(&src, `<link rel="stylesheet" href="https://example.test/a.css" media="screen and (min-width:%dpx)">`, i)
	}
	src.WriteString(`<p>T</p>`)
	d, err := Analyze([]byte(src.String()), DefaultLimits())
	if err != nil || !d.UnresolvedStylesheet {
		t.Fatalf("external styles must remain unresolved: %v", err)
	}
}

func BenchmarkAuditInertStyles(b *testing.B) {
	for _, styled := range []bool{false, true} {
		node := `<div>T</div>`
		if styled {
			node = `<div style="color:red;display:block;font-size:12px">T</div>`
		}
		data := []byte(`<p>visible</p><template>` + strings.Repeat(node, 2000) + `</template>`)
		b.Run(fmt.Sprintf("styled%v", styled), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Analyze(data, DefaultLimits()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The baseline cached these one-shot applicability queries. This benchmark
// measures the replacement path, including transient parsing, with no retention.
func BenchmarkAuditMediaApplicability(b *testing.B) {
	values := make([]string, 10000)
	for i := range values {
		values[i] = fmt.Sprintf("screen and (min-width:%dpx)", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := resourceguard.NewMemory(1)
		s := sheet{memory: m, cpu: testCPUGuard(cpuGuard{memory: m})}
		for _, v := range values {
			s.mediaCanApply(v)
		}
		if m.Used() != 0 {
			b.Fatal("unexpected retention")
		}
	}
}

func TestInertContentStillHasStructuralLimitsAndCancellation(t *testing.T) {
	source := []byte(`<template>` + strings.Repeat(`<div style="color:red">T</div>`, 2000) + `</template>`)
	limits := DefaultLimits()
	limits.InputBytes = len(source) - 1

	if _, err := Analyze(source, limits); err == nil {
		t.Fatal("inert source bypassed input limit")
	}

	limits = DefaultLimits()
	limits.MemoryBytes = 4096
	expectTermination(t, termination.MemoryExceeded, func() { Analyze(source, limits) })
	root, err := html.Parse(strings.NewReader(string(source)))
	if err != nil {
		t.Fatal(err)
	}
	doc := parsedDocument{elements: resourceguard.Table[*html.Node, elementPreparation]{}}
	p := processor{Limits: DefaultLimits(), shouldStop: func() {
		{
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}}
	walker := documentWalker{processor: p, document: &doc}
	expectTermination(t, termination.CPUExceeded, func() { walker.run(root) })
	if walker.nodeCount != 256 {
		t.Fatalf("inert traversal cancellation: nodes=%d", walker.nodeCount)
	}
}

// Test convenience wrappers; production supplies the sheet's complete CPU guard.
func parseMedia(src string) mediaCondition { return parseMediaBudgeted(src, nil) }

// Both retained conditions and temporary applicability parsing consume the
// monotonic allocation budget. Per-query bounds also limit regexp scratch.
func parseMediaBudgeted(src string, memory *resourceguard.Memory) mediaCondition {
	return parseMediaWithBudget(src, &cpuGuard{memory: memory})
}
