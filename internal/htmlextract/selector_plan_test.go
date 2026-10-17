package htmlextract

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestOverComplexSelectorRetainsSafeFinalAncestorScope(t *testing.T) {
	sequence := 0
	plans, _, _ := planSelectorList(`u + .body .rio-asin-container-image img`, &sequence, nil, maxSelectorBranches)
	plan := plans[0]
	memory := resourceguard.NewMemory(1 << 20)
	plan.makeUncertain(memory)
	if !plan.uncertain || len(plan.execution.compounds) != 2 || len(plan.execution.combinators) != 1 || plan.execution.combinators[0] != ' ' {
		t.Fatalf("unexpected conservative plan: %+v", plan)
	}
	if used := memory.Used(); used != 0 {
		t.Fatalf("compiled conservative scope charged %d bytes, want matcher reuse", used)
	}

	ordinary := &html.Node{Type: html.ElementNode, Data: "img"}
	container := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "class", Val: "rio-asin-container-image"}}}
	product := &html.Node{Type: html.ElementNode, Data: "img", Parent: container}
	container.FirstChild = product
	if plan.scope.Match(ordinary) {
		t.Fatal("conservative selector scope matched an unrelated image")
	}
	if !plan.scope.Match(product) {
		t.Fatal("conservative selector scope did not retain the necessary ancestor")
	}
}

func TestPreparedMathDeclarationUsesCPUControl(t *testing.T) {
	value := `calc(1px + 1px)`
	tokens, status := lexValue(value, nil)
	guard := &cpuGuard{shouldStop: func() bool { return true }}
	prepared := prepareDeclaration(declaration{
		prop: fontSize, value: value, valueTokens: tokens, valueStatus: status, tokensReady: true,
	}, guard)
	if !guard.stopped {
		t.Fatal("math declaration validation did not sample the CPU control")
	}
	if !prepared.validityReady || prepared.validity != valueUnsupported {
		t.Fatalf("stopped declaration validity = (%d, %t), want unsupported", prepared.validity, prepared.validityReady)
	}
}

func TestUncertainSelectorScopeDoesNotCrossFinalSiblingCombinator(t *testing.T) {
	sequence := 0
	plans, _, _ := planSelectorList(`.product + img`, &sequence, nil, maxSelectorBranches)
	plan := plans[0]
	plan.makeUncertain(nil)
	if len(plan.execution.compounds) != 1 {
		t.Fatalf("sibling selector was unsafely narrowed: %+v", plan.execution)
	}
	if !plan.scope.Match(&html.Node{Type: html.ElementNode, Data: "img"}) {
		t.Fatal("sibling selector lost its safe rightmost scope")
	}
}

func TestConservativeSelectorScopeAlwaysHasSafeFallback(t *testing.T) {
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	for _, prefix := range []string{"", "*", "["} {
		if matcher := compileConservativeScope(prefix, nil); matcher == nil || !matcher.Match(node) {
			t.Fatalf("scope %q did not use a universal fallback", prefix)
		}
	}
	matcher := compileConservativeScope("div", nil)
	if matcher == nil || matcher.Match(node) {
		t.Fatal("valid conservative scope lost its tag constraint")
	}
}

func TestSelectorIndexIncludesEveryPotentialCandidate(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseStylesheetCSS(`p{display:none}.target{opacity:0}#chosen{visibility:hidden}.ancestor *{font-size:0}[data-x]{color:red}`)
	s.buildSelectorIndex()
	ancestor := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "class", Val: "ancestor"}}}
	node := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "id", Val: "chosen"}, {Key: "class", Val: "target"}, {Key: "data-x", Val: "1"}}, Parent: ancestor}
	refs := s.candidates(node)
	got := make(map[string]bool)
	for _, ref := range refs {
		got[s.rules[ref.rule].plans[ref.branch].source] = true
	}
	for _, selector := range []string{"p", ".target", "#chosen", ".ancestor *", "[data-x]"} {
		if !got[selector] {
			t.Errorf("index omitted %q; candidates=%v", selector, got)
		}
	}
}

func TestDirectSelectorIndexHasNoAncestorSearch(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`p{display:none}`)
	s.buildSelectorIndex()
	if len(s.index.ancestorTags) != 0 || len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0 {
		t.Fatalf("direct selector populated ancestor index: %+v", s.index)
	}
	parent := &html.Node{Type: html.ElementNode, Data: "div"}
	for range 128 {
		parent = &html.Node{Type: html.ElementNode, Data: "div", Parent: parent}
	}
	node := &html.Node{Type: html.ElementNode, Data: "p", Parent: parent}
	refs := s.candidates(node)
	if len(refs) != 1 || s.rules[refs[0].rule].plans[refs[0].branch].source != "p" {
		t.Fatalf("direct selector candidates = %+v", refs)
	}
}

func TestNamespaceSelectorsRetainEveryPotentialCandidate(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`s|text{display:none}*|text{display:none}|text{display:none}s|*{visibility:hidden}s|linearGradient{opacity:0}[s|href]{display:none}`)
	s.buildSelectorIndex()
	node := &html.Node{Type: html.ElementNode, Data: "text", Namespace: "svg"}
	refs := s.candidates(node)
	got := make(map[string]bool)
	for _, ref := range refs {
		got[s.rules[ref.rule].plans[ref.branch].source] = true
	}
	for _, selector := range []string{"s|text", "*|text", "|text", "s|*", "s|linearGradient", "[s|href]"} {
		if !got[selector] {
			t.Errorf("index omitted %q; candidates=%v", selector, got)
		}
	}
	if plan := s.rules[0].plans[0]; plan.scopePrefix != "text" || plan.key != (selectorKey{kind: selectorTag, value: "text"}) || !plan.uncertain {
		t.Fatalf("qualified selector plan = %+v", plan)
	}
	if plan := s.rules[4].plans[0]; plan.scopePrefix != "" || plan.key.kind != selectorUniversal || !plan.uncertain {
		t.Fatalf("case-sensitive qualified selector plan = %+v", plan)
	}
}

func TestNamespaceVisibilityIsConservative(t *testing.T) {
	for _, test := range []struct {
		name, css string
	}{
		{"qualified", `@namespace s url(http://www.w3.org/2000/svg);s|text{display:none}`},
		{"wildcard prefix", `*|text{display:none}`},
		{"default", `@namespace url(http://www.w3.org/2000/svg);text{display:none}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.css+`</style><svg><text>T</text></svg>`)
			if got := findText(t, document, "T").Label; got != "unknown" {
				t.Fatalf("label = %q, want unknown", got)
			}
		})
	}
}

func TestMixedCaseSVGTypeSelectorsAreConservative(t *testing.T) {
	for _, test := range []struct {
		name, css, body, want string
	}{
		{
			name: "direct canonical name",
			css:  `textPath{display:none}`,
			body: `<svg><textPath>T</textPath></svg>`,
			want: "unknown",
		},
		{
			name: "canonical ancestor name",
			css:  `foreignObject div{display:none}`,
			body: `<svg><foreignObject><div>T</div></foreignObject></svg>`,
			want: "unknown",
		},
		{
			name: "ordinary uppercase HTML selector",
			css:  `DIV{display:none}`,
			body: `<div>T</div>`,
			want: "concealed",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.css+`</style>`+test.body)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMixedCaseSVGTypeSelectorIsIndexed(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`textPath{display:none}`)
	s.buildSelectorIndex()
	node := &html.Node{Type: html.ElementNode, Data: "textPath", Namespace: "svg"}
	refs := s.candidates(node)
	if len(refs) != 1 {
		t.Fatalf("mixed-case SVG candidates = %+v, want one", refs)
	}
	plan := s.rules[refs[0].rule].plans[refs[0].branch]
	if !plan.foreignCaseType || !plan.uncertain || !plan.scope.Match(node) {
		t.Fatalf("mixed-case SVG plan = %+v", plan)
	}

	s = sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`textpath{display:none}`)
	s.buildSelectorIndex()
	refs = s.candidates(node)
	if len(refs) != 1 {
		t.Fatalf("lowercase SVG candidates = %+v, want one candidate for authoritative matching", refs)
	}
	plan = s.rules[refs[0].rule].plans[refs[0].branch]
	if plan.foreignCaseType || plan.uncertain || plan.matcher.Match(node) {
		t.Fatalf("wrong-case SVG selector matched canonical node: %+v", plan)
	}
}

func TestSelectorIndexDoesNotReturnUnrelatedKeyedRules(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`.wanted{display:none}#chosen{opacity:0}section{visibility:hidden}`)
	s.buildSelectorIndex()
	node := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "other"}}}
	if refs := s.candidates(node); len(refs) != 0 {
		t.Fatalf("unrelated candidates = %+v", refs)
	}
}

func TestSelectorIndexRemovesRulesWithoutRelevantDeclarations(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`*{}.unused{unknown-property:value}p{display:none}`)
	if len(s.rules) != 3 {
		t.Fatalf("parsed rules = %d, want 3", len(s.rules))
	}
	s.buildSelectorIndex()
	if len(s.rules) != 1 || len(s.rules[0].decls) != 1 {
		t.Fatalf("indexed rules = %+v", s.rules)
	}
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	if refs := s.candidates(node); len(refs) != 1 {
		t.Fatalf("relevant candidates = %+v", refs)
	}
}

func TestSelectorIndexBypassesAttributeWorkWithoutSelectors(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.buildSelectorIndex()
	node := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: strings.Repeat("word ", 1_000)}}}
	if refs := s.candidates(node); len(refs) != 0 {
		t.Fatalf("candidates without selectors = %+v", refs)
	}
}

func TestActiveAncestorCandidatesMatchParentWalk(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`.wanted *{display:none}#outer *{opacity:0}div *{visibility:hidden}svg *{font-size:0}linearGradient *{color:red}.absent *{display:none}p{display:block}`)
	s.buildSelectorIndex()
	root, err := html.Parse(strings.NewReader(`<div id="outer" class="wanted"><div class="wanted"><p></p></div><svg><linearGradient><rect></rect></linearGradient></svg></div>`))
	if err != nil {
		t.Fatal(err)
	}
	active := &s.runtime.activeAncestors
	active.reset(s.index.count)
	active.enabled = true
	defer func() { active.enabled = false }()

	refSet := func(refs []selectorRef) map[int]bool {
		set := make(map[int]bool, len(refs))
		for _, ref := range refs {
			set[ref.sequence] = true
		}
		return set
	}
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.ElementNode {
			active.enabled = false
			walked, complete := s.collectCandidates(node, nil)
			walked = append([]selectorRef(nil), walked...)
			active.enabled = true
			if !complete {
				t.Fatal("parent-walk candidate collection failed")
			}
			indexed, complete := s.collectCandidates(node, nil)
			indexed = append([]selectorRef(nil), indexed...)
			if !complete || !reflect.DeepEqual(refSet(indexed), refSet(walked)) {
				t.Fatalf("candidate mismatch for <%s>: active=%v walked=%v complete=%t", node.Data, refSet(indexed), refSet(walked), complete)
			}
		}
		var activation selectorAncestorActivation
		if node.Type == html.ElementNode && node.FirstChild != nil {
			var complete bool
			activation, complete = s.activateAncestorBuckets(node, nil)
			if !complete {
				t.Fatalf("cannot activate <%s>", node.Data)
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if node.Type == html.ElementNode {
			s.deactivateAncestorBuckets(activation)
		}
	}
	walk(root)
	if len(active.buckets) != 0 {
		t.Fatalf("active ancestor buckets leaked after traversal: %d", len(active.buckets))
	}
}
