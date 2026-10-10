package htmlextract

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/html"
)

func inspectHTML(t *testing.T, src string) Document {
	t.Helper()
	// Existing four-property policy tests supply an explicit canvas. New colour
	// tests below deliberately do not inject a background.
	p := processor{Limits: DefaultLimits(), retainInspection: true}
	src = `<style>html{background-color:white}</style>` + src
	r, e := p.process([]byte(src))
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func findText(t *testing.T, in Document, text string) Text {
	t.Helper()
	for _, v := range in.Text {
		if v.Node != nil && v.Node.Data == text {
			return v
		}
	}
	t.Fatalf("missing %q in %+v", text, in.Text)
	return Text{}
}

func textStyle(text Text, name string) Value {
	if text.inspection == nil {
		return Value{}
	}
	for property, propertyName := range names {
		if propertyName == name {
			return text.inspection.style[property]
		}
	}
	return Value{}
}

func TestProductionTextResultIsCompact(t *testing.T) {
	if size := unsafe.Sizeof(Text{}); size > 192 {
		t.Fatalf("Text retains too much per-node state: %d bytes", size)
	}
}

func TestAnalyzeValidatesLimitsWithoutPanicking(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Limits)
	}{
		{"input bytes", func(l *Limits) { l.InputBytes = 0 }},
		{"nodes", func(l *Limits) { l.Nodes = 0 }},
		{"text nodes", func(l *Limits) { l.TextNodes = 0 }},
		{"depth", func(l *Limits) { l.Depth = -1 }},
		{"rules", func(l *Limits) { l.Rules = -1 }},
		{"selectors", func(l *Limits) { l.Selectors = -1 }},
		{"selector bytes", func(l *Limits) { l.SelectorBytes = 0 }},
		{"match work", func(l *Limits) { l.MatchWork = 0 }},
		{"media cases", func(l *Limits) { l.MediaCases = 0 }},
		{"expression work", func(l *Limits) { l.ExpressionWork = 0 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			limits := DefaultLimits()
			c.change(&limits)
			if _, err := Analyze([]byte(`<p>T</p>`), limits); err == nil || !strings.Contains(err.Error(), "invalid limit") {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestAnalyzeDoesNotPreallocateCallerDepth(t *testing.T) {
	limits := DefaultLimits()
	limits.Depth = int(^uint(0) >> 1)
	if _, err := Analyze([]byte(`<p>T</p>`), limits); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyGeneratedContentElementsAreRetained(t *testing.T) {
	document := inspectHTML(t, `<div><p>T</p><img src="x"><input type="button" value="Go"><span>U</span></div>`)
	if len(document.Elements) != 2 || document.Elements[0].Node.Data != "img" || document.Elements[1].Node.Data != "input" {
		t.Fatalf("retained elements = %+v", document.Elements)
	}
}

func TestNodeLimitsBeforeAndAfterTreeConstruction(t *testing.T) {
	t.Run("lexical nodes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Nodes = 3
		err := preflight([]byte(`<b></b><i></i><u></u><s></s>`), limits)
		if err == nil || !strings.Contains(err.Error(), "lexical nodes") {
			t.Fatalf("node limit error = %v", err)
		}
	})
	t.Run("lexical text nodes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.TextNodes = 2
		err := preflight([]byte(`first<b>second</b>third`), limits)
		if err == nil || !strings.Contains(err.Error(), "lexical text nodes") {
			t.Fatalf("text-node limit error = %v", err)
		}
	})
	t.Run("parser-created nodes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Nodes = 2
		_, err := (processor{Limits: limits}).parseDocument([]byte(`<p>x`))
		if err == nil || !strings.Contains(err.Error(), "tree nodes") {
			t.Fatalf("tree node limit error = %v", err)
		}
	})
}

func TestPreflightSelfClosingTagDepth(t *testing.T) {
	limits := DefaultLimits()
	limits.Depth = 2

	t.Run("non-void HTML remains open", func(t *testing.T) {
		err := preflight([]byte(`<div/><span/><p/>`), limits)
		if err == nil || !strings.Contains(err.Error(), "lexical depth") {
			t.Fatalf("depth limit error = %v", err)
		}
	})

	t.Run("void HTML remains self-contained", func(t *testing.T) {
		if err := preflight([]byte(`<br/><img/><input/><hr/>`), limits); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("foreign self-closing syntax is honored", func(t *testing.T) {
		if err := preflight([]byte(`<svg><g><path/><circle/><rect/></g></svg><math><mrow><mi/><mn/></mrow></math>`), limits); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("HTML integration point resumes HTML rules", func(t *testing.T) {
		err := preflight([]byte(`<svg><foreignObject><div/></foreignObject></svg>`), limits)
		if err == nil || !strings.Contains(err.Error(), "lexical depth") {
			t.Fatalf("depth limit error = %v", err)
		}
	})
}

func TestUnsupportedCSSVolumeDoesNotAbortAnalysis(t *testing.T) {
	var css strings.Builder
	for i := 0; i < 300; i++ {
		css.WriteString("@unsupported-")
		css.WriteString(strconv.Itoa(i))
		css.WriteString("{x}")
	}
	css.WriteString("p{display:none}")

	document, err := (processor{Limits: DefaultLimits()}).process([]byte("<style>" + css.String() + "</style><p>T</p>"))
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "concealed" {
		t.Fatalf("unsupported CSS volume changed concealment to %q", got)
	}
}
func TestSelectors(t *testing.T) {
	for _, sel := range []string{"*", "p", ".x", "#target", "[data-x]", "[data-x=a]", "div p", "div > p", "i + p", "i ~ p", "p:not(.other)", "#absent,p"} {
		t.Run(sel, func(t *testing.T) {
			in := inspectHTML(t, `<div><i></i><p id="target" class="x" data-x="a">T</p></div><style>`+sel+`{display:none}</style>`)
			if findText(t, in, "T").Label != "concealed" {
				t.Fatal(in)
			}
		})
	}
}
func TestCascade(t *testing.T) {
	cases := []struct{ name, css, inline, want string }{
		{"source", "p{display:none}p{display:block}", "", "visible"},
		{"specificity", "#t{display:none}p{display:block}", "", "concealed"},
		{"matching branch", "#absent,p{display:none}.c{display:block}", "", "visible"},
		{"inline", "#t{display:none}", "display:block", "visible"},
		{"important author", "p{display:none!important}", "display:block", "concealed"},
		{"inline important", "#t{display:none!important}", "display:block ! important", "visible"},
		{"invalid ignored", "p{display:none;display:banana}", "", "concealed"},
		{"unsupported winner", "p{display:none;display:var(--d)}", "", "visible"},
		{"unsupported loser", "p{display:var(--d);display:none}", "", "concealed"},
		{"font shorthand", "p{font-size:0;font:12px serif}", "", "unknown"},
		{"all shorthand", "p{display:none;all:revert}", "", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, `<p id=t class=c style="`+c.inline+`">T</p><style>`+c.css+`</style>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("got %s want %s: %+v", got, c.want, in)
			}
		})
	}
}
func TestInlineDeclarationsDecodeCSSIdentifierEscapes(t *testing.T) {
	for _, style := range []string{
		`displa\79 :none`,
		`display:n\6f ne`,
		`visi\62 ility:hidden`,
		`visibility:h\69 dden`,
		`opa\63 ity:0`,
		`font-si\7a e:0`,
	} {
		in := inspectHTML(t, `<span style="`+style+`">T</span>`)
		if got := findText(t, in, "T").Label; got != "concealed" {
			t.Errorf("style %q label = %q, want concealed", style, got)
		}
	}
}

func TestCSSIdentifierEscapesDoNotChangeTokenMeaning(t *testing.T) {
	cases := []struct {
		name, style, want string
	}{
		{
			"escaped bang is part of identifier",
			`display:block;display:none\!important`,
			"visible",
		},
		{
			"escaped trailing space is part of identifier",
			`visibility:visible;visibility:hidden\ `,
			"visible",
		},
		{
			"escaped digit remains an identifier",
			`opacity:1;opacity:\30`,
			"visible",
		},
		{
			"comment may separate priority tokens",
			`display:block;display:none!/**/important`,
			"concealed",
		},
		{
			"important identifier may contain an escape",
			`display:block;display:none!\69mportant`,
			"concealed",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, `<p style="`+c.style+`">T</p>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
		})
	}
}

func TestInlineAtRuleDeclarationsAreNotAppliedUnconditionally(t *testing.T) {
	cases := []struct {
		name, style, want string
	}{
		{
			"media cannot reveal top-level hidden content",
			`visibility:hidden;@media print{visibility:visible}`,
			"concealed",
		},
		{
			"media declaration is not unconditional",
			`@media screen{display:none}`,
			"visible",
		},
		{
			"keyframes cannot reveal top-level hidden content",
			`display:none;@keyframes k{from{display:block}}`,
			"concealed",
		},
		{
			"unknown at-rule declaration is not unconditional",
			`@supports(display:grid){display:none}`,
			"visible",
		},
		{
			"at-rule swallowed into declaration remains uncertain",
			`display:none @keyframes k{from{display:block}}`,
			"unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, `<p style="`+c.style+`">T</p>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
		})
	}

	t.Run("nested ruleset cannot escape into document stylesheet", func(t *testing.T) {
		s := sheet{limits: DefaultLimits()}
		if declarations := s.parseCSS(`@keyframes k{p{display:none}}`, true); len(declarations) != 0 {
			t.Fatalf("inline declarations = %+v", declarations)
		}
		if len(s.rules) != 0 {
			t.Fatalf("inline style created document rules: %+v", s.rules)
		}
	})
}

func TestInheritance(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"display ancestor", `<div style="display:none"><p style="display:block">T</p></div>`, "concealed"},
		{"display unknown ancestor", `<div style="display:var(--d)"><p style="display:block">T</p></div>`, "visible"},
		{"visibility inherited", `<div style="visibility:hidden"><p>T</p></div>`, "concealed"},
		{"visibility restored", `<div style="visibility:hidden"><p style="visibility:visible">T</p></div>`, "visible"},
		{"opacity product", `<div style="opacity:10%"><p style="opacity:.1">T</p></div>`, "concealed"},
		{"opacity not inherited", `<div style="opacity:.2"><p>T</p></div>`, "visible"},
		{"opacity zero proof", `<div style="opacity:var(--o)"><p style="opacity:0">T</p></div>`, "concealed"},
		{"font parent", `<div style="font-size:20px"><p style="font-size:10%">T</p></div>`, "concealed"},
		{"font rem root", `<html style="font-size:20px"><body><p style="font-size:.1rem">T</p></body></html>`, "concealed"},
		{"font root rem", `<html style="font-size:.125rem"><body>T</body></html>`, "concealed"},
		{"font restored", `<div style="font-size:0"><p style="font-size:16px">T</p></div>`, "visible"},
		{"font inherit", `<div style="font-size:0"><p style="font-size:inherit">T</p></div>`, "concealed"},
		{"font initial", `<div style="font-size:0"><p style="font-size:initial">T</p></div>`, "visible"},
		{"font unset", `<div style="font-size:0"><p style="font-size:unset">T</p></div>`, "concealed"},
		{"display unset", `<div style="display:none"><p style="display:unset">T</p></div>`, "concealed"},
		{"hidden until found with box", `<div hidden="until-found" style="display:block">T</div>`, "concealed"},
		{"hidden until found author override", `<div hidden="until-found" style="content-visibility:visible">T</div>`, "visible"},
		{"opacity inherit", `<div style="opacity:.1"><p style="opacity:inherit">T</p></div>`, "concealed"},
		{"ex unsupported", `<p style="font-size:2ex">T</p>`, "unknown"},
		{"ch unsupported", `<p style="font-size:2ch">T</p>`, "unknown"},
		{"lh unsupported", `<p style="font-size:2lh">T</p>`, "unknown"},
		{"collapse", `<p style="visibility:collapse">T</p>`, "concealed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, c.src)
			v := findText(t, in, "T")
			if v.Label != c.want {
				t.Fatalf("got %+v want %s", v, c.want)
			}
		})
	}
}
func TestNumbersAndColours(t *testing.T) {
	for _, c := range []struct {
		v    string
		want float64
	}{{"0", 0}, {"2px", 2}, {"1.5pt", 2}, {".125em", 2}, {"12.5%", 2}, {".125rem", 2}} {
		v, st := resolve(fontSize, c.v, initial(), initial())
		if st != 1 || v.Number != c.want {
			t.Fatal(c, v, st)
		}
	}
	for _, c := range []struct {
		v    string
		want float64
	}{{"-2", 0}, {"200%", 1}, {".25", .25}} {
		v, st := resolve(opacity, c.v, initial(), initial())
		if st != 1 || v.Number != c.want {
			t.Fatal(c, v, st)
		}
	}
	for _, c := range []struct{ v, want string }{{"#123", "rgba(17,34,51,1)"}, {"#1234", "rgba(17,34,51,0.26666666666666666)"}, {"#11223344", "rgba(17,34,51,0.26666666666666666)"}, {"rgb(100%,0%,0%)", "rgba(255,0,0,1)"}, {"rgba(255,0,0,.5)", "rgba(255,0,0,0.5)"}, {"red", "rgba(255,0,0,1)"}, {"transparent", "rgba(0,0,0,0)"}} {
		v, st := parseColor(c.v)
		if st != 1 || v != c.want {
			t.Fatal(c, v, st)
		}
	}
	in := inspectHTML(t, `<div style="color:red;background-color:blue"><p style="background-color:currentColor">T</p><p>U</p></div>`)
	v := findText(t, in, "T")
	if textStyle(v, "color").Text != "rgba(255,0,0,1)" || textStyle(v, "background-color").Text != textStyle(v, "color").Text {
		t.Fatal(v)
	}
	if textStyle(findText(t, in, "U"), "background-color").Text != "rgba(0,0,0,0)" {
		t.Fatal(in)
	}
}
func TestConditionsAndRecovery(t *testing.T) {
	for _, c := range []struct{ css, want string }{{"@media all{p{display:none}}", "concealed"}, {"@media screen{p{display:none}}", "concealed"}, {"@media print{p{display:none}}", "visible"}, {"@media screen and (min-width:1px){p{display:none}}", "client-dependent"}, {"@supports(display:grid){p{display:none}}", "unknown"}, {"p:hover{display:none}", "visible"}, {"p::before{display:none}", "unknown"}, {"p{broken;display:none}", "concealed"}, {"p{display:banana}p{display:none}", "concealed"}, {"@media print{@supports(display:grid){p{display:none}}}", "visible"}} {
		t.Run(c.css, func(t *testing.T) {
			in := inspectHTML(t, `<p>T</p><style>`+c.css+`</style>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("%s want %s %+v", got, c.want, in)
			}
		})
	}
}

func TestStyleElementMediaAttribute(t *testing.T) {
	cases := []struct {
		name, media, css, want string
	}{
		{"print", "print", `p{display:none}`, "visible"},
		{"screen", "screen", `p{display:none}`, "concealed"},
		{"width dependent", "(max-width:1px)", `p{display:none}`, "client-dependent"},
		{"unknown", "(orientation:portrait)", `p{display:none}`, "unknown"},
		{"empty", "", `p{display:none}`, "concealed"},
		{"nested conditions", "screen", `@media print{p{display:none}}`, "visible"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, `<style media="`+c.media+`">`+c.css+`</style><p>T</p>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUnrelatedUnsupportedCSSDoesNotMakeDocumentUncertain(t *testing.T) {
	for _, src := range []string{
		`<link rel="stylesheet" href="https://example.test/email.css"><p>T</p>`,
		`<style>a:hover{text-decoration:underline}</style><p>T</p>`,
		`<style>[data-kind^="x"]{margin:1px}</style><p>T</p>`,
	} {
		in := inspectHTML(t, src)
		if got := findText(t, in, "T").Label; got != "visible" {
			t.Errorf("%q label = %q", src, got)
		}
	}
}
func TestUnsupportedSelectorUncertaintyIsLimitedToRelevantDeclarations(t *testing.T) {
	in := inspectHTML(t, `<style>p::before{display:none}</style><p>T</p><div>U</div>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("label = %q", got)
	}
	if got := findText(t, in, "U").Label; got != "visible" {
		t.Fatalf("unrelated label = %q", got)
	}

	in = inspectHTML(t, `<style>div:has(.x) .offer{visibility:hidden}.other:has(.x){opacity:0}</style><div class="offer">offer</div><div class="other">other</div><div>ordinary</div>`)
	for text, want := range map[string]string{"offer": "unknown", "other": "unknown", "ordinary": "visible"} {
		if got := findText(t, in, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
	}
}

func TestNestedInteractionSelectorsRemainUncertain(t *testing.T) {
	for _, test := range []struct {
		name, selector, body, text string
	}{
		{"is", `div:is(.secret,:hover)`, `<div class="secret">is target</div>`, "is target"},
		{"where", `div:where(.secret,:focus)`, `<div class="secret">where target</div>`, "where target"},
		{"has", `div:has(.child,:active)`, `<div>has target<span class="child"></span></div>`, "has target"},
		{"not", `div:not(:hover)`, `<div>not target</div>`, "not target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.selector+`{visibility:hidden}</style>`+test.body)
			if got := findText(t, document, test.text).Label; got != "unknown" {
				t.Fatalf("nested interaction selector label = %q", got)
			}
		})
	}
}

func TestTopLevelInteractionSelectorBranchRemainsInactive(t *testing.T) {
	document := inspectHTML(t, `<style>p:hover,span.static{display:none}</style><p>interactive</p><span class="static">static</span>`)
	if got := findText(t, document, "interactive").Label; got != "visible" {
		t.Fatalf("top-level interaction label = %q", got)
	}
	if got := findText(t, document, "static").Label; got != "concealed" {
		t.Fatalf("static selector label = %q", got)
	}
}

func TestAttributeSelectorOperatorsAreEvaluated(t *testing.T) {
	in := inspectHTML(t, `<style>[class~="mobile"]{display:none}[style*="margin: 16px"]{font-size:100%}[data-prefix^="yes"]{visibility:hidden}</style><p class="mobile">hidden</p><p style="margin: 16px 0">ordinary</p><p data-prefix="no">also ordinary</p>`)
	if got := findText(t, in, "hidden").Label; got != "concealed" {
		t.Fatalf("attribute word selector label = %q", got)
	}
	for _, value := range []string{"ordinary", "also ordinary"} {
		if got := findText(t, in, value).Label; got != "visible" {
			t.Errorf("%q label = %q", value, got)
		}
	}
}

func TestSelectorWorkLimitMakesUnprocessedTextUnknown(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 2
	inspection, err := (processor{Limits: limits}).process([]byte(`<style>p{display:none}</style><p>T</p><div>U</div>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, inspection, "T").Label; got != "unknown" {
		t.Fatalf("affected text label = %q", got)
	}
	if got := findText(t, inspection, "U").Label; got != "unknown" {
		t.Fatalf("text after budget exhaustion = %q", got)
	}
}

func TestSelectorWorkBudgetStopsBeforePartialCascadeIsTrusted(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 5
	s := sheet{limits: limits}
	s.parseCSS(`p{display:none}p{display:block}`, false)
	for ruleIndex := range s.rules {
		rule := &s.rules[ruleIndex]
		for _, selector := range rule.selectors {
			rule.costs = append(rule.costs, selectorCost(selector.String(), 1, 1, limits.MatchWork))
			rule.fallbackScopes = append(rule.fallbackScopes, uncertainSelectorScope(selector.String()))
			rule.scopeCosts = append(rule.scopeCosts, int64(len(selector.String())+1))
		}
	}
	matches := matchBudget{limit: limits.MatchWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	style, _, err := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initial(), initial(), nil, nil, 1024, false, &matches, &expressions)
	if err != nil {
		t.Fatal(err)
	}
	if !matches.exhausted || matches.used > matches.limit {
		t.Fatalf("match budget was not enforced: %+v", matches)
	}
	if style[display].Known {
		t.Fatalf("partial cascade was trusted: %+v", style[display])
	}
}

func TestSelectorWorkBudgetChargesInactiveRules(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 1
	s := sheet{limits: limits}
	s.parseCSS(`@media print{p{display:none}}@media print{div{display:none}}`, false)
	matches := matchBudget{limit: limits.MatchWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	style, _, err := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initial(), initial(), nil, nil, 1024, false, &matches, &expressions)
	if err != nil {
		t.Fatal(err)
	}
	if !matches.exhausted || style[display].Known {
		t.Fatalf("inactive rule scan escaped budget: budget=%+v display=%+v", matches, style[display])
	}
}

func TestSiblingSelectorWorkIsWeighted(t *testing.T) {
	const nodes = 100
	const limit = int64(1_000_000)
	for _, selector := range []string{"q ~ p", "q + p"} {
		base := int64(len(selector) + 1)
		want := base + int64(nodes+1)*siblingMatchWeight
		if got := selectorCost(selector, 1, nodes, limit); got != want {
			t.Errorf("selectorCost(%q) = %d, want %d", selector, got, want)
		}
	}
	if got, want := selectorCost("q p", 4, nodes, limit), int64(len("q p")+1+5); got != want {
		t.Errorf("descendant selector cost = %d, want %d", got, want)
	}
}

func TestTreeEvidence(t *testing.T) {
	in := inspectHTML(t, `<p>&amp;lt;b&amp;gt;&#x200b;&lt;style&gt;hidden&lt;/style&gt;</p><script>script</script><style>p{color:red}</style><!--comment--><template>inert</template><iframe>fallback</iframe>`)
	v := findText(t, in, "&lt;b&gt;\u200b<style>hidden</style>")
	if v.Label != "visible" {
		t.Fatal(v)
	}
	if len(in.Text) != 1 {
		t.Fatal(in)
	}
	in = inspectHTML(t, `<div style="display:none"><table>foster<tr><td>cell</table></div><p>end`)
	if findText(t, in, "foster").Label != "concealed" || findText(t, in, "cell").Label != "concealed" || findText(t, in, "end").Label != "visible" {
		t.Fatal(in)
	}
	in = inspectHTML(t, `<table style="display:none">foster<tr><td>cell</td></tr></table>`)
	if findText(t, in, "foster").Label != "visible" || findText(t, in, "cell").Label != "concealed" {
		t.Fatal(in)
	}
}
func TestAllFixtures(t *testing.T) {
	files, e := filepath.Glob("testdata/*.html")
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			b, e := os.ReadFile(f)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := (processor{Limits: DefaultLimits()}).process(b); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestLimitSubprocess(t *testing.T) {
	if os.Getenv("HTML_EVAL_CHILD") == "1" {
		l := DefaultLimits()
		name := os.Getenv("HTML_EVAL_CASE")
		var src string
		switch name {
		case "depth":
			src = strings.Repeat("<div>", 300) + "T"
		case "attribute":
			src = `<p title="` + strings.Repeat("x", 9<<20) + `">T</p>`
		case "rules":
			l.Rules = 3
			src = `<style>` + strings.Repeat(`p{display:none}`, 10) + `</style><p>T</p>`
		case "selectors":
			l.Selectors = 3
			src = `<style>p,i,b,u,div{display:none}</style><p>T</p>`
		case "work":
			l.MatchWork = 2
			src = `<style>*{display:none}</style><p>T</p>`
		case "malformed":
			src = `<style>` + strings.Repeat(`x{bad;;;;color:;}`, 1000) + `</style><p>T</p>`
		case "transitions":
			src = strings.Repeat(`<p style="visibility:hidden"><span style="visibility:visible">T</span></p>`, 1000)
		}
		document, e := (processor{Limits: l}).process([]byte(src))
		expected := name == "depth" || name == "attribute"
		if expected != (e != nil) {
			t.Fatal(name, e)
		}
		if (name == "rules" || name == "selectors") && findText(t, document, "T").Label != "unknown" {
			t.Fatal(name, document)
		}
		return
	}
	for _, name := range []string{"depth", "attribute", "rules", "selectors", "work", "malformed", "transitions"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLimitSubprocess$")
			c.Env = append(os.Environ(), "HTML_EVAL_CHILD=1", "HTML_EVAL_CASE="+name)
			b, e := c.CombinedOutput()
			if e != nil {
				t.Fatalf("%v %s", e, b)
			}
		})
	}
}
func BenchmarkLargest(b *testing.B) {
	src := []byte(`<style>.quiet{opacity:.005}</style><p>` + strings.Repeat(`<span class="quiet">padding</span> visible `, 24000) + `</p>`)
	p := processor{Limits: DefaultLimits()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := p.process(src); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkSiblingSelectorPhases(b *testing.B) {
	limits := DefaultLimits()
	body := strings.Repeat(`<p></p>`, limits.Nodes-10)
	src := []byte(`<style>q ~ p{display:none}</style>` + body)
	sparseBody := strings.Repeat(`<div></div>`, limits.Nodes-1010) + strings.Repeat(`<p></p>`, 1000)
	sparse := []byte(`<style>q ~ p{display:none}</style>` + sparseBody)
	b.Run("preflight", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := preflight(src, limits); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("tree", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := html.ParseWithOptions(bytes.NewReader(src), html.ParseOptionEnableScripting(false)); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("full-analysis", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := Analyze(src, limits); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("full-analysis-no-selector", func(b *testing.B) {
		plain := []byte(body)
		for i := 0; i < b.N; i++ {
			if _, err := Analyze(plain, limits); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("sparse-sibling-worst-case", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := Analyze(sparse, limits); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestReferenceRegressions(t *testing.T) {
	for _, c := range []struct {
		file string
		want string
	}{
		{"broken-quotes.original.html", "Before:visible"},
		{"comment-unterminated.original.html", "before:visible"},
		{"comments.original.html", "Hello:visible|visible:visible"},
		{"missing-end.original.html", "Visible:visible|Forged correspondence:concealed"},
	} {
		t.Run(c.file, func(t *testing.T) {
			b, e := os.ReadFile("testdata/" + c.file)
			if e != nil {
				t.Fatal(e)
			}
			r, e := (processor{Limits: DefaultLimits()}).process(b)
			if e != nil {
				t.Fatal(e)
			}
			var text []string
			for _, v := range r.Text {
				if v.Node != nil && strings.TrimSpace(v.Node.Data) != "" {
					text = append(text, strings.TrimSpace(v.Node.Data)+":"+v.Label)
				}
			}
			if strings.Join(text, "|") != c.want {
				t.Fatal(text)
			}
		})
	}
}
func TestPropertyUncertainty(t *testing.T) {
	in := inspectHTML(t, `<div style="color:lab(10% 2 3);font-size:2ex;display:none"><p style="font-size:16px">T</p></div><p style="color:banana;font-size:banana;background-color:lab(10% 2 3)">U</p>`)
	v := findText(t, in, "T")
	if v.Label != "concealed" || textStyle(v, "color").Known || !textStyle(v, "font-size").Known {
		t.Fatal(v)
	}
	v = findText(t, in, "U")
	if !textStyle(v, "color").Known || !textStyle(v, "font-size").Known || textStyle(v, "background-color").Known {
		t.Fatal(v)
	}
}

func TestAdditionalBoundsAndUnsupportedWinners(t *testing.T) {
	for _, property := range []string{"opacity:0;opacity:sin(1)", "display:none;display:ruby", "display:none;display:run-in"} {
		in := inspectHTML(t, `<p style="`+property+`">T</p>`)
		if findText(t, in, "T").Label != "unknown" {
			t.Fatal(property, in)
		}
	}
	src := "<style>" + strings.Repeat("@media screen{", 200) + "p{display:none}" + strings.Repeat("}", 200) + "</style><p>T</p>"
	document, err := (processor{Limits: DefaultLimits()}).process([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("CSS nesting limit label = %q", got)
	}
}
