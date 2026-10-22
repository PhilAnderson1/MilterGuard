package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func initialPtr() *Style {
	style := initial()
	return &style
}

func mediaAt(width float64) *mediaEvaluation {
	return &mediaEvaluation{width: width}
}

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
	for property, propertyName := range names[:properties] {
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

func TestDocumentWalkerDoesNotRunAfterCPUStop(t *testing.T) {
	for _, visited := range []int{0, 1, 254, 255} {
		t.Run(strconv.Itoa(visited), func(t *testing.T) {
			budget := testCPUGuard(cpuGuard{shouldStop: func() { termination.Fail(termination.Failure{Code: termination.CPUExceeded}) }})
			walker := documentWalker{processor: processor{cpu: budget}, document: &parsedDocument{}, nodeCount: visited}
			frame := documentFrame{n: &html.Node{Type: html.TextNode, Data: "text"}, scope: scopeActive}
			expectTermination(t, termination.CPUExceeded, func() { budget.checkpoint(); walker.visit(&frame) })
			if walker.nodeCount != visited || walker.document.extractableTextCount != 0 {
				t.Fatal("processed text after termination")
			}
		})
	}
}

func TestASCIIKeywordHelpers(t *testing.T) {
	if got := normalizeCSSKeyword(" \tBLaCK\r\n"); got != "black" {
		t.Fatalf("normalized keyword = %q", got)
	}
	if got := normalizeCSSKeyword("blacK"); got != "blacK" {
		t.Fatalf("Unicode identifier changed to %q", got)
	}
	if !equalASCIIFold("VaR(", "var(") || !equalASCIIFoldBytes([]byte("IMPORTANT"), "important") {
		t.Fatal("ASCII case folding rejected an ASCII spelling")
	}
	if equalASCIIFold("K", "k") || equalASCIIFoldBytes([]byte("K"), "k") {
		t.Fatal("Unicode character was accepted as an ASCII keyword")
	}
}

func TestConcealmentReasonMaskMaterializesInStableOrder(t *testing.T) {
	mask := reasonDisplayNone | reasonVisibilityHidden | reasonVisibilityCollapse | reasonOpacity | reasonFontSize | reasonColour | reasonEmptyClip | reasonContentVisibility
	got := strings.Join(concealmentReasonStrings(mask), ",")
	want := "display-none,visibility-hidden,visibility-collapse,opacity,font-size,colour-distance,empty-clip,content-visibility-hidden"
	if got != want {
		t.Fatalf("concealment reasons = %q, want %q", got, want)
	}
}

func TestConcealmentReasonsAreRetainedInPublicResult(t *testing.T) {
	document, err := Analyze([]byte(`<p style="display:none">T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	text := findText(t, document, "T")
	if text.Label != "concealed" || strings.Join(concealmentReasonStrings(text.ConcealmentReasons), ",") != "display-none" {
		t.Fatalf("concealed text result = %+v", text)
	}
}

func TestAggregatedLabelUnionsViewingCaseEvidence(t *testing.T) {
	document, err := Analyze([]byte(`<style>p{display:none}@media(min-width:500px){p{display:block;opacity:0}}</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	text := findText(t, document, "T")
	if text.Label != "unknown" {
		t.Fatalf("aggregated label = %q", text.Label)
	}
	if text.ConcealmentReasons != 0 || text.EffectiveOpacity != 0 {
		t.Fatalf("aggregated viewing-case evidence = %+v", text)
	}

	document, err = Analyze([]byte(`<style>p{color:white;background:white}@media(min-width:500px){p{color:black;font-size:0}}</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	text = findText(t, document, "T")
	if text.Label != "concealed" || strings.Join(concealmentReasonStrings(text.ConcealmentReasons), ",") != "font-size,colour-distance" || text.FontSize != "0px" {
		t.Fatalf("aggregated font-size evidence = %+v", text)
	}
}

func TestCascadeWinnerIsCompact(t *testing.T) {
	winnerSize := unsafe.Sizeof(candidate{})
	if winnerSize > 64 || winnerSize >= unsafe.Sizeof(declaration{}) {
		t.Fatalf("cascade winner is %d bytes; declaration is %d bytes", winnerSize, unsafe.Sizeof(declaration{}))
	}
}

func TestCSSParserSamplesCooperativeStop(t *testing.T) {
	calls := 0
	s := sheet{
		limits: DefaultLimits(),
		shouldStop: func() {
			calls++
			{
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		},
	}
	expectTermination(t, termination.CPUExceeded, func() { s.parseStylesheetCSS(`/*` + strings.Repeat(`x`, 8<<10) + `*/p{color:red}`) })
	if calls == 0 {
		t.Fatal("stop callback was not sampled")
	}
}

func TestParseDocumentPublishesCSSUsageOnTermination(t *testing.T) {
	cssText := strings.Repeat("p,", 64) + "p{display:none}"
	input := []byte("<style>" + cssText + "</style><p>text</p>")
	for stopAfter := 1; stopAfter <= 256; stopAfter++ {
		calls := 0
		stop := func() {
			calls++
			if calls == stopAfter {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}
		}
		memory := resourceguard.NewMemory(DefaultLimits().MemoryBytes)
		var usage AnalysisUsage
		p := processor{
			Limits:     DefaultLimits(),
			shouldStop: stop,
			memory:     memory,
			usage:      &usage,
			cpu:        testCPUGuard(cpuGuard{shouldStop: stop, memory: memory}),
		}
		var failure termination.Failure
		func() {
			defer termination.Recover(&failure)
			_, _ = p.parseDocument(input)
		}()
		if failure.Code == termination.CPUExceeded && usage.CSSBytes == len(cssText) {
			return
		}
	}
	t.Fatal("no parse-phase termination published admitted CSS usage")
}

func TestCSSByteLimitAppliesAcrossParserInputs(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSBytes = len(`p{display:none}`) + len(`div{display:none}`)
	s := sheet{limits: limits}
	s.parseStylesheetCSS(`p{display:none}`)
	s.parseStylesheetCSS(`div{display:none}`)
	if s.cascadeIncomplete {
		t.Fatal("CSS at the cumulative limit invalidated the cascade")
	}
	s.parseStylesheetCSS(`i{display:none}`)
	if !s.cascadeIncomplete {
		t.Fatal("split CSS inputs bypassed the cumulative byte limit")
	}
	if len(s.rules) != 0 {
		t.Fatalf("invalidated cascade retained %d rules", len(s.rules))
	}
}

func TestSelectorBranchLimitAbandonsCascade(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(strings.Repeat("a,", maxSelectorBranches) + "a{display:none}")
	if !s.cascadeIncomplete {
		t.Fatal("selector branch limit did not abandon the cascade")
	}
	if len(s.rules) != 0 {
		t.Fatalf("abandoned cascade retained %d rules", len(s.rules))
	}
}

func TestDeclarationLimitAbandonsCascade(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.declarationCount = maxCSSDeclarations
	s.parseStylesheetCSS(`a{color:red}`)
	if !s.cascadeIncomplete {
		t.Fatal("declaration limit did not abandon the cascade")
	}
	if len(s.rules) != 0 {
		t.Fatalf("abandoned cascade retained %d rules", len(s.rules))
	}
}

func TestMatchCacheStopsGrowingAtEntryLimit(t *testing.T) {
	s := sheet{memory: resourceguard.NewMemory(1 << 20), index: selectorIndex{count: 1}}
	s.runtime.cacheMatches = true
	s.runtime.matchCacheEntries = maxMatchCacheEntries - 1
	plan := selectorPlan{sequence: 0}
	first := &html.Node{Type: html.ElementNode, Data: "p"}
	s.cacheMatch(&plan, first, true)
	if s.runtime.matchCacheEntries != maxMatchCacheEntries || s.runtime.matchCaches[0].View()[first] != 2 {
		t.Fatalf("last cache entry was not retained: runtime=%+v", s.runtime)
	}
	second := &html.Node{Type: html.ElementNode, Data: "p"}
	s.cacheMatch(&plan, second, true)
	if s.runtime.matchCacheEntries != maxMatchCacheEntries {
		t.Fatalf("cache entries=%d, want %d", s.runtime.matchCacheEntries, maxMatchCacheEntries)
	}
	if _, exists := s.runtime.matchCaches[0].View()[second]; exists {
		t.Fatal("cache grew beyond its entry limit")
	}
}

func TestCSSByteLimitAppliesBeforeStyleTextCollection(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSBytes = len(`p{display:none}`)
	source := `<style>p{display:none}</style><style>` + strings.Repeat("x", limits.CSSBytes+1) + `</style><p>T</p>`
	document, err := (processor{Limits: limits}).process([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("label = %q, want unknown", got)
	}
}

func TestOnlyGeneratedContentElementsAreRetained(t *testing.T) {
	document := inspectHTML(t, `<div><p>T</p><img src="x"><input type="button" value="Go"><span>U</span></div>`)
	if len(document.Elements) != 2 || document.Elements[0].Node.Data != "img" || document.Elements[1].Node.Data != "input" {
		t.Fatalf("retained elements = %+v", document.Elements)
	}
}

func TestInertImageLikeElementsAreNotRetained(t *testing.T) {
	source := `<body>` +
		`<img id="visible-image" src="visible"><input id="visible-input" type="button" value="Go">` +
		`<template><img id="template-image"><input id="template-input"></template>` +
		`<iframe><img id="iframe-image"><input id="iframe-input"></iframe>` +
		`<noembed><img id="noembed-image"><input id="noembed-input"></noembed>` +
		`<noframes><img id="noframes-image"><input id="noframes-input"></noframes>` +
		`<object><img id="object-image"><input id="object-input"></object>`
	document := inspectHTML(t, source)
	if len(document.Elements) != 4 {
		t.Fatalf("retained elements = %d, want two active and two uncertain fallback elements: %+v", len(document.Elements), document.Elements)
	}
	for _, fallback := range document.Elements[2:] {
		if fallback.Label != "unknown" {
			t.Fatalf("fallback element = %+v", fallback)
		}
	}
	if got := attr(document.Elements[0].Node, "id"); got != "visible-image" {
		t.Fatalf("first retained element = %q, want visible-image", got)
	}
	if got := attr(document.Elements[1].Node, "id"); got != "visible-input" {
		t.Fatalf("second retained element = %q, want visible-input", got)
	}
}

func TestDocumentCollectionCountsExtractableResults(t *testing.T) {
	source := []byte(`<body><p>A<style>p{color:red}</style>C<script>D</script></p><img><input><iframe>E</iframe></body>`)
	parsed, err := (processor{Limits: DefaultLimits()}).parseDocument(source)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.extractableTextCount != 2 || parsed.extractableElementCount != 2 {
		t.Fatalf("extractable counts = text %d, elements %d", parsed.extractableTextCount, parsed.extractableElementCount)
	}
	document, err := Analyze(source, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Text) != parsed.extractableTextCount || len(document.Elements) != parsed.extractableElementCount {
		t.Fatalf("result counts = text %d, elements %d", len(document.Text), len(document.Elements))
	}
}

func TestDocumentCollectionRecordsElementChildren(t *testing.T) {
	parsed, err := (processor{Limits: DefaultLimits()}).parseDocument([]byte(`<main>text<!-- filler --><section>child</section></main><p>text only</p>`))
	if err != nil {
		t.Fatal(err)
	}
	var main, section, paragraph *html.Node
	stack := []*html.Node{parsed.root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type == html.ElementNode {
			switch n.Data {
			case "main":
				main = n
			case "section":
				section = n
			case "p":
				paragraph = n
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			stack = append(stack, child)
		}
	}
	if main == nil || section == nil || paragraph == nil {
		t.Fatalf("missing parsed elements: main=%v section=%v paragraph=%v", main, section, paragraph)
	}
	if !parsed.elements.View()[main].hasElementChild {
		t.Fatal("main element child was not recorded")
	}
	if parsed.elements.View()[section].hasElementChild || parsed.elements.View()[paragraph].hasElementChild {
		t.Fatal("text-only element was recorded as having an element child")
	}
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
		`font-si\7a e:0`,
	} {
		in := inspectHTML(t, `<span style="`+style+`">T</span>`)
		if got := findText(t, in, "T").Label; got != "concealed" {
			t.Errorf("style %q label = %q, want concealed", style, got)
		}
	}
	in := inspectHTML(t, `<span style="opa\63 ity:0">T</span>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Errorf("escaped opacity label = %q, want unknown", got)
	}
}

func TestCSSIdentifierEscapesDoNotChangeTokenMeaning(t *testing.T) {
	cases := []struct {
		name, style, want string
	}{
		{
			"escaped bang is part of identifier",
			`display:block;display:none\!important`,
			"unknown",
		},
		{
			"escaped trailing space is part of identifier",
			`visibility:visible;visibility:hidden\ `,
			"unknown",
		},
		{
			"escaped digit remains an identifier",
			`opacity:1;opacity:\30`,
			"unknown",
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

func TestLegacyEscapedValuesRemainUncertain(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{
			"inline IE suffix",
			`<p style="display:none\9">T</p>`,
			"unknown",
		},
		{
			"stylesheet IE suffix",
			`<style>p{display:none\9}</style><p>T</p>`,
			"unknown",
		},
		{
			"later valid declaration wins",
			`<p style="display:none\9;display:block">T</p>`,
			"visible",
		},
		{
			"unrelated property remains irrelevant",
			`<p style="untracked:none\9">T</p>`,
			"visible",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, test.source)
			if got := findText(t, in, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
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
			"unknown",
		},
		{
			"media declaration is not unconditional",
			`@media screen{display:none}`,
			"unknown",
		},
		{
			"keyframes cannot reveal top-level hidden content",
			`display:none;@keyframes k{from{display:block}}`,
			"concealed",
		},
		{
			"unknown at-rule declaration is not unconditional",
			`@supports(display:grid){display:none}`,
			"unknown",
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
		if declarations := s.parseInlineCSS(`@keyframes k{p{display:none}}`).declarations; len(declarations) != 0 {
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
		{"opacity product", `<div style="opacity:10%"><p style="opacity:.1">T</p></div>`, "unknown"},
		{"opacity not inherited", `<div style="opacity:.2"><p>T</p></div>`, "visible"},
		{"opacity zero proof", `<div style="opacity:var(--o)"><p style="opacity:0">T</p></div>`, "unknown"},
		{"font parent", `<div style="font-size:20px"><p style="font-size:10%">T</p></div>`, "concealed"},
		{"font rem root", `<html style="font-size:20px"><body><p style="font-size:.1rem">T</p></body></html>`, "concealed"},
		{"font root rem", `<html style="font-size:.125rem"><body>T</body></html>`, "concealed"},
		{"font restored", `<div style="font-size:0"><p style="font-size:16px">T</p></div>`, "visible"},
		{"font inherit", `<div style="font-size:0"><p style="font-size:inherit">T</p></div>`, "concealed"},
		{"font initial", `<div style="font-size:0"><p style="font-size:initial">T</p></div>`, "visible"},
		{"font unset", `<div style="font-size:0"><p style="font-size:unset">T</p></div>`, "concealed"},
		{"display unset", `<div style="display:none"><p style="display:unset">T</p></div>`, "concealed"},
		{"hidden until found with box", `<div hidden="until-found" style="display:block">T</div>`, "unknown"},
		{"hidden until found author override", `<div hidden="until-found" style="content-visibility:visible">T</div>`, "visible"},
		{"opacity inherit", `<div style="opacity:.1"><p style="opacity:inherit">T</p></div>`, "unknown"},
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
	for _, value := range []string{"0", "+0", "-0", ".5", "+.5", "-.5", "1.25", "1e2", "1E-2", "+1e+2"} {
		if _, ok := number(value); !ok {
			t.Errorf("valid CSS number %q was rejected", value)
		}
	}
	for _, value := range []string{"", "+", ".", "1.", "0x0p0", "0x1_0p0", "1_0", "1e", "1e+", "NaN", "Inf"} {
		if _, ok := number(value); ok {
			t.Errorf("invalid CSS number %q was accepted", value)
		}
	}
	if _, ok := number("1e400"); ok {
		t.Fatal("general number parser accepted non-finite overflow")
	}
	for _, c := range []struct {
		v    string
		want float64
	}{{"0", 0}, {"2px", 2}, {"1.5pt", 2}, {".125pc", 2}, {".0529166666666667cm", 2}, {".529166666666667mm", 2}, {".0208333333333333in", 2}, {"2.11666666666667q", 2}, {".125em", 2}, {"12.5%", 2}, {".125rem", 2}} {
		v, st := resolve(fontSize, c.v, initialPtr(), initialPtr())
		if st != valueResolved || math.Abs(v.Number-c.want) > 1e-12 {
			t.Fatal(c, v, st)
		}
	}
	for _, c := range []struct {
		v    string
		want float64
	}{{"-2", 0}, {"200%", 1}, {".25", .25}} {
		v, st := resolve(opacity, c.v, initialPtr(), initialPtr())
		if st != valueResolved || v.Number != c.want {
			t.Fatal(c, v, st)
		}
	}
	for _, c := range []struct{ v, want string }{{"#123", "rgba(17,34,51,1)"}, {"#1234", "rgba(17,34,51,0.26666666666666666)"}, {"#11223344", "rgba(17,34,51,0.26666666666666666)"}, {"rgb(100%,0%,0%)", "rgba(255,0,0,1)"}, {"rgba(255,0,0,.5)", "rgba(255,0,0,0.5)"}, {"red", "rgba(255,0,0,1)"}, {"transparent", "rgba(0,0,0,0)"}} {
		v, st := parseColor(c.v)
		if st != valueResolved || v != c.want {
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

func TestSplitLengthUnits(t *testing.T) {
	for _, want := range lengthUnits {
		input := "1" + want.suffix
		numberText, got, found := splitLength(input)
		if !found || numberText != "1" || got != want {
			t.Errorf("splitLength(%q) = %q, %+v, %t; want 1, %+v, true", input, numberText, got, found, want)
		}
	}
	for _, test := range []struct {
		input, suffix string
	}{
		{"1rem", "rem"},
		{"1rlh", "rlh"},
		{"1rcap", "rcap"},
		{"1ric", "ric"},
		{"1rex", "rex"},
		{"1rch", "rch"},
		{"1dvw", "dvw"},
	} {
		_, unit, found := splitLength(test.input)
		if !found || unit.suffix != test.suffix {
			t.Errorf("splitLength(%q) suffix = %q, found=%t; want %q", test.input, unit.suffix, found, test.suffix)
		}
	}
	if numberText, _, found := splitLength("1"); found || numberText != "1" {
		t.Fatalf("splitLength(unitless) = %q, found=%t", numberText, found)
	}
}

func TestUnknownRelativeFontSizePreservesSpecifiedText(t *testing.T) {
	parent, root := initial(), initial()
	parent[fontSize] = Value{Text: "1vw"}
	root[fontSize] = Value{Text: "1vw"}
	for _, specified := range []string{"1em", "50%", "smaller", "larger"} {
		value, status := resolve(fontSize, specified, &parent, &root)
		if status != valueResolved || value.Known || value.Text != specified {
			t.Errorf("resolve(font-size, %q) = %+v, status %d", specified, value, status)
		}
	}
	value, status := resolve(fontSize, "1rem", initialPtr(), &root)
	if status != valueResolved || value.Known || value.Text != "1rem" {
		t.Fatalf("resolve(font-size, 1rem) = %+v, status %d", value, status)
	}
}

func TestGoOnlyNumbersDoNotConcealText(t *testing.T) {
	for _, property := range []string{
		`font-size:16px;font-size:0x0p0`,
		`font-size:16px;font-size:0x0p0px`,
		`font-size:16px;font-size:0_0px`,
		`font-size:16px;font-size:calc(0x0p0px)`,
		`opacity:1;opacity:0x0p0`,
	} {
		t.Run(property, func(t *testing.T) {
			document := inspectHTML(t, `<p style="`+property+`">T</p>`)
			if got := findText(t, document, "T").Label; got != "visible" {
				t.Fatalf("label = %q, want visible", got)
			}
		})
	}

	for _, property := range []string{`font-size:+0`} {
		t.Run(property, func(t *testing.T) {
			document := inspectHTML(t, `<p style="`+property+`">T</p>`)
			if got := findText(t, document, "T").Label; got != "concealed" {
				t.Fatalf("label = %q, want concealed", got)
			}
		})
	}
	document := inspectHTML(t, `<p style="opacity:+0">T</p>`)
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("opacity:+0 label = %q, want unknown", got)
	}
}
func TestConditionsAndRecovery(t *testing.T) {
	for _, c := range []struct{ css, want string }{{"@media all{p{display:none}}", "concealed"}, {"@media screen{p{display:none}}", "concealed"}, {"@media print{p{display:none}}", "visible"}, {"@media screen and (min-width:1px){p{display:none}}", "client-dependent"}, {"@supports(display:grid){p{display:none}}", "unknown"}, {"p:hover{display:none}", "visible"}, {"p::before{display:none}", "visible"}, {"p{broken;display:none}", "concealed"}, {"p{display:banana}p{display:none}", "concealed"}, {"@media print{@supports(display:grid){p{display:none}}}", "visible"}} {
		t.Run(c.css, func(t *testing.T) {
			in := inspectHTML(t, `<p>T</p><style>`+c.css+`</style>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("%s want %s %+v", got, c.want, in)
			}
		})
	}
}

func TestNestedDescriptorAtRuleDeclarationsDoNotLeakIntoOuterRule(t *testing.T) {
	for _, nested := range []string{
		`@page{display:block}`,
		`@font-face{display:block}`,
	} {
		t.Run(nested, func(t *testing.T) {
			in := inspectHTML(t, `<style>#a{display:none;`+nested+`}</style><p id="a">T</p>`)
			if got := findText(t, in, "T").Label; got != "concealed" {
				t.Fatalf("label = %q, want concealed", got)
			}
		})
	}
}

func TestDeclarationsAfterNestedAtRuleRetainEnclosingSelector(t *testing.T) {
	for _, nested := range []string{
		`@x{}`,
		`@supports(display:flex){}`,
		`@media screen{}`,
		`@media print{p{display:block}}`,
		`@media screen{@supports(display:flex){p{display:block}}}`,
		`@page{display:block}`,
		`@font-face{display:block}`,
		`@keyframes k{from{opacity:0}}`,
	} {
		for _, wrapper := range []string{"", "@media screen"} {
			t.Run(wrapper+"/"+nested, func(t *testing.T) {
				css := `#a{display:block;` + nested + `;--hidden:none;display:var(--hidden)}`
				if wrapper != "" {
					css = wrapper + "{" + css + "}"
				}
				in := inspectHTML(t, `<style>`+css+`</style><p id="a">T</p><p>U</p>`)
				want := "concealed"
				if strings.Contains(nested, `p{display:block}`) {
					want = "unknown"
				}
				if got := findText(t, in, "T").Label; got != want {
					t.Fatalf("enclosing rule label = %q, want %s", got, want)
				}
				if got := findText(t, in, "U").Label; got == "concealed" {
					t.Fatalf("outer declarations leaked to sibling: label = %q", got)
				}
			})
		}
	}
}

func TestUnsupportedCSSNestingDoesNotProduceConfidentVisibility(t *testing.T) {
	for _, css := range []string{
		`div{span{display:none}}`,
		`div{&{display:none}}`,
		`div{@media screen{display:none}}`,
		`div{&:is(*){display:none}}`,
		`div{& + p{display:none}}`,
		`div{@media screen{span{display:none}}}`,
	} {
		t.Run(css, func(t *testing.T) {
			in := inspectHTML(t, `<style>`+css+`</style><div>Parent<span>Inside</span></div><p>Sibling</p>`)
			if !in.UnresolvedStylesheet {
				t.Fatal("unsupported nesting was not reported")
			}
			for _, text := range []string{"Parent", "Inside", "Sibling"} {
				if got := findText(t, in, text).Label; got != "unknown" {
					t.Fatalf("%s label = %q, want unknown", text, got)
				}
			}
		})
	}
}

func TestNestingDetectionDoesNotFlagOrdinaryBraceValuesOrEmptyAtRules(t *testing.T) {
	for _, css := range []string{
		`div{--fallback:{display:none};display:block}`,
		`div{background:var(--missing,{red});display:block}`,
		`{ { #if template } }`,
		`div{@x{};display:none}`,
		`div{@page{display:block};display:none}`,
		`@media screen{div{display:none}}`,
	} {
		t.Run(css, func(t *testing.T) {
			in := inspectHTML(t, `<style>`+css+`</style><div>T</div>`)
			if in.UnresolvedStylesheet {
				t.Fatal("ordinary CSS was reported as unsupported nesting")
			}
		})
	}
}

func TestCSSParserPreservesAuthorEscapesDuringDelimiterRecovery(t *testing.T) {
	for _, test := range []struct {
		name, css  string
		inline     bool
		wantColour string
	}{
		{
			name: "comment separation",
			css:  `p{/* separator */--literal:"\)";--url:url(x\))}`,
		},
		{
			name:       "delimiter recovery",
			css:        `p{--literal:"\)";--url:url(x\));--mixed:var(--missing,"\)",[unused)]);--mixed-after:var(--missing,[unused)]),"\)";color:var(--missing,[unused)])}`,
			wantColour: `var(--missing,[unused)])`,
		},
		{
			name:       "inline delimiter recovery",
			css:        `--literal:"\)";--url:url(x\));--mixed:var(--missing,"\)",[unused)]);--mixed-after:var(--missing,[unused)]),"\)";color:var(--missing,[unused)])`,
			inline:     true,
			wantColour: `var(--missing,[unused)])`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := sheet{limits: DefaultLimits()}
			var declarations []declaration
			if test.inline {
				declarations = s.parseInlineCSS(test.css).declarations
			} else {
				s.parseStylesheetCSS(test.css)
				if len(s.rules) != 1 {
					t.Fatalf("rules = %d, want 1", len(s.rules))
				}
				declarations = s.rules[0].decls
			}
			values := make(map[string]string)
			for _, declaration := range declarations {
				if declaration.custom != "" {
					values[declaration.custom] = declaration.value
				} else if declaration.prop == color {
					values["color"] = declaration.value
				}
			}
			if got := values["--literal"]; got != `"\)"` {
				t.Fatalf("escaped string = %q, want author value", got)
			}
			if got := values["--url"]; got != `url(x\))` {
				t.Fatalf("escaped URL = %q, want author value", got)
			}
			if test.wantColour != "" && values["--mixed"] != `var(--missing,"\)",[unused)])` {
				t.Fatalf("mixed value = %q, want author escape and recovered delimiter", values["--mixed"])
			}
			if test.wantColour != "" && values["--mixed-after"] != `var(--missing,[unused)]),"\)"` {
				t.Fatalf("trailing author escape = %q, want restored delimiter and author escape", values["--mixed-after"])
			}
			if test.wantColour != "" && values["color"] != test.wantColour {
				t.Fatalf("recovered value = %q, want %q", values["color"], test.wantColour)
			}
		})
	}
}

func TestInlineAtRuleRecoveryDoesNotSilentlyDropFollowingDeclarations(t *testing.T) {
	for _, c := range []struct{ style, want string }{
		{`@media screen{color:red};display:none`, "unknown"},
		{`@supports(display:flex){color:red};display:none`, "unknown"},
		{`@x{};display:none`, "concealed"},
		{`@page{color:red};display:none`, "concealed"},
		{`@font-face{color:red};display:none`, "concealed"},
		{`@keyframes k{from{opacity:0}};display:none`, "concealed"},
	} {
		t.Run(c.style, func(t *testing.T) {
			in := inspectHTML(t, `<div style="`+c.style+`"><span>T</span></div><p>U</p>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
			if got := findText(t, in, "U").Label; got != "visible" {
				t.Fatalf("inline uncertainty affected sibling: label = %q", got)
			}
		})
	}
}

func TestViewingCaseLabelMergeRejectsShapeMismatch(t *testing.T) {
	labels := []visibilityLabel{labelBit("visible")}
	if !mergeViewingCaseLabel(labels, 0, labelBit("unknown")) {
		t.Fatal("valid viewing-case label was rejected")
	}
	if labels[0] != labelBit("visible")|labelBit("unknown") {
		t.Fatalf("merged label bits = %b", labels[0])
	}
	if mergeViewingCaseLabel(labels, -1, labelBit("unknown")) || mergeViewingCaseLabel(labels, len(labels), labelBit("unknown")) {
		t.Fatal("out-of-range viewing-case label was accepted")
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

func TestLinkedAndImportedStylesheets(t *testing.T) {
	cases := []struct {
		name       string
		source     string
		want       string
		unresolved bool
	}{
		{"percent-encoded data link", `<link rel="stylesheet" href="data:text/css,p%7Bdisplay%3Anone%7D"><p>T</p>`, "unknown", false},
		{"base64 data link", `<link rel="stylesheet" href="data:text/css;base64,cHtkaXNwbGF5Om5vbmV9"><p>T</p>`, "unknown", false},
		{"data import", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D";</style><p>T</p>`, "unknown", false},
		{"data import with screen media", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D" screen;</style><p>T</p>`, "unknown", false},
		{"print-only data import", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D" print;</style><p>T</p>`, "visible", false},
		{"remote link", `<link rel="stylesheet" href="https://example.test/email.css"><p>T</p>`, "visible", true},
		{"cid import", `<style>@import url(cid:email-css);</style><p>T</p>`, "visible", true},
		{"malformed data link", `<link rel="stylesheet" href="data:text/css,%zz"><p>T</p>`, "visible", true},
		{"unsupported import modifier", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D" layer(theme);</style><p>T</p>`, "visible", true},
		{"print-only remote link", `<link rel="stylesheet" media="print" href="https://example.test/print.css"><p>T</p>`, "visible", false},
		{"alternate stylesheet", `<link rel="alternate stylesheet" href="https://example.test/alternate.css"><p>T</p>`, "visible", false},
		{"non-CSS type", `<link rel="stylesheet" type="text/plain" href="https://example.test/not-css"><p>T</p>`, "visible", false},
		{"late import is invalid", `<style>p{display:block}@import "https://example.test/late.css";</style><p>T</p>`, "visible", false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
			if document.UnresolvedStylesheet != test.unresolved {
				t.Fatalf("unresolved stylesheet = %t, want %t", document.UnresolvedStylesheet, test.unresolved)
			}
		})
	}
}

func TestStyleElementRequiresCSSMIMEType(t *testing.T) {
	for _, test := range []struct {
		name, typ, want string
	}{
		{"absent", "", "concealed"},
		{"empty", ` type=""`, "concealed"},
		{"CSS type", ` type="text/css"`, "concealed"},
		{"mixed-case CSS type", ` type="Text/CSS"`, "concealed"},
		{"CSS type parameters", ` type="text/css; charset=utf-8"`, "concealed"},
		{"non-CSS type", ` type="text/plain"`, "visible"},
		{"malformed type", ` type="text/css; charset"`, "visible"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style`+test.typ+`>p{display:none}</style><p>T</p>`)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestOversizedStylesheetMIMETypeAvoidsParameterParsing(t *testing.T) {
	padding := strings.Repeat("x", maxCSSMediaTypeBytes)
	for _, test := range []struct {
		name, typ, want string
	}{
		{"valid CSS parameters", `text/css;p=` + padding, "concealed"},
		{"malformed CSS parameters remain conservative", `text/css;` + padding, "concealed"},
		{"non-CSS type", `text/plain;p=` + padding, "visible"},
		{"whitespace-only type", strings.Repeat(" ", maxCSSMediaTypeBytes+1), "concealed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style type="`+test.typ+`">p{display:none}</style><p>T</p>`)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}

	typ := `text/css;p=` + padding
	document := inspectHTML(t, `<link rel="stylesheet" type="`+typ+`" href="data:text/css,p%7Bdisplay%3Anone%7D"><p>T</p>`)
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("linked stylesheet label = %q, want unknown", got)
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
	in := inspectHTML(t, `<style>p::before{display:block}</style><p>T</p><div>U</div>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("label = %q", got)
	}
	if got := findText(t, in, "U").Label; got != "visible" {
		t.Fatalf("unrelated label = %q", got)
	}

	in = inspectHTML(t, `<style>div:has(.x) .offer{visibility:hidden}.other:has(.x){opacity:0}</style><div class="offer">offer</div><div class="other">other</div><div>ordinary</div>`)
	for text, want := range map[string]string{"offer": "visible", "other": "unknown", "ordinary": "visible"} {
		if got := findText(t, in, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
	}

	in = inspectHTML(t, `<style>p[data-value#=(a+) ]{display:none}</style><p data-value="aaaa">regex target</p><div>unrelated</div>`)
	if got := findText(t, in, "regex target").Label; got != "visible" {
		t.Fatalf("regex target label = %q, want visible", got)
	}
	if got := findText(t, in, "unrelated").Label; got != "visible" {
		t.Fatalf("regex-unrelated label = %q, want visible", got)
	}
}

func TestSuppressedGeneratedPseudoElementsDoNotAffectSourceText(t *testing.T) {
	for _, test := range []struct {
		name, css, body, text, want string
	}{
		{"before", `span::before{display:none}`, `<span>T</span>`, "T", "visible"},
		{"legacy before", `span:before{display:none}`, `<span>T</span>`, "T", "visible"},
		{"after important", `span::after{display:none!important}`, `<span>T</span>`, "T", "visible"},
		{"discarded content", `span::before{content:"x";display:none}`, `<span>T</span>`, "T", "visible"},
		{"may paint", `span::before{display:block}`, `<span>T</span>`, "T", "unknown"},
		{"other retained effect", `span::before{display:none;color:white}`, `<span>T</span>`, "T", "unknown"},
		{"first line styles source text", `span::first-line{color:white}`, `<span>T</span>`, "T", "unknown"},
		{"escaped class colon", `.foo\:before{display:none}`, `<span class="foo:before">T</span>`, "T", "concealed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.css+`</style>`+test.body)
			if got := findText(t, document, test.text).Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}

	document := inspectHTML(t, `<style>span::before,p.hide{display:none}</style><span>S</span><p class="hide">P</p>`)
	if got := findText(t, document, "S").Label; got != "visible" {
		t.Fatalf("generated branch label = %q, want visible", got)
	}
	if got := findText(t, document, "P").Label; got != "concealed" {
		t.Fatalf("ordinary branch label = %q, want concealed", got)
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

func TestColourAffectingPaintLayersInvalidateMemo(t *testing.T) {
	neutral := paintLayer{
		backgroundKnown: true, imageKnown: true,
		opacity: 1, opacityKnown: true, compositionKnown: true, enhancementKnown: true,
	}
	tests := []struct {
		name  string
		layer paintLayer
	}{
		{name: "background", layer: func() paintLayer { p := neutral; p.background.A = 1; return p }()},
		{name: "unknown background", layer: func() paintLayer { p := neutral; p.backgroundKnown = false; return p }()},
		{name: "unknown image", layer: func() paintLayer { p := neutral; p.imageKnown = false; return p }()},
		{name: "opacity", layer: func() paintLayer { p := neutral; p.opacity = .5; return p }()},
		{name: "unknown opacity", layer: func() paintLayer { p := neutral; p.opacityKnown = false; return p }()},
		{name: "composition", layer: func() paintLayer { p := neutral; p.compositionKnown = false; return p }()},
		{name: "enhancement", layer: func() paintLayer { p := neutral; p.enhancementKnown = false; return p }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := viewingCaseRunner{layers: []paintLayer{neutral}, layerGeneration: 10}
			node := &html.Node{Type: html.ElementNode, Data: "span"}
			if changed := runner.enterPaintLayer(node, test.layer); !changed || runner.layerGeneration != 11 {
				t.Fatalf("entry did not invalidate context: changed=%t generation=%d", changed, runner.layerGeneration)
			}
			runner.leavePaintLayer(true)
			if runner.layerGeneration != 12 {
				t.Fatalf("exit generation=%d, want 12", runner.layerGeneration)
			}
		})
	}
}

func TestBodyPaintLayerAlwaysInvalidatesColourMemo(t *testing.T) {
	neutral := paintLayer{
		backgroundKnown: true, imageKnown: true,
		opacity: 1, opacityKnown: true, compositionKnown: true, enhancementKnown: true,
	}
	htmlNode := &html.Node{Type: html.ElementNode, Data: "html"}
	bodyNode := &html.Node{Type: html.ElementNode, Data: "body", Parent: htmlNode}
	runner := viewingCaseRunner{layers: []paintLayer{neutral}, layerGeneration: 20}
	if changed := runner.enterPaintLayer(bodyNode, neutral); !changed || runner.layerGeneration != 21 {
		t.Fatalf("body entry did not invalidate context: changed=%t generation=%d", changed, runner.layerGeneration)
	}
	runner.leavePaintLayer(true)
	if runner.layerGeneration != 22 {
		t.Fatalf("body exit generation=%d, want 22", runner.layerGeneration)
	}
}

func TestDeclarationsPrepareContextFreeValuesOnce(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	static := s.declarations("color", "rgb(1 2 3)")
	if len(static) != 1 || static[0].prepared == nil || static[0].prepared.status != valueResolved || !static[0].prepared.value.Known {
		t.Fatalf("static declaration was not prepared: %+v", static)
	}
	contextual := s.declarations("font-size", "50%")
	if len(contextual) != 1 || contextual[0].prepared != nil {
		t.Fatalf("context-dependent declaration was prepared as static: %+v", contextual)
	}
}

func TestPreparedDeclarationReleasesUnneededTokens(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	static := s.declarations("display", "none")
	if len(static) != 1 || static[0].prepared == nil {
		t.Fatalf("static declaration was not prepared: %+v", static)
	}
	if static[0].tokensReady || static[0].valueTokens != nil {
		t.Fatalf("static declaration retained tokens: %+v", static[0])
	}

	contextual := s.declarations("font-size", "calc(1em + 2px)")
	if len(contextual) != 1 || contextual[0].prepared != nil || !contextual[0].tokensReady || len(contextual[0].valueTokens) == 0 {
		t.Fatalf("contextual declaration did not retain tokens: %+v", contextual)
	}
	custom := s.declarations("--size", "calc(1em + 2px)")
	if len(custom) != 1 || !custom[0].tokensReady || len(custom[0].valueTokens) == 0 {
		t.Fatalf("custom declaration did not retain tokens: %+v", custom)
	}
}

func TestRelevantDeclarationPropertyClassification(t *testing.T) {
	relevant := []string{
		"display", "DISPLAY", `d\69splay`, "margin", "background", "font", "all",
		"animation", "animation-name", "-webkit-animation", "-webkit-animation-name",
		"-webkit-mask", "-webkit-transform", "-ms-transform", "-webkit-text-stroke-width", "--custom",
	}
	for _, property := range relevant {
		if !relevantDeclarationProperty(property) {
			t.Errorf("relevantDeclarationProperty(%q) = false", property)
		}
	}
	for _, property := range []string{"border", "padding", "-vendor-display", ""} {
		if relevantDeclarationProperty(property) {
			t.Errorf("relevantDeclarationProperty(%q) = true", property)
		}
	}
}

func TestAnalyzeReportsUnsupportedColourFunctions(t *testing.T) {
	tests := []struct {
		name  string
		style string
		want  int
	}{
		{name: "static fast path", style: `color:lab(50% 0 0)`, want: 1},
		{name: "retained variable path", style: `--ink:lab(50% 0 0);color:var(--ink)`, want: 1},
		{name: "escaped retained path", style: `color:l\61 b(50% 0 0)`, want: 1},
		{name: "shorthand counted once", style: `background:color-mix(in srgb,red,blue)`, want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Analyze([]byte(`<p style="`+test.style+`">T</p>`), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if got := document.Usage.UnsupportedColourFunctions; got != test.want {
				t.Fatalf("unsupported colour functions = %d, want %d", got, test.want)
			}
			if label := findText(t, document, "T").Label; label != "unknown" {
				t.Fatalf("label = %q, want unknown", label)
			}
		})
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

func TestStylesInExcludedHeadContainersDoNotEnterCascade(t *testing.T) {
	for _, container := range []string{"template", "iframe", "noembed", "noframes"} {
		t.Run(container, func(t *testing.T) {
			source := `<head><` + container + `><style>#message{display:none}</style></` + container + `></head><body><p id="message">Visible text</p></body>`
			document := inspectHTML(t, source)
			if got := findText(t, document, "Visible text").Label; got != "visible" {
				t.Fatalf("label = %q, want visible", got)
			}
		})
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

func BenchmarkDeepMediaRuleStorage(b *testing.B) {
	var source strings.Builder
	for range 127 {
		source.WriteString(`@media all{`)
	}
	for range 2_048 {
		source.WriteString(`p{display:none}`)
	}
	for range 127 {
		source.WriteByte('}')
	}
	input := []byte(`<style>` + source.String() + `</style><p>T</p>`)
	limits := DefaultLimits()
	b.ReportAllocs()
	b.SetBytes(int64(len(input)))
	b.ResetTimer()
	for range b.N {
		if document, err := Analyze(input, limits); err != nil {
			b.Fatal(err)
		} else if document.Usage.CSSLimitExceeded {
			b.Fatal("cascade abandoned")
		}
	}
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
	if got := findText(t, document, "T").Label; got != "concealed" {
		t.Fatalf("deep CSS nesting label = %q", got)
	}
}

func TestAnalyzeEnforcesSharedMemoryBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MemoryBytes = 512
	input := []byte(`<div ` + strings.Repeat(`data-x="value" `, 100) + `>text</div>`)
	_, usage, err, failure := captureAnalysis(input, limits)
	if err != nil || failure.Code != termination.MemoryExceeded || !usage.MemoryLimitExceeded || usage.MemoryBytes > limits.MemoryBytes {
		t.Fatalf("failure=%+v usage=%+v err=%v", failure, usage, err)
	}
}

func TestAnalyzeReportsFinalMemoryUsage(t *testing.T) {
	limits := DefaultLimits()
	memory := resourceguard.NewMemory(limits.MemoryBytes)
	document, err := (processor{Limits: limits, memory: memory}).process([]byte(
		`<style>p.notice{display:none}</style><main><p class="notice">concealed</p><p>visible</p></main>`,
	))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := document.Usage.MemoryBytes, memory.Used(); got != want {
		t.Fatalf("reported memory usage=%d, final memory counter=%d", got, want)
	}
}

func TestAnalyzeValidatesCurrentLimits(t *testing.T) {
	for _, change := range []func(*Limits){func(l *Limits) { l.InputBytes = 0 }, func(l *Limits) { l.CSSBytes = 0 }, func(l *Limits) { l.MemoryBytes = 0 }} {
		limits := DefaultLimits()
		change(&limits)
		if _, err := Analyze(nil, limits); err == nil {
			t.Fatal("invalid limit accepted")
		}
	}
}
