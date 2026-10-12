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

func preflight(b []byte, limits Limits) error {
	_, err := measurePreflight(b, limits)
	return err
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
	if text.Label != "concealed" || strings.Join(text.ConcealmentReasons, ",") != "display-none" {
		t.Fatalf("concealed text result = %+v", text)
	}
}

func TestAggregatedLabelRetainsFirstViewingCaseEvidence(t *testing.T) {
	document, err := Analyze([]byte(`<style>p{display:none}@media(min-width:500px){p{display:block;opacity:0}}</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	text := findText(t, document, "T")
	if text.Label != "concealed" {
		t.Fatalf("aggregated label = %q", text.Label)
	}
	if strings.Join(text.ConcealmentReasons, ",") != "display-none" || text.EffectiveOpacity != 1 {
		t.Fatalf("first viewing-case evidence = %+v", text)
	}
}

func TestCascadeWinnerIsCompact(t *testing.T) {
	winnerSize := unsafe.Sizeof(candidate{})
	if winnerSize > 64 || winnerSize >= unsafe.Sizeof(declaration{}) {
		t.Fatalf("cascade winner is %d bytes; declaration is %d bytes", winnerSize, unsafe.Sizeof(declaration{}))
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
		{"attributes", func(l *Limits) { l.Attributes = 0 }},
		{"depth", func(l *Limits) { l.Depth = -1 }},
		{"rules", func(l *Limits) { l.Rules = -1 }},
		{"selectors", func(l *Limits) { l.Selectors = -1 }},
		{"selector bytes", func(l *Limits) { l.SelectorBytes = 0 }},
		{"CSS bytes", func(l *Limits) { l.CSSBytes = 0 }},
		{"CSS construct bytes", func(l *Limits) { l.CSSConstructBytes = 0 }},
		{"CSS construct tokens", func(l *Limits) { l.CSSConstructTokens = 0 }},
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

func TestCSSInputIsBoundedBeforeParsing(t *testing.T) {
	limits := DefaultLimits()
	oversized := `p{color:` + strings.Repeat(`0 0 0 1px,`, limits.CSSConstructBytes) + `red}`
	s := sheet{limits: limits}
	if declarations := s.parseCSS(oversized, false); declarations != nil {
		t.Fatalf("oversized stylesheet returned declarations: %+v", declarations)
	}
	if !s.cascadeIncomplete {
		t.Fatal("oversized stylesheet did not invalidate the cascade")
	}
	if s.cssBytes != 0 {
		t.Fatalf("oversized stylesheet was admitted: CSS bytes = %d", s.cssBytes)
	}
}

func TestLargeStylesheetOfBoundedConstructsIsAccepted(t *testing.T) {
	limits := DefaultLimits()
	source := strings.Repeat(`p{color:red}`, 2_000)
	if len(source) <= limits.CSSConstructBytes || len(source) >= limits.CSSBytes {
		t.Fatalf("test stylesheet size = %d", len(source))
	}
	s := sheet{limits: limits}
	s.parseCSS(source, false)
	if s.cascadeIncomplete {
		t.Fatal("bounded declarations were rejected based on total stylesheet size")
	}
	if len(s.rules) != 2_000 {
		t.Fatalf("parsed rules = %d, want 2000", len(s.rules))
	}
}

func TestNestedCustomPropertyCannotBypassCSSConstructLimit(t *testing.T) {
	for name, value := range map[string]string{
		"nested block": `{` + strings.Repeat(`x`, 40) + `}`,
		"comment":      `/*` + strings.Repeat(`x`, 40) + `*/`,
	} {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.CSSConstructBytes = 32
			s := sheet{limits: limits}
			s.parseCSS(`p{--payload:`+value+`;display:none}`, false)
			if !s.cascadeIncomplete {
				t.Fatal("custom-property value bypassed construct limit")
			}
		})
	}
}

func TestCSSConstructTokenLimitPrecedesFullParser(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSConstructBytes = 1_000
	limits.CSSConstructTokens = 8
	s := sheet{limits: limits}
	s.parseCSS(`p{color:0 0 0 0 0 0 0 0 0}`, false)
	if !s.cascadeIncomplete {
		t.Fatal("token-heavy declaration bypassed construct limit")
	}
}

func TestCSSByteLimitAppliesAcrossParserInputs(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSBytes = len(`p{display:none}`) + len(`div{display:none}`)
	s := sheet{limits: limits}
	s.parseCSS(`p{display:none}`, false)
	s.parseCSS(`div{display:none}`, false)
	if s.cascadeIncomplete {
		t.Fatal("CSS at the cumulative limit invalidated the cascade")
	}
	s.parseCSS(`i{display:none}`, false)
	if !s.cascadeIncomplete {
		t.Fatal("split CSS inputs bypassed the cumulative byte limit")
	}
	if len(s.rules) != 0 {
		t.Fatalf("invalidated cascade retained %d rules", len(s.rules))
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

func TestOversizedCSSMakesVisibilityUnknown(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSConstructBytes = 32
	source := `<style>p{display:` + strings.Repeat(`x`, limits.CSSConstructBytes+1) + `}</style><p>T</p>`
	document, err := (processor{Limits: limits}).process([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	text := findText(t, document, "T")
	if text.Label != "unknown" {
		t.Fatalf("label = %q, want unknown after CSS preflight limit", text.Label)
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

func TestDocumentCollectionPreparesElementMetadataOnce(t *testing.T) {
	source := []byte(`<p class="` + strings.Repeat("x", 32) + `" style="opacity:.5" hidden>T</p>`)
	parsed, err := (processor{Limits: DefaultLimits()}).parseDocument(source)
	if err != nil {
		t.Fatal(err)
	}
	for node, prepared := range parsed.elements {
		if node.Data != "p" {
			continue
		}
		if len(prepared.inline) != 1 || len(prepared.legacy) != 1 || prepared.selector.empty() {
			t.Fatalf("prepared element metadata = %+v", prepared)
		}
		return
	}
	t.Fatal("missing prepared paragraph metadata")
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
	t.Run("lexical attributes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Attributes = 2
		err := preflight([]byte(`<p a="1" b="2" c="3">x</p>`), limits)
		if err == nil || !strings.Contains(err.Error(), "lexical attributes") {
			t.Fatalf("attribute limit error = %v", err)
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

func TestPreflightEndTagIndexTracksEveryStackPop(t *testing.T) {
	limits := DefaultLimits()
	limits.Depth = 4

	// The first div end tag pops both span and div. Neither later closing tag
	// may be treated as open, and the SVG breakout must remove both foreign
	// frames from the same index before ordinary HTML parsing resumes.
	src := []byte(`<div><span></div></span></div><svg><g><p></g></svg></g>`)
	usage, err := measurePreflight(src, limits)
	if err != nil {
		t.Fatal(err)
	}
	if usage.depth != 2 {
		t.Fatalf("lexical depth = %d, want 2", usage.depth)
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

func TestAllShorthandIsStoredOnceAndChargedForEveryProperty(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	inline := s.declarations("all", "revert")
	if len(inline) != 1 || inline[0].prop != allShorthandProperty {
		t.Fatalf("all shorthand declarations = %+v", inline)
	}

	wantWork := elementTraversalWork + int64(declarationProperties)*declarationApplyWeight
	matches := matchBudget{limit: wantWork}
	expressions := expressionBudget{remaining: s.limits.ExpressionWork}
	result := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, inline, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if matches.exhausted || matches.used != wantWork {
		t.Fatalf("all shorthand work = %+v, want %d", matches, wantWork)
	}
	if result.style[display].Known {
		t.Fatalf("all shorthand display = %+v, want unresolved", result.style[display])
	}

	matches = matchBudget{limit: wantWork - 1}
	expressions = expressionBudget{remaining: s.limits.ExpressionWork}
	s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, inline, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if !matches.exhausted {
		t.Fatal("all shorthand partially applied after its complete work reservation failed")
	}
}

func TestRepeatedAllShorthandsDoNotAmplifyStoredDeclarations(t *testing.T) {
	const declarations = 1_000
	s := sheet{limits: DefaultLimits()}
	s.parseCSS("p{"+strings.Repeat("all:x;", declarations)+"}", false)
	if s.cascadeIncomplete || s.workIncomplete {
		t.Fatalf("ordinary-size stylesheet was abandoned: %+v", s)
	}
	if len(s.rules) != 1 || len(s.rules[0].decls) != declarations {
		t.Fatalf("stored declarations = %d, want %d", len(s.rules[0].decls), declarations)
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
	}{{"0", 0}, {"2px", 2}, {"1.5pt", 2}, {".125em", 2}, {"12.5%", 2}, {".125rem", 2}} {
		v, st := resolve(fontSize, c.v, initialPtr(), initialPtr())
		if st != 1 || v.Number != c.want {
			t.Fatal(c, v, st)
		}
	}
	for _, c := range []struct {
		v    string
		want float64
	}{{"-2", 0}, {"200%", 1}, {".25", .25}} {
		v, st := resolve(opacity, c.v, initialPtr(), initialPtr())
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

func TestUnknownRelativeFontSizePreservesSpecifiedText(t *testing.T) {
	parent, root := initial(), initial()
	parent[fontSize] = Value{Text: "1vw"}
	root[fontSize] = Value{Text: "1vw"}
	for _, specified := range []string{"1em", "50%", "smaller", "larger"} {
		value, status := resolve(fontSize, specified, &parent, &root)
		if status != 1 || value.Known || value.Text != specified {
			t.Errorf("resolve(font-size, %q) = %+v, status %d", specified, value, status)
		}
	}
	value, status := resolve(fontSize, "1rem", initialPtr(), &root)
	if status != 1 || value.Known || value.Text != "1rem" {
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

	for _, property := range []string{`font-size:+0`, `opacity:+0`} {
		t.Run(property, func(t *testing.T) {
			document := inspectHTML(t, `<p style="`+property+`">T</p>`)
			if got := findText(t, document, "T").Label; got != "concealed" {
				t.Fatalf("label = %q, want concealed", got)
			}
		})
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
		{"percent-encoded data link", `<link rel="stylesheet" href="data:text/css,p%7Bdisplay%3Anone%7D"><p>T</p>`, "concealed", false},
		{"base64 data link", `<link rel="stylesheet" href="data:text/css;base64,cHtkaXNwbGF5Om5vbmV9"><p>T</p>`, "concealed", false},
		{"data import", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D";</style><p>T</p>`, "concealed", false},
		{"data import with screen media", `<style>@import "data:text/css,p%7Bdisplay%3Anone%7D" screen;</style><p>T</p>`, "concealed", false},
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

func TestElementTraversalConsumesSharedWorkBudget(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	matches := matchBudget{limit: elementTraversalWork}
	expressions := expressionBudget{remaining: s.limits.ExpressionWork}
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	first := s.elementStyle(node, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if !first.style[display].Known || matches.exhausted {
		t.Fatalf("first traversal = %+v, budget=%+v", first.style[display], matches)
	}
	second := s.elementStyle(node, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if second.style[display].Known || !matches.exhausted {
		t.Fatalf("second traversal = %+v, budget=%+v", second.style[display], matches)
	}
}

func TestColourLayerTraversalConsumesSharedWorkBudget(t *testing.T) {
	layers := make([]paintLayer, 128)
	for i := range layers {
		layers[i] = layer(initialPtr())
	}
	cost := int64(1 + len(layers))
	enough := matchBudget{limit: cost}
	if result := evaluateColour(initial()[color], layers, &enough); !result.known || enough.used != cost || enough.exhausted {
		t.Fatalf("bounded colour result = %+v, budget=%+v", result, enough)
	}
	short := matchBudget{limit: cost - 1}
	if result := evaluateColour(initial()[color], layers, &short); result.known || !short.exhausted {
		t.Fatalf("over-budget colour result = %+v, budget=%+v", result, short)
	}
}

func TestSelectorWorkBudgetStopsBeforePartialCascadeIsTrusted(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 5
	s := sheet{limits: limits}
	s.parseCSS(`p{display:none}p{display:block}`, false)
	s.buildSelectorIndex(1, 1)
	matches := matchBudget{limit: limits.MatchWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	result := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if !matches.exhausted || matches.used > matches.limit {
		t.Fatalf("match budget was not enforced: %+v", matches)
	}
	if result.style[display].Known {
		t.Fatalf("partial cascade was trusted: %+v", result.style[display])
	}
}

func TestDeclarationApplicationWorkStopsBeforePartialCascadeIsTrusted(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`*{color:red;color:green;color:blue}`, false)
	s.buildSelectorIndex(1, 1)
	plan := s.rules[0].plans[0]
	declarations := int64(len(s.rules[0].decls))
	if declarations < 2 {
		t.Fatalf("test rule has only %d declarations", declarations)
	}
	// Leave enough work to match the selector but one unit less than is
	// required to reserve the complete declaration list.
	matches := matchBudget{limit: s.planningWork + 1 + plan.cost + declarations*declarationApplyWeight - 1, used: s.planningWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	result := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if !matches.exhausted {
		t.Fatalf("declaration application did not exhaust budget: %+v", matches)
	}
	if result.style[color].Known {
		t.Fatalf("partially applied cascade was trusted: %+v", result.style[color])
	}
}

func TestSelectorIndexSkipsIrrelevantInactiveRules(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`@media print{p{display:none}}@media print{div{display:none}}`, false)
	s.buildSelectorIndex(1, 1)
	work := elementTraversalWork + 1 // Traversal and the indexed p candidate.
	for _, rule := range s.rules {
		work += rule.mediaStateWork(false)
	}
	matches := matchBudget{limit: work}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	result := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if matches.exhausted || !result.style[display].Known {
		t.Fatalf("irrelevant indexed rule consumed work: budget=%+v display=%+v", matches, result.style[display])
	}
}

func TestDeclarationsPrepareContextFreeValuesOnce(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	static := s.declarations("color", "rgb(1 2 3)")
	if len(static) != 1 || static[0].prepared == nil || static[0].prepared.status != 1 || !static[0].prepared.value.Known {
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
		"-webkit-mask", "-webkit-transform", "-ms-transform", "-webkit-text-stroke-width", "--custom",
	}
	for _, property := range relevant {
		if !relevantDeclarationProperty(property) {
			t.Errorf("relevantDeclarationProperty(%q) = false", property)
		}
	}
	for _, property := range []string{"border", "padding", "animation", "-vendor-display", ""} {
		if relevantDeclarationProperty(property) {
			t.Errorf("relevantDeclarationProperty(%q) = true", property)
		}
	}
}

func TestAnalyzeReportsResourceUsage(t *testing.T) {
	limits := DefaultLimits()
	document, err := Analyze([]byte(`<style>@media screen{p,.x{font-size:calc(50% + 1px)}}</style><p class="x">T</p>`), limits)
	if err != nil {
		t.Fatal(err)
	}
	usage := document.Usage
	if usage.InputBytes == 0 || usage.Nodes == 0 || usage.TextNodes == 0 || usage.Attributes != 1 || usage.Depth == 0 {
		t.Fatalf("missing HTML usage: %+v", usage)
	}
	if usage.CSSDepth != 1 || usage.Rules != 1 || usage.Selectors != 2 || usage.MediaCases == 0 {
		t.Fatalf("missing CSS usage: %+v", usage)
	}
	if usage.MatchWork == 0 || usage.MatchWork > limits.MatchWork || usage.ExpressionWork > limits.ExpressionWork {
		t.Fatalf("invalid work usage: %+v", usage)
	}
}

func TestCSSLimitAbandonmentPreservesResourceUsage(t *testing.T) {
	limits := DefaultLimits()
	limits.Rules = 1
	document, err := Analyze([]byte(`<style>p{display:none}b{display:none}</style><p>T</p>`), limits)
	if err != nil {
		t.Fatal(err)
	}
	if label := findText(t, document, "T").Label; label != "unknown" {
		t.Fatalf("label = %q, want unknown", label)
	}
	usage := document.Usage
	if !usage.CSSLimitExceeded {
		t.Fatalf("CSS limit was not reported: %+v", usage)
	}
	if usage.Rules != 2 || usage.Selectors != 2 {
		t.Fatalf("discarded CSS work was not retained: %+v", usage)
	}
	if usage.MatchWork <= 1 {
		t.Fatalf("planning work was reset on abandonment: %+v", usage)
	}
}

func TestCSSAbandonmentReleasesPreparedElementMetadata(t *testing.T) {
	limits := DefaultLimits()
	limits.Rules = 1
	document, err := (processor{Limits: limits}).parseDocument([]byte(`<p class="before" style="display:none">A</p><style>b{display:none}i{display:none}</style><b class="after">B</b>`))
	if err != nil {
		t.Fatal(err)
	}
	if !document.styles.cascadeIncomplete {
		t.Fatal("CSS limit was not exhausted")
	}
	if document.elements != nil {
		t.Fatalf("unusable element metadata was retained for %d elements", len(document.elements))
	}
}

func TestOversizedDeclarationValueIsPreparedAsUnresolved(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	value := "rgb(" + strings.Repeat("0", maxValueBytes) + ")"
	ds := s.declarations("color", value)
	if len(ds) != 1 || ds[0].prepared == nil || ds[0].prepared.status != 2 {
		t.Fatalf("oversized declaration was not bounded: %+v", ds)
	}
}

func TestLongValidMathValueCanStillProveConcealment(t *testing.T) {
	value := "calc(" + strings.Repeat("0px + ", 900) + "1px)"
	if len(value) <= 4096 || len(value) > maxValueBytes {
		t.Fatalf("invalid test value length %d", len(value))
	}
	document := inspectHTML(t, `<p style="font-size:`+value+`">T</p>`)
	text := findText(t, document, "T")
	if text.Label != "concealed" {
		t.Fatalf("label = %q, want concealed", text.Label)
	}
	if size := textStyle(text, "font-size"); !size.Known || size.Number != 1 {
		t.Fatalf("font size = %+v, want known 1px", size)
	}
}

func TestDeclarationValuesShareWorkBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 4
	s := sheet{limits: limits}
	s.parseCSS(`p{display:none}`, false)
	if !s.workIncomplete {
		t.Fatal("declaration value did not exhaust the shared work budget")
	}
	matches := matchBudget{limit: limits.MatchWork, used: s.planningWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	result := s.elementStyle(&html.Node{Type: html.ElementNode, Data: "p"}, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
	if !matches.exhausted || result.style[display].Known {
		t.Fatalf("exhausted declaration work was trusted: budget=%+v display=%+v", matches, result.style[display])
	}
}

func TestSelectorPlanningSharesWorkBudget(t *testing.T) {
	selector := strings.Repeat(".a", 20)
	limits := DefaultLimits()
	limits.MatchWork = int64(len(selector))
	s := sheet{limits: limits}
	s.parseCSS(selector+`{display:none}`, false)
	if !s.workIncomplete {
		t.Fatal("selector planning did not exhaust the shared work budget")
	}
	if s.planCount != 0 || len(s.rules) != 0 {
		t.Fatalf("selector was planned after budget exhaustion: plans=%d rules=%d", s.planCount, len(s.rules))
	}
}

func TestSiblingSelectorWorkIsWeighted(t *testing.T) {
	const nodes = 100
	const limit = int64(1_000_000)
	for _, selector := range []string{"q ~ p", "q + p"} {
		sequence := 0
		plan := planSelectorList(selector, &sequence)[0]
		want := int64(5) + int64(nodes+1)*siblingMatchWeight
		if got := selectorExecutionCost(plan.complexity, selectorAttributeProfile{}, 1, nodes, limit); got != want {
			t.Errorf("selectorExecutionCost(%q) = %d, want %d", selector, got, want)
		}
	}
	sequence := 0
	plan := planSelectorList("q p", &sequence)[0]
	if got, want := selectorExecutionCost(plan.complexity, selectorAttributeProfile{}, 4, nodes, limit), int64(10); got != want {
		t.Errorf("descendant selector cost = %d, want %d", got, want)
	}
	sequence = 0
	plan = planSelectorList("a ~ b ~ p", &sequence)[0]
	if bound, additive := plannedSelectorCost(plan.complexity, selectorAttributeProfile{}, 1, nodes, limit), selectorExecutionCost(plan.complexity, selectorAttributeProfile{}, 1, nodes, limit); bound <= additive {
		t.Fatalf("nested sibling bound %d did not exceed additive cost %d", bound, additive)
	}

	maxInt := int(^uint(0) >> 1)
	sequence = 0
	plan = planSelectorList("q ~ p", &sequence)[0]
	if got := selectorExecutionCost(plan.complexity, selectorAttributeProfile{}, 1, maxInt, limit); got != limit+1 {
		t.Fatalf("overflowing execution cost = %d, want %d", got, limit+1)
	}
	if got := plannedSelectorCost(plan.complexity, selectorAttributeProfile{}, 1, maxInt, limit); got != limit+1 {
		t.Fatalf("overflowing planned cost = %d, want %d", got, limit+1)
	}
}

func TestAttributeAwareSelectorBoundRejectsExpensiveBacktracking(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`.a1 .a2 .a3 p{display:none}`, false)
	s.buildSelectorIndex(104, 108)
	plan := &s.rules[0].plans[0]
	profile := selectorAttributeProfile{classes: 3125, attributes: 3125}
	context := selectorMatchContext{current: profile, path: profile, document: profile, depth: 104, nodes: 108}
	if cost := selectorMatchCost(plan, context, limits.MatchWork); cost <= limits.MatchWork {
		t.Fatalf("attribute-heavy selector match cost = %d, want over %d", cost, limits.MatchWork)
	}
}

func TestAttributeAwareSelectorChargesConservativeBound(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`.ancestor p{display:none}`, false)
	s.buildSelectorIndex(10, 20)
	plan := &s.rules[0].plans[0]
	profile := selectorAttributeProfile{classes: 100, ids: 2, attributes: 200}
	context := selectorMatchContext{current: selectorAttributeProfile{}, path: profile, document: profile, depth: 10, nodes: 20}
	cost := selectorMatchCost(plan, context, limits.MatchWork)
	withAttributes := plannedSelectorCost(plan.execution, profile, context.depth, context.nodes, limits.MatchWork)
	withoutAttributes := plannedSelectorCost(plan.execution, selectorAttributeProfile{}, context.depth, context.nodes, limits.MatchWork)
	want := plan.cost + withAttributes - withoutAttributes
	if plan.uncertain || cost != want || cost <= plan.cost {
		t.Fatalf("attribute selector cost = %d, want conservative %d above static %d: %+v", cost, want, plan.cost, plan)
	}
}

func TestAttributeHeavyBacktrackingStopsBeforeCascadia(t *testing.T) {
	const depth = 100
	class := "a3 a2 " + strings.Repeat("x", 20000-len("a3 a2 "))
	var source strings.Builder
	source.WriteString(`<style>.a1 .a2 .a3 p{display:none}</style>`)
	for range depth {
		source.WriteString(`<div class="`)
		source.WriteString(class)
		source.WriteString(`">`)
	}
	source.WriteString(`<p>T</p>`)
	document, err := Analyze([]byte(source.String()), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("attribute-heavy selector result = %q, want unknown", got)
	}
	if document.Usage.MatchWork > int64(document.Usage.Nodes)*elementTraversalWork+10 {
		t.Fatalf("expensive selector reached matching: usage=%+v", document.Usage)
	}
}

func TestOverComplexSelectorBecomesUncertainBeforeMatching(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 1_000
	s := sheet{limits: limits}
	s.parseCSS(`a ~ b ~ p{display:none}`, false)
	s.buildSelectorIndex(1, 100)
	if len(s.rules) != 1 || len(s.rules[0].plans) != 1 {
		t.Fatalf("unexpected plans: %+v", s.rules)
	}
	plan := s.rules[0].plans[0]
	if plan.bound <= limits.MatchWork {
		t.Fatalf("single-call bound %d did not exceed limit %d", plan.bound, limits.MatchWork)
	}
	if !plan.uncertain || plan.matcher != nil || plan.scope == nil {
		t.Fatalf("over-complex selector was not converted to uncertainty: %+v", plan)
	}
}

func TestConservativeSelectorScopeAlwaysHasSafeFallback(t *testing.T) {
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	for _, prefix := range []string{"", "*", "["} {
		if matcher := compileConservativeScope(prefix); matcher == nil || !matcher.Match(node) {
			t.Fatalf("scope %q did not use a universal fallback", prefix)
		}
	}
	matcher := compileConservativeScope("div")
	if matcher == nil || matcher.Match(node) {
		t.Fatal("valid conservative scope lost its tag constraint")
	}
}

func TestSelectorIndexIncludesEveryPotentialCandidate(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`p{display:none}.target{opacity:0}#chosen{visibility:hidden}.ancestor *{font-size:0}[data-x]{color:red}`, false)
	s.buildSelectorIndex(4, 20)
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
	s.parseCSS(`p{display:none}`, false)
	s.buildSelectorIndex(128, 129)
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
	s.parseCSS(`s|text{display:none}*|text{display:none}|text{display:none}s|*{visibility:hidden}s|linearGradient{opacity:0}[s|href]{display:none}`, false)
	s.buildSelectorIndex(2, 4)
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

func TestSelectorIndexDoesNotReturnUnrelatedKeyedRules(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`.wanted{display:none}#chosen{opacity:0}section{visibility:hidden}`, false)
	s.buildSelectorIndex(1, 4)
	node := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "other"}}}
	if refs := s.candidates(node); len(refs) != 0 {
		t.Fatalf("unrelated candidates = %+v", refs)
	}
}

func TestSelectorIndexRemovesRulesWithoutRelevantDeclarations(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`*{}.unused{unknown-property:value}p{display:none}`, false)
	if len(s.rules) != 3 {
		t.Fatalf("parsed rules = %d, want 3", len(s.rules))
	}
	s.buildSelectorIndex(1, 1)
	if len(s.rules) != 1 || len(s.rules[0].decls) != 1 {
		t.Fatalf("indexed rules = %+v", s.rules)
	}
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	if refs := s.candidates(node); len(refs) != 1 {
		t.Fatalf("relevant candidates = %+v", refs)
	}
}

func TestMatchCacheStopsAtDocumentLimit(t *testing.T) {
	s := sheet{limits: DefaultLimits(), runtime: sheetRuntime{cacheMatches: true, matchCacheEntries: maxMatchCacheEntries - 1}}
	s.parseCSS(`p{display:none}`, false)
	s.buildSelectorIndex(1, 2)
	// buildSelectorIndex resets cache accounting, so place it immediately below
	// the ceiling before exercising two distinct entries.
	s.runtime.cacheMatches = true
	s.runtime.matchCacheEntries = maxMatchCacheEntries - 1
	plan := &s.rules[0].plans[0]
	first := &html.Node{Type: html.ElementNode, Data: "p"}
	second := &html.Node{Type: html.ElementNode, Data: "p"}
	s.cacheMatch(plan, first, true)
	s.cacheMatch(plan, second, true)
	if s.runtime.matchCacheEntries != maxMatchCacheEntries {
		t.Fatalf("cache entries = %d", s.runtime.matchCacheEntries)
	}
	cache := s.runtime.matchCaches[plan.sequence]
	if cache[first] != 2 {
		t.Fatal("entry below the ceiling was not cached")
	}
	if _, ok := cache[second]; ok {
		t.Fatal("entry beyond the ceiling was cached")
	}
}

func TestMatchingContinuesAfterMatchCacheIsFull(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`p{display:none}`, false)
	s.buildSelectorIndex(1, 1)
	s.runtime.cacheMatches = true
	s.runtime.matchCacheEntries = maxMatchCacheEntries
	matches := matchBudget{limit: s.limits.MatchWork, used: s.planningWork}
	expressions := expressionBudget{remaining: s.limits.ExpressionWork}
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	for range 2 {
		result := s.elementStyle(node, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &expressions)
		if !result.style[display].Known || result.style[display].Text != "none" {
			t.Fatalf("uncached match display = %+v", result.style[display])
		}
	}
	if s.runtime.matchCaches != nil {
		t.Fatal("full cache retained a new match")
	}
}

func TestSelectorIndexBypassesAttributeWorkWithoutSelectors(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.buildSelectorIndex(1, 1)
	node := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: strings.Repeat("word ", 1_000)}}}
	if refs := s.candidates(node); len(refs) != 0 {
		t.Fatalf("candidates without selectors = %+v", refs)
	}
}

func TestSelectorIndexDeduplicatesRepeatedAncestorBuckets(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(strings.Repeat(`.wanted *{display:none}`, 1_000), false)
	s.buildSelectorIndex(128, 129)
	parent := &html.Node{Type: html.ElementNode, Data: "div"}
	for range 128 {
		parent = &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "class", Val: "wanted"}}, Parent: parent}
	}
	node := &html.Node{Type: html.ElementNode, Data: "p", Parent: parent}
	matches := matchBudget{limit: s.limits.MatchWork}
	refs, complete := s.collectCandidates(node, &matches)
	if !complete || len(refs) != 1_000 {
		t.Fatalf("repeated ancestor candidates = %+v, complete=%t", refs, complete)
	}
	if len(s.runtime.candidateScratch) > s.index.count {
		t.Fatalf("candidate scratch length = %d, selector count = %d", len(s.runtime.candidateScratch), s.index.count)
	}
	if matches.used != 1_256 {
		t.Fatalf("candidate work = %d, want 256 attribute scans plus 1,000 bucket entries", matches.used)
	}
	limited := matchBudget{limit: 100}
	if _, complete := s.collectCandidates(node, &limited); complete || !limited.exhausted {
		t.Fatalf("limited candidate collection completed: %+v", limited)
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
	for _, container := range []string{"template", "iframe", "noembed", "noframes", "object"} {
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
