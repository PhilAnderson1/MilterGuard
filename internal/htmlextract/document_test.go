package htmlextract

import (
	"bytes"
	"context"
	"math"
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
	if text.Label != "concealed" || strings.Join(text.ConcealmentReasons, ",") != "display-none" {
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
	if len(text.ConcealmentReasons) != 0 || text.EffectiveOpacity != 0 {
		t.Fatalf("aggregated viewing-case evidence = %+v", text)
	}

	document, err = Analyze([]byte(`<style>p{color:white;background:white}@media(min-width:500px){p{color:black;font-size:0}}</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	text = findText(t, document, "T")
	if text.Label != "concealed" || strings.Join(text.ConcealmentReasons, ",") != "font-size,colour-distance" || text.FontSize != "0px" {
		t.Fatalf("aggregated font-size evidence = %+v", text)
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

func TestMatchWorkMaximumKeepsOverBudgetSentinelRepresentable(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = maxMatchWork
	if _, err := Analyze([]byte(`<style>div ~ b ~ div{visibility:hidden}</style><div>T</div>`), limits); err != nil {
		t.Fatalf("maximum safe MatchWork rejected: %v", err)
	}

	limits.MatchWork++
	_, err := Analyze([]byte(`<style>div ~ b ~ div{visibility:hidden}</style><div>T</div>`), limits)
	if err == nil || !strings.Contains(err.Error(), "invalid limit: MatchWork") {
		t.Fatalf("overflowing MatchWork validation error = %v", err)
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

func TestCSSConstructPreflightMirrorsVendorPrefixedAtRules(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSConstructBytes = 32
	for _, atRule := range []string{"@-x-media screen", "@-x-supports (display:block)", "@-moz-document url-prefix()", "@-webkit-keyframes pulse"} {
		t.Run(atRule, func(t *testing.T) {
			source := atRule + `{` + strings.Repeat(`p{color:red}`, 10) + `}`
			if len(source) <= limits.CSSConstructBytes {
				t.Fatalf("test source is only %d bytes", len(source))
			}
			if !boundedCSSConstructs(source, false, limits.CSSConstructBytes, limits.CSSConstructTokens) {
				t.Fatal("bounded nested rules were treated as one construct")
			}
		})
	}
}

func TestCSSConstructPreflightDoesNotPromoteUnknownVendorAtRule(t *testing.T) {
	if got := atRuleContext("@-x-widget"); got != cssDeclarationList {
		t.Fatalf("unknown vendor at-rule context = %v, want declaration list", got)
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

func TestOversizedInlineStyleKeepsUncertaintyLocal(t *testing.T) {
	limits := DefaultLimits()
	limits.CSSConstructBytes = 32
	stylesheet := `.concealed{display:none}`
	inline := `color:` + strings.Repeat(`x`, limits.CSSConstructBytes+1)
	source := `<style>` + stylesheet + `</style>` +
		`<p class="concealed">Hidden</p>` +
		`<div style="` + inline + `">Uncertain<span>Descendant</span></div>` +
		`<p>Visible</p>`
	document, err := Analyze([]byte(source), limits)
	if err != nil {
		t.Fatal(err)
	}
	for text, want := range map[string]string{
		"Hidden":     "concealed",
		"Uncertain":  "unknown",
		"Descendant": "unknown",
		"Visible":    "visible",
	} {
		if got := findText(t, document, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
	}
	if document.Usage.CSSLimitExceeded {
		t.Fatalf("localized inline limit invalidated the cascade: %+v", document.Usage)
	}
	if want := len(stylesheet) + len(inline); document.Usage.CSSBytes != want {
		t.Fatalf("CSS bytes = %d, want %d", document.Usage.CSSBytes, want)
	}
}

func TestAnalyzeDoesNotPreallocateCallerDepth(t *testing.T) {
	limits := DefaultLimits()
	limits.Depth = int(^uint(0) >> 1)
	if _, err := Analyze([]byte(`<p>T</p>`), limits); err != nil {
		t.Fatal(err)
	}
}

func TestTreeDepthAllowsParserImpliedAncestors(t *testing.T) {
	limits := DefaultLimits()
	boundary := strings.Repeat(`<div>`, limits.Depth) + `T`
	document, err := Analyze([]byte(boundary), limits)
	if err != nil {
		t.Fatalf("boundary fragment rejected: %v", err)
	}
	if document.Usage.Depth <= limits.Depth || document.Usage.Depth > limits.Depth+impliedTreeDepthMargin {
		t.Fatalf("boundary fragment depth = %d, want parser margin above %d", document.Usage.Depth, limits.Depth)
	}

	withTableWrapper := strings.Repeat(`<div>`, limits.Depth-3) + `<table><tr><td>T`
	if document, err = Analyze([]byte(withTableWrapper), limits); err != nil {
		t.Fatalf("boundary table fragment rejected: %v", err)
	}
	if document.Usage.Depth <= limits.Depth || document.Usage.Depth > limits.Depth+impliedTreeDepthMargin {
		t.Fatalf("boundary table depth = %d, want parser margin above %d", document.Usage.Depth, limits.Depth)
	}

	nestedTables := 33
	nestedTableSource := strings.Repeat(`<table><tr><td>`, nestedTables) + `T`
	document, err = Analyze([]byte(nestedTableSource), limits)
	if err != nil {
		t.Fatalf("nested tables within lexical depth rejected: %v", err)
	}
	if document.Usage.Depth <= limits.Depth+impliedTreeDepthMargin || document.Usage.Depth > limits.Depth+impliedTreeDepthMargin+nestedTables {
		t.Fatalf("nested-table tree depth = %d, want dynamic allowance above %d", document.Usage.Depth, limits.Depth+impliedTreeDepthMargin)
	}

	// A td directly below each table causes the parser to insert both tbody
	// and tr. Those generated ancestors must not turn lexically bounded input
	// into a post-allocation depth rejection.
	impliedWrapperTables := 63
	impliedWrapperSource := strings.Repeat(`<table><td>`, impliedWrapperTables) + `T`
	document, err = Analyze([]byte(impliedWrapperSource), limits)
	if err != nil {
		t.Fatalf("nested tables with implied tbody/tr wrappers rejected: %v", err)
	}
	if document.Usage.Depth <= limits.Depth+impliedTreeDepthMargin+impliedWrapperTables ||
		document.Usage.Depth > limits.Depth+impliedTreeDepthMargin+2*impliedWrapperTables {
		t.Fatalf("implied-wrapper tree depth = %d, want two-level table allowance", document.Usage.Depth)
	}

	if _, err = Analyze([]byte(strings.Repeat(`<div>`, limits.Depth+1)), limits); err == nil || !strings.Contains(err.Error(), "lexical depth") {
		t.Fatalf("explicit over-limit nesting error = %v, want lexical-depth rejection", err)
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
	if len(document.Elements) != 2 {
		t.Fatalf("retained elements = %d, want only two active elements: %+v", len(document.Elements), document.Elements)
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
	t.Run("node-producing end tags", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Nodes = 4
		if err := preflight([]byte(strings.Repeat(`</br>`, limits.Nodes)), limits); err != nil {
			t.Fatalf("exact token budget rejected: %v", err)
		}
		_, err := (processor{Limits: limits}).parseDocument([]byte(strings.Repeat(`</br>`, limits.Nodes+1)))
		if err == nil || !strings.Contains(err.Error(), "lexical nodes") {
			t.Fatalf("end-tag flood limit error = %v", err)
		}
	})
	t.Run("balanced HTML uses the same conservative budget", func(t *testing.T) {
		limits := DefaultLimits()
		limits.Nodes = 6
		usage, err := measurePreflight([]byte(`<b>x</b><i>y</i>`), limits)
		if err != nil {
			t.Fatal(err)
		}
		if usage.nodes != 4 || usage.treeBuilderTokens != limits.Nodes {
			t.Fatalf("lexical usage = %+v", usage)
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

func TestPreflightImplicitClosuresPreserveConcealmentAnalysis(t *testing.T) {
	for _, c := range []struct{ name, prefix, suffix string }{
		{"paragraphs", strings.Repeat(`<p>`, 200), ""},
		{"paragraph phrasing", strings.Repeat(`<p><span>x`, 200), ""},
		{"paragraphs in container", `<div>` + strings.Repeat(`<p>x`, 200), `</div>`},
		{"list items", `<ul>` + strings.Repeat(`<li>x`, 200), `</ul>`},
		{"list item phrasing", `<ul>` + strings.Repeat(`<li><span>x`, 200), `</ul>`},
		{"definition items", `<dl>` + strings.Repeat(`<dt>x<dd>y`, 200), `</dl>`},
		{"options", `<select>` + strings.Repeat(`<option>x`, 200), `</select>`},
		{"option groups", `<select>` + strings.Repeat(`<optgroup><option>x`, 200), `</select>`},
		{"anchors", strings.Repeat(`<a href="#">`, 200), `</a>`},
		{"cells", `<table><tr>` + strings.Repeat(`<td>x<th>y`, 200), `</table>`},
		{"rows", `<table>` + strings.Repeat(`<tr><td>x`, 200), `</table>`},
		{"table sections", `<table>` + strings.Repeat(`<tbody><tr><td>x`, 200), `</table>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.Depth = 16
			source := c.prefix + c.suffix + `<div style="display:none">PAYLOAD</div>`
			usage, err := measurePreflight([]byte(source), limits)
			if err != nil {
				t.Fatalf("shallow optional-tag sequence rejected: %v", err)
			}
			in, err := Analyze([]byte(source), limits)
			if err != nil {
				t.Fatal(err)
			}
			if got := findText(t, in, "PAYLOAD").Label; got != "concealed" {
				t.Fatalf("label = %q, want concealed; preflight usage=%+v", got, usage)
			}
		})
	}
}

func TestPreflightImplicitClosuresDoNotFlattenRealNesting(t *testing.T) {
	for _, c := range []struct{ name, repeated string }{
		{"divs", `<div>`},
		{"nested lists", `<ul><li>`},
		{"nested definition lists", `<dl><dd>`},
		{"nested tables", `<table><tr><td>`},
		{"paragraph button scope", `<p><button>`},
		{"paragraph object scope", `<p><object>`},
		{"paragraph template scope", `<p><template>`},
		{"foreign paragraph scope", `<math><mtext><p>`},
		{"foreign cells", `<svg><td>`},
		{"SVG recovery retains ancestors", `<p><svg><div>`},
		{"MathML recovery retains ancestors", `<div><p><math>`},
		{"groups outside select", `<optgroup>`},
		{"anchor recovery across blocks", `<a><div>`},
	} {
		t.Run(c.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.Depth = 16
			err := preflight([]byte(strings.Repeat(c.repeated, 20)), limits)
			if err == nil || !strings.Contains(err.Error(), "lexical depth") {
				t.Fatalf("expected rejection before tree construction, got %v", err)
			}
		})
	}
}

func TestPreflightImplicitClosureDepthAgainstTreeBuilder(t *testing.T) {
	// Repeated three-tag patterns exercise interactions between optional
	// closures, insertion contexts, formatting recovery, and foreign content.
	// The oracle is the actual allocating parser, not our closure lookup rules.
	tags := []string{"p", "div", "button", "table", "td", "tr", "tbody", "select", "option", "optgroup", "li", "ul", "dd", "dl", "a", "b", "template", "svg", "g", "foreignObject", "math", "mtext", "object", "caption", "form"}
	limits := DefaultLimits()
	limits.Depth = 16
	for _, a := range tags {
		for _, b := range tags {
			for _, c := range tags {
				pattern := "<" + a + "><" + b + "><" + c + ">"
				source := strings.Repeat(pattern, 70)
				usage, err := measurePreflight([]byte(source), limits)
				if err != nil {
					continue
				}
				root, err := html.ParseWithOptions(strings.NewReader(source), html.ParseOptionEnableScripting(false))
				if err != nil {
					t.Fatalf("admitted %s: tree construction failed: %v", pattern, err)
				}
				type entry struct {
					n     *html.Node
					depth int
				}
				stack := []entry{{n: root}}
				for len(stack) > 0 {
					e := stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					if e.depth > limits.Depth+impliedTreeDepthMargin+2*usage.nestedTables {
						t.Fatalf("admitted %s: tree depth %d exceeds guarded depth; preflight=%+v", pattern, e.depth, usage)
					}
					for child := e.n.FirstChild; child != nil; child = child.NextSibling {
						stack = append(stack, entry{n: child, depth: e.depth + 1})
					}
				}
			}
		}
	}
}

func TestPreflightImplicitClosuresKeepResourceAccounting(t *testing.T) {
	limits := DefaultLimits()
	limits.Depth = 4
	limits.Nodes = 10
	_, err := measurePreflight([]byte(strings.Repeat(`<p>`, 11)), limits)
	if err == nil || !strings.Contains(err.Error(), "lexical nodes") {
		t.Fatalf("implicit closure bypassed token budget: %v", err)
	}
	limits.Nodes = 100
	limits.Attributes = 10
	_, err = measurePreflight([]byte(strings.Repeat(`<p id="x">`, 11)), limits)
	if err == nil || !strings.Contains(err.Error(), "lexical attributes") {
		t.Fatalf("implicit closure bypassed attribute budget: %v", err)
	}
	// Every implicit pop must also remove descendants from the end-tag index.
	usage, err := measurePreflight([]byte(`<p><span><p></span></p><div>`), limits)
	if err != nil || usage.depth != 2 {
		t.Fatalf("stale open-element index after implicit closure: usage=%+v error=%v", usage, err)
	}
}

func TestPreflightMirrorsTreeBuilderRawTextOverrides(t *testing.T) {
	for _, test := range []struct {
		name, source string
	}{
		{
			name:   "noscript with scripting disabled",
			source: `<noscript><b a="1" b="2" c="3">text</b></noscript>`,
		},
		{
			name:   "raw-text-named SVG element",
			source: `<svg><title><b a="1" b="2" c="3">text</b></title></svg>`,
		},
		{
			name:   "raw-text-named MathML element",
			source: `<math><style><b a="1" b="2" c="3">text</b></style></math>`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			limits := DefaultLimits()
			limits.Attributes = 2
			err := preflight([]byte(test.source), limits)
			if err == nil || !strings.Contains(err.Error(), "lexical attributes") {
				t.Fatalf("preflight limit error = %v", err)
			}
		})
	}
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

func TestParserCompatibilityPreservesAuthorEscapedParentheses(t *testing.T) {
	for _, test := range []struct {
		name, css  string
		inline     bool
		wantColour string
	}{
		{
			name: "comment rewrite",
			css:  `p{/* separator */--literal:"\)";--url:url(x\))}`,
		},
		{
			name:       "delimiter rewrite",
			css:        `p{--literal:"\)";--url:url(x\));--mixed:var(--missing,"\)",[unused)]);--mixed-after:var(--missing,[unused)]),"\)";color:var(--missing,[unused)])}`,
			wantColour: `var(--missing,[unused)])`,
		},
		{
			name:       "inline delimiter rewrite",
			css:        `--literal:"\)";--url:url(x\));--mixed:var(--missing,"\)",[unused)]);--mixed-after:var(--missing,[unused)]),"\)";color:var(--missing,[unused)])`,
			inline:     true,
			wantColour: `var(--missing,[unused)])`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := sheet{limits: DefaultLimits()}
			var declarations []declaration
			if test.inline {
				declarations = s.parseCSS(test.css, true)
			} else {
				s.parseCSS(test.css, false)
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
				t.Fatalf("mixed compatibility value = %q, want author escape and restored delimiter", values["--mixed"])
			}
			if test.wantColour != "" && values["--mixed-after"] != `var(--missing,[unused)]),"\)"` {
				t.Fatalf("trailing author escape = %q, want restored delimiter and author escape", values["--mixed-after"])
			}
			if test.wantColour != "" && values["color"] != test.wantColour {
				t.Fatalf("restored compatibility value = %q, want %q", values["color"], test.wantColour)
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

func TestCSSDataURLMetadataIsBoundedWithoutBreakingTerminalBase64Marker(t *testing.T) {
	payload := `cHtkaXNwbGF5Om5vbmV9`
	for _, reference := range []string{
		`data:text/css;note="a;b";base64,` + payload,
		`data:text/css;note="a;b"; BASE64 ,` + payload,
	} {
		decoded, isData, valid := decodeCSSDataURL(reference, maxValueBytes)
		if !isData || !valid || string(decoded) != `p{display:none}` {
			t.Fatalf("valid base64 data URL rejected: data=%t valid=%t decoded=%q", isData, valid, decoded)
		}
	}

	oversized := `data:text/css;` + strings.Repeat(`a`, maxValueBytes) + `,p%7Bdisplay%3Anone%7D`
	decoded, isData, valid := decodeCSSDataURL(oversized, maxValueBytes)
	if !isData || valid || decoded != nil {
		t.Fatalf("oversized metadata admitted: data=%t valid=%t decoded=%q", isData, valid, decoded)
	}
	s := sheet{limits: DefaultLimits()}
	s.loadStylesheetReference(oversized, "")
	if !s.unresolvedStylesheet {
		t.Fatal("oversized metadata was not reported as an unresolved stylesheet")
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
	for text, want := range map[string]string{"offer": "unknown", "other": "unknown", "ordinary": "visible"} {
		if got := findText(t, in, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
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
	matches := matchBudget{limit: elementInheritanceWork}
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

func TestColourMemoRetainsPerTextWorkCharge(t *testing.T) {
	style := initial()
	runner := viewingCaseRunner{
		matches: &matchBudget{limit: 100},
		layers:  []paintLayer{layer(&style)},
	}
	first := runner.evaluateColour(style[color])
	firstCharge := runner.matches.used
	if !first.known || firstCharge == 0 {
		t.Fatalf("first colour evaluation = %+v, budget=%+v", first, runner.matches)
	}
	second := runner.evaluateColour(style[color])
	if second != first || runner.matches.used != 2*firstCharge {
		t.Fatalf("memoized colour evaluation = %+v, budget=%+v; first=%+v, charge=%d", second, runner.matches, first, firstCharge)
	}
	runner.layerGeneration++
	third := runner.evaluateColour(style[color])
	if third != first || runner.matches.used != 3*firstCharge {
		t.Fatalf("invalidated colour evaluation = %+v, budget=%+v", third, runner.matches)
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

func TestAnalyzeReportsUnsupportedColourFunctions(t *testing.T) {
	document, err := Analyze([]byte(`<p style="--ink:lab(50% 0 0);color:var(--ink);background:color-mix(in srgb,red,blue)">T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := document.Usage.UnsupportedColourFunctions; got != 2 {
		t.Fatalf("unsupported colour functions = %d, want 2", got)
	}
	if label := findText(t, document, "T").Label; label != "unknown" {
		t.Fatalf("label = %q, want unknown", label)
	}
}

func TestAnalyzeReportsExpressionDepthLimit(t *testing.T) {
	tests := []struct {
		name     string
		property string
		value    string
	}{
		{
			name:     "variable fallback",
			property: "display",
			value: func() string {
				value := "none"
				for range maxExpressionDepth + 1 {
					value = "var(--missing," + value + ")"
				}
				return value
			}(),
		},
		{
			name:     "arithmetic",
			property: "font-size",
			value:    strings.Repeat("calc(", maxExpressionDepth+1) + "1px" + strings.Repeat(")", maxExpressionDepth+1),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, err := Analyze([]byte(`<p style="`+test.property+`:`+test.value+`">T</p>`), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !document.Usage.ExpressionDepthLimitExceeded {
				t.Fatalf("expression depth limit was not reported: %+v", document.Usage)
			}
			if document.Usage.ExpressionWorkExhausted {
				t.Fatalf("depth limit was misreported as work exhaustion: %+v", document.Usage)
			}
			if label := findText(t, document, "T").Label; label != "unknown" {
				t.Fatalf("label = %q, want unknown", label)
			}
		})
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

func TestCSSSourceScanningIsChargedAndReported(t *testing.T) {
	const cssText = `p{display:none}`
	document, err := Analyze([]byte(`<style>`+cssText+`</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if document.Usage.CSSBytes != len(cssText) {
		t.Fatalf("CSS bytes = %d, want %d", document.Usage.CSSBytes, len(cssText))
	}
	if document.Usage.MatchWork < int64(len(cssText)+1) {
		t.Fatalf("CSS source scan was not charged: %+v", document.Usage)
	}
}

func TestMediaConditionPlanningIsCached(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	condition := `(max-width: 600px)`
	first := s.parseMediaCondition(condition)
	if len(first) == 0 || s.planningWork == 0 {
		t.Fatalf("first media parse was not retained or charged: condition=%+v work=%d", first, s.planningWork)
	}
	charged := s.planningWork
	second := s.parseMediaCondition(condition)
	if len(second) == 0 || s.planningWork != charged {
		t.Fatalf("cached media parse was charged again: before=%d after=%d", charged, s.planningWork)
	}
	s.parseMediaCondition(`(min-width: 601px)`)
	if s.planningWork <= charged {
		t.Fatalf("distinct media parse was not charged: before=%d after=%d", charged, s.planningWork)
	}
}

func TestFailedAnalysisReturnsConsumedResourceUsage(t *testing.T) {
	source := `<style>p{display:none}</style><p>T`
	limits := DefaultLimits()
	limits.Nodes = 7 // Preflight sees five tokens; the DOM adds structural nodes.
	document, err := Analyze([]byte(source), limits)
	if err == nil || !strings.Contains(err.Error(), "tree nodes") {
		t.Fatalf("Analyze error = %v, want post-parse tree-node rejection", err)
	}
	if document.Root != nil || len(document.Text) != 0 || len(document.Elements) != 0 {
		t.Fatalf("failed analysis exposed partial document content: %+v", document)
	}
	if document.Usage.InputBytes != len(source) || document.Usage.MatchWork == 0 || document.Usage.Rules != 1 || document.Usage.Selectors != 1 {
		t.Fatalf("failed analysis discarded resource usage: %+v", document.Usage)
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

func TestAbandonedCascadeSkipsStylesheetReferences(t *testing.T) {
	for _, incomplete := range []struct {
		name    string
		cascade bool
		work    bool
	}{
		{name: "cascade", cascade: true},
		{name: "work", work: true},
	} {
		t.Run(incomplete.name, func(t *testing.T) {
			s := sheet{
				limits:            DefaultLimits(),
				cascadeIncomplete: incomplete.cascade,
				workIncomplete:    incomplete.work,
			}
			node := &html.Node{Type: html.ElementNode, Data: "link", Attr: []html.Attribute{
				{Key: "rel", Val: "stylesheet"},
				{Key: "media", Val: "screen"},
				{Key: "href", Val: "data:text/css,p%7Bdisplay%3Anone%7D"},
			}}
			if _, _, applies := s.stylesheetLink(node); applies {
				t.Fatal("stylesheet link applied after cascade abandonment")
			}
			if s.planningWork != 0 {
				t.Fatalf("stylesheet link consumed planning work: %d", s.planningWork)
			}

			s.loadStylesheetReference("https://example.invalid/style.css", "")
			if s.unresolvedStylesheet || s.cssBytes != 0 || len(s.rules) != 0 {
				t.Fatalf("stylesheet reference was processed after abandonment: %+v", s)
			}
		})
	}
}

func TestOversizedDeclarationValueIsPreparedAsUnresolved(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	value := "rgb(" + strings.Repeat("0", maxValueBytes) + ")"
	ds := s.declarations("color", value)
	if len(ds) != 1 || ds[0].prepared == nil || ds[0].prepared.status != valueUnsupported {
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

func TestSelectorAttributeCountWorkRoundsUp(t *testing.T) {
	for _, test := range []struct {
		attributes int
		want       int64
	}{
		{attributes: 0, want: 0},
		{attributes: 1, want: 1},
		{attributes: 8, want: 1},
		{attributes: 9, want: 2},
		{attributes: 49_000, want: 6_125},
	} {
		if got := selectorAttributeCountWork(test.attributes); got != test.want {
			t.Errorf("selectorAttributeCountWork(%d) = %d, want %d", test.attributes, got, test.want)
		}
	}
}

func TestSelectorAttributeProfileChargesTinyAttributes(t *testing.T) {
	node := &html.Node{Type: html.ElementNode, Data: "p"}
	for i := range 9 {
		node.Attr = append(node.Attr, html.Attribute{Key: string(rune('a' + i))})
	}
	var profile selectorAttributeProfile
	profile.observe(node)
	if profile.attributes != 2 {
		t.Fatalf("tiny attribute work = %d, want 2", profile.attributes)
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

func TestDescendantChainUsesBoundedMatcher(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`zzz div div div{display:none}`, false)
	s.buildSelectorIndex(122, 16_123)
	if len(s.rules) != 1 || len(s.rules[0].plans) != 1 {
		t.Fatalf("unexpected plans: %+v", s.rules)
	}
	plan := &s.rules[0].plans[0]
	if plan.bound <= limits.MatchWork/2 {
		t.Fatalf("descendant bound = %d, want a demonstrably expensive recursive bound", plan.bound)
	}
	if plan.uncertain || len(plan.ancestorChain) != 4 {
		t.Fatalf("descendant selector did not receive a bounded chain: %+v", plan)
	}
	node := &html.Node{Type: html.ElementNode, Data: "div"}
	for range 122 {
		child := &html.Node{Type: html.ElementNode, Data: "div", Parent: node}
		node.FirstChild = child
		node = child
	}
	context := selectorMatchContext{depth: 122, nodes: 123}
	budget := matchBudget{limit: limits.MatchWork}
	matched, complete := s.matchAncestorChain(plan, node, context, &budget)
	if !complete || matched {
		t.Fatalf("bounded descendant result: matched=%t complete=%t", matched, complete)
	}
	const wantWork = 123 + 123*4 // path walk plus one "zzz" check per element
	if budget.used != wantWork {
		t.Fatalf("bounded descendant work = %d, want %d", budget.used, wantWork)
	}
	sibling := &html.Node{Type: html.ElementNode, Data: "div", Parent: node.Parent}
	before := budget.used
	matched, complete = s.matchAncestorChain(plan, sibling, context, &budget)
	if !complete || matched {
		t.Fatalf("cached sibling result: matched=%t complete=%t", matched, complete)
	}
	if added := budget.used - before; added != 6 { // sibling + cached parent, then one 4-unit compound check
		t.Fatalf("cached sibling work = %d, want 6", added)
	}
	s.runtime.ancestorStates = nil
	s.runtime.ancestorNodes = nil
	s.runtime.matchCacheUnits = 0
	limited := matchBudget{limit: wantWork - 1}
	if _, complete := s.matchAncestorChain(plan, node, context, &limited); complete || !limited.exhausted {
		t.Fatalf("bounded matcher ignored exhaustion: %+v", limited)
	}
}

func TestBoundedAncestorChainsMatchCascadia(t *testing.T) {
	root, err := html.Parse(strings.NewReader(`<main class="a"><div><p class="b"><span class="c"><em id="target">T</em></span></p><p class="x">X</p></div></main>`))
	if err != nil {
		t.Fatal(err)
	}
	var elements []*html.Node
	stack := []*html.Node{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Type == html.ElementNode {
			elements = append(elements, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			stack = append(stack, child)
		}
	}
	for _, selector := range []string{
		`html main div`, `html > body main div`, `html main > div span em`, `.a > div .b .c`, `html div:not(.missing) p`,
	} {
		t.Run(selector, func(t *testing.T) {
			sequence := 0
			plan := planSelectorList(selector, &sequence)[0]
			if plan.uncertain || plan.ancestorChain == nil {
				t.Fatalf("selector did not compile as an ancestor chain: %+v", plan)
			}
			s := sheet{limits: DefaultLimits(), index: selectorIndex{count: 1}}
			for _, node := range elements {
				depth := 0
				for parent := node.Parent; parent != nil; parent = parent.Parent {
					if parent.Type == html.ElementNode {
						depth++
					}
				}
				budget := matchBudget{limit: s.limits.MatchWork}
				got, complete := s.matchAncestorChain(&plan, node, selectorMatchContext{depth: depth, nodes: len(elements)}, &budget)
				if !complete {
					t.Fatalf("bounded match exhausted for %s", node.Data)
				}
				if want := plan.matcher.Match(node); got != want {
					t.Fatalf("match(%s) = %t, Cascadia = %t", node.Data, got, want)
				}
			}
		})
	}
}

func TestDescendantChainBroomRemainsBounded(t *testing.T) {
	const (
		depth  = 122
		leaves = 16_000
	)
	var source strings.Builder
	source.WriteString(`<style>zzz div div div{color:red}</style>`)
	for range depth {
		source.WriteString(`<div>`)
	}
	for range leaves {
		source.WriteString(`<div>x</div>`)
	}
	for range depth {
		source.WriteString(`</div>`)
	}
	document, err := Analyze([]byte(source.String()), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if document.Usage.MatchWorkExhausted || document.Usage.MatchWork > 5_000_000 {
		t.Fatalf("descendant-chain broom used unbounded matching work: %+v", document.Usage)
	}
}

func TestAttributeHeavyBacktrackingUsesBoundedMatcher(t *testing.T) {
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
	if got := findText(t, document, "T").Label; got != "visible" {
		t.Fatalf("attribute-heavy selector result = %q, want visible", got)
	}
	if document.Usage.MatchWorkExhausted || document.Usage.MatchWork >= DefaultLimits().MatchWork {
		t.Fatalf("bounded selector exhausted matching work: usage=%+v", document.Usage)
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

func TestOverComplexSelectorRetainsSafeFinalAncestorScope(t *testing.T) {
	sequence := 0
	plan := planSelectorList(`u + .body .rio-asin-container-image img`, &sequence)[0]
	plan.makeUncertain()
	if !plan.uncertain || len(plan.execution.compounds) != 2 || len(plan.execution.combinators) != 1 || plan.execution.combinators[0] != ' ' {
		t.Fatalf("unexpected conservative plan: %+v", plan)
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

func TestUncertainSelectorScopeDoesNotCrossFinalSiblingCombinator(t *testing.T) {
	sequence := 0
	plan := planSelectorList(`.product + img`, &sequence)[0]
	plan.makeUncertain()
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
	s.parseCSS(`textPath{display:none}`, false)
	s.buildSelectorIndex(2, 2)
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
	s.parseCSS(`textpath{display:none}`, false)
	s.buildSelectorIndex(2, 2)
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
	s := sheet{limits: DefaultLimits(), runtime: sheetRuntime{cacheMatches: true, matchCacheUnits: maxMatchCacheUnits - 1}}
	s.parseCSS(`p{display:none}`, false)
	s.buildSelectorIndex(1, 2)
	// buildSelectorIndex resets cache accounting, so place it immediately below
	// the ceiling before exercising two distinct entries.
	s.runtime.cacheMatches = true
	s.runtime.matchCacheUnits = maxMatchCacheUnits - 1
	plan := &s.rules[0].plans[0]
	first := &html.Node{Type: html.ElementNode, Data: "p"}
	second := &html.Node{Type: html.ElementNode, Data: "p"}
	s.cacheMatch(plan, first, true)
	s.cacheMatch(plan, second, true)
	if s.runtime.matchCacheUnits != maxMatchCacheUnits {
		t.Fatalf("cache units = %d", s.runtime.matchCacheUnits)
	}
	cache := s.runtime.matchCaches[plan.sequence]
	if cache[first] != 2 {
		t.Fatal("entry below the ceiling was not cached")
	}
	if _, ok := cache[second]; ok {
		t.Fatal("entry beyond the ceiling was cached")
	}
}

func TestAttributeCandidateCacheSharesDocumentLimit(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`.one{display:none}.two{display:none}`, false)
	s.buildSelectorIndex(1, 2)
	s.runtime.matchCacheUnits = maxMatchCacheUnits - 3
	budget := matchBudget{limit: s.limits.MatchWork}
	first := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "one two"}}}
	candidates, complete := s.attributeCandidateBuckets(first, &budget)
	if !complete || len(candidates.direct) != 2 {
		t.Fatalf("attribute candidates = %+v, complete=%t", candidates, complete)
	}
	if s.runtime.matchCacheUnits != maxMatchCacheUnits {
		t.Fatalf("cache units = %d, want ceiling", s.runtime.matchCacheUnits)
	}
	if _, ok := s.runtime.attributeCandidates[first]; !ok {
		t.Fatal("attribute candidates below the ceiling were not cached")
	}

	second := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "one"}}}
	candidates, complete = s.attributeCandidateBuckets(second, &budget)
	if !complete || len(candidates.direct) != 1 {
		t.Fatalf("uncached attribute candidates = %+v, complete=%t", candidates, complete)
	}
	if s.runtime.matchCacheUnits != maxMatchCacheUnits {
		t.Fatalf("cache exceeded ceiling: %d", s.runtime.matchCacheUnits)
	}
	if _, ok := s.runtime.attributeCandidates[second]; ok {
		t.Fatal("attribute candidates beyond the ceiling were cached")
	}
}

func TestMatchingContinuesAfterMatchCacheIsFull(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`p{display:none}`, false)
	s.buildSelectorIndex(1, 1)
	s.runtime.cacheMatches = true
	s.runtime.matchCacheUnits = maxMatchCacheUnits
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
	if matches.used != 1_384 {
		t.Fatalf("candidate work = %d, want 128 attribute scans, 128 class scans, 128 token lookups plus 1,000 bucket entries", matches.used)
	}
	repeated := matchBudget{limit: s.limits.MatchWork}
	refs, complete = s.collectCandidates(node, &repeated)
	if !complete || len(refs) != 1_000 || repeated.used != 1_000 {
		t.Fatalf("cached ancestor candidates = %d refs, work=%d, complete=%t", len(refs), repeated.used, complete)
	}
	limited := matchBudget{limit: 100}
	if _, complete := s.collectCandidates(node, &limited); complete || !limited.exhausted {
		t.Fatalf("limited candidate collection completed: %+v", limited)
	}
}

func TestSelectorIndexChargesAndCachesClassTokens(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`.wanted *{display:none}`, false)
	s.buildSelectorIndex(2, 2)
	classes := strings.Repeat("other ", 1_000)
	parent := &html.Node{Type: html.ElementNode, Data: "div", Attr: []html.Attribute{{Key: "class", Val: classes}}}
	node := &html.Node{Type: html.ElementNode, Data: "p", Parent: parent}

	first := matchBudget{limit: s.limits.MatchWork}
	refs, complete := s.collectCandidates(node, &first)
	want := int64(1 + 1 + selectorByteWork(len(classes)) + 1_000)
	if !complete || len(refs) != 0 || first.used != want {
		t.Fatalf("initial class candidates = %d refs, work=%d want=%d, complete=%t", len(refs), first.used, want, complete)
	}
	second := matchBudget{limit: s.limits.MatchWork}
	refs, complete = s.collectCandidates(node, &second)
	if !complete || len(refs) != 0 || second.used != 0 {
		t.Fatalf("cached class candidates = %d refs, work=%d, complete=%t", len(refs), second.used, complete)
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

func BenchmarkDeepMediaRuleStorage(b *testing.B) {
	var source strings.Builder
	for range 127 {
		source.WriteString(`@media all{`)
	}
	for range 9_000 {
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
		if _, err := Analyze(input, limits); err != nil {
			b.Fatal(err)
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
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("CSS nesting limit label = %q", got)
	}
}
