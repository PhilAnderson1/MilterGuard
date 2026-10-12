package htmlextract

import (
	"fmt"
	"html"
	"strings"
	"testing"

	xhtml "golang.org/x/net/html"
)

func TestConditionalCases(t *testing.T) {
	cases := []struct{ name, css, want string }{
		{"mobile", `@media screen and (max-width:600px){p{display:none}}`, "client-dependent"},
		{"legacy device width", `@media only screen and (max-device-width:600px),only screen and (max-width:600px){p{display:none}}`, "client-dependent"},
		{"light colour scheme", `@media (prefers-color-scheme:light){p{display:none}}`, "unknown"},
		{"dark colour scheme", `@media (prefers-color-scheme:dark){p{display:none}}`, "unknown"},
		{"colour scheme can reveal", `p{display:none}@media (prefers-color-scheme:dark){p{display:block}}`, "unknown"},
		{"colour scheme overridden", `@media (prefers-color-scheme:dark){p{display:none}}p{display:block}`, "visible"},
		{"colour scheme scoped elsewhere", `@media (prefers-color-scheme:dark){b{display:none}}`, "visible"},
		{"intermediate", `p{display:none}@media (min-width:500px) and (max-width:501px){p{display:block}}`, "client-dependent"},
		{"point", `p{display:none}@media (min-width:500px) and (max-width:500px){p{display:block}}`, "client-dependent"},
		{"all hidden", `@media (max-width:500px){p{display:none}}@media (min-width:500px){p{display:none}}`, "concealed"},
		{"nested", `@media screen{@media (max-width:500px){p{display:none}}}`, "client-dependent"},
		{"comma", `@media print,(max-width:500px){p{display:none}}`, "client-dependent"},
		{"important", `p{display:block!important}@media (max-width:500px){p{display:none}}`, "visible"},
		{"unsupported scoped", `@media (prefers-reduced-motion:reduce){.other{display:none}}`, "visible"},
		{"unsupported applies", `@media (prefers-reduced-motion:reduce){p{display:none}}`, "unknown"},
		{"unsupported overridden", `@media (prefers-reduced-motion:reduce){p{display:none}}p{display:block}`, "visible"},
		{"unsupported ancestor", `@media (orientation:portrait){div{opacity:0}}`, "unknown"},
		{"print unknown", `@media print and (orientation:portrait){p{display:none}}`, "visible"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, `<style>`+c.css+`</style><div><p>T</p></div>`)
			if got := findText(t, in, "T"); got.Label != c.want {
				t.Fatalf("%s: %+v", c.want, got)
			}
		})
	}
	l := DefaultLimits()
	l.MediaCases = 1
	in, e := (processor{Limits: l}).process([]byte(`<style>@media(max-width:500px){p{display:none}}</style><p>T</p><b>U</b>`))
	if e != nil {
		t.Fatal(e)
	}
	if findText(t, in, "T").Label != "unknown" || findText(t, in, "U").Label != "visible" {
		t.Fatal(in)
	}
}

func TestViewingCasesHardCap(t *testing.T) {
	for _, breakpoints := range []int{15, 16} {
		var src strings.Builder
		src.WriteString("<style>")
		for i := 1; i <= breakpoints; i++ {
			fmt.Fprintf(&src, "@media(min-width:%dpx){p{display:none}}", i*100)
		}
		src.WriteString("</style><p>T</p><b>U</b>")
		limits := DefaultLimits()
		limits.MediaCases = 64 // Direct callers cannot raise the ceiling either.
		in, err := (processor{Limits: limits}).process([]byte(src.String()))
		if err != nil {
			t.Fatal(err)
		}
		if breakpoints == 15 {
			if findText(t, in, "T").Label != "client-dependent" {
				t.Fatal(in)
			}
		} else if findText(t, in, "T").Label != "unknown" || findText(t, in, "U").Label != "visible" {
			t.Fatal(in)
		}
	}
}

func TestMediaStateWorkAndPlanningCache(t *testing.T) {
	dense := rule{conditions: []mediaCondition{{
		{bounds: []widthBound{{}, {}, {}}},
		{bounds: []widthBound{{}, {}}},
	}}}
	if got := dense.mediaStateWork(false); got != 9 {
		t.Fatalf("media state work = %d, want 9", got)
	}
	if got := dense.mediaStateWork(true); got != 11 {
		t.Fatalf("fallback media state work = %d, want 11", got)
	}

	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`@media(max-width:500px){p{display:none}}`, false)
	widths, fallback := s.viewingCases(MaxViewingCases)
	if fallback || len(widths) == 0 {
		t.Fatalf("viewing cases = %v, fallback=%t", widths, fallback)
	}
	cacheHit := matchBudget{limit: 0}
	if _, complete := s.mediaStates(widths[0], false, &cacheHit); !complete || cacheHit.used != 0 || cacheHit.exhausted {
		t.Fatalf("planned media state was not cached: %+v", cacheHit)
	}

	cost := s.rules[0].mediaStateWork(true)
	short := matchBudget{limit: cost - 1}
	if _, complete := s.mediaStates(1024, true, &short); complete || !short.exhausted {
		t.Fatalf("fallback media state exceeded its budget: %+v", short)
	}
	enough := matchBudget{limit: cost}
	if _, complete := s.mediaStates(1024, true, &enough); !complete || enough.used != cost || enough.exhausted {
		t.Fatalf("fallback media state was not charged exactly: %+v", enough)
	}
}

func TestMediaCasesShareSelectorWorkBudget(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`@media(max-width:500px){p{display:none}}@media(min-width:500px){p{display:block}}`, false)
	s.buildSelectorIndex(1, 1)
	firstCaseWork := elementTraversalWork + 2 // Element traversal plus both indexed candidates.
	for ruleIndex := range s.rules {
		firstCaseWork += s.rules[ruleIndex].mediaStateWork(false)
		if s.rules[ruleIndex].mediaState(0, false) != mediaNo {
			firstCaseWork += s.rules[ruleIndex].plans[0].cost
			firstCaseWork += int64(len(s.rules[ruleIndex].decls)) * declarationApplyWeight
		}
	}

	matches := matchBudget{limit: firstCaseWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	node := &xhtml.Node{Type: xhtml.ElementNode, Data: "p"}
	first, _, _, _, err := s.elementStyle(node, initial(), initial(), nil, nil, 0, false, selectorMatchContext{}, &matches, &expressions)
	if err != nil {
		t.Fatal(err)
	}
	if !first[display].Known || first[display].Text != "none" {
		t.Fatalf("first media case = %+v", first[display])
	}
	second, _, _, _, err := s.elementStyle(node, initial(), initial(), nil, nil, 1000, false, selectorMatchContext{}, &matches, &expressions)
	if err != nil {
		t.Fatal(err)
	}
	if !matches.exhausted || second[display].Known {
		t.Fatalf("media cases did not share budget: budget=%+v display=%+v", matches, second[display])
	}
}

func TestEmptyClipping(t *testing.T) {
	cases := []struct{ style, want string }{
		{`clip-path:circle(0px)`, "concealed"},
		{`clip-path:inset(50%)`, "concealed"},
		{`clip-path:circle(1px)`, "unknown"},
		{`clip-path:circle(0px);clip-path:none`, "visible"},
		{`clip-path:circle(0px)!important;clip-path:none`, "concealed"},
		{`clip:rect(0px,0px,0px,0px);position:absolute`, "concealed"},
		{`clip:rect(0px,0px,0px,0px);position:fixed`, "concealed"},
		{`clip:rect(0px,0px,0px,0px)`, "visible"},
		{`clip:rect(0px,1px,1px,0px);position:absolute`, "unknown"},
		{`clip-path:circle(0px);display:contents`, "unknown"},
		{`clip-path:circle(2px);display:none`, "concealed"},
	}
	for _, c := range cases {
		t.Run(c.style, func(t *testing.T) {
			in := inspectHTML(t, `<div style="`+c.style+`"><p style="clip-path:none">T</p></div>`)
			if v := findText(t, in, "T"); v.Label != c.want {
				t.Fatalf("want %s: %+v", c.want, v)
			}
		})
	}
	in := inspectHTML(t, `<style>@media(max-width:500px){p{clip-path:circle(0px)}}</style><p>T</p>`)
	if findText(t, in, "T").Label != "client-dependent" {
		t.Fatal(in)
	}
}

func TestClipPathApplicabilityToInlineBoxes(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"default inline span", `<span style="clip-path:circle(0)">T</span>`, "unknown"},
		{"declared inline block element", `<div style="display:inline;clip-path:circle(0)">T</div>`, "unknown"},
		{"inline without clip path", `<span>T</span>`, "visible"},
		{"declared block span", `<span style="display:block;clip-path:circle(0)">T</span>`, "concealed"},
		{"default block element", `<div style="clip-path:circle(0)">T</div>`, "concealed"},
		{"positioned inline element", `<span style="position:absolute;clip-path:circle(0)">T</span>`, "concealed"},
		{"legacy clip remains independent of overflow", `<span style="position:absolute;clip:rect(0,0,0,0)">T</span>`, "concealed"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, test.src)
			if got := findText(t, in, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMSOHideIsClientDependent(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"inline declaration", `<p style="mso-hide:all">T</p>`, "unknown"},
		{"stylesheet declaration", `<style>.outlook-hidden{mso-hide:all}</style><p class="outlook-hidden">T</p>`, "unknown"},
		{"ancestor", `<div style="mso-hide:all"><p>T</p></div>`, "unknown"},
		{"variable", `<p style="--outlook:all;mso-hide:var(--outlook)">T</p>`, "unknown"},
		{"later initial value", `<p style="mso-hide:all;mso-hide:initial">T</p>`, "visible"},
		{"important value", `<p style="mso-hide:all!important;mso-hide:initial">T</p>`, "unknown"},
		{"universally concealed", `<p style="display:none;mso-hide:all">T</p>`, "concealed"},
		{"invalid variable", `<p style="mso-hide:var(--missing)">T</p>`, "visible"},
		{"unsupported value", `<p style="mso-hide:future(1)">T</p>`, "unknown"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, test.src)
			if got := findText(t, in, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLayoutHidingPatternsAreVisibilityUncertain(t *testing.T) {
	cases := []struct{ name, style, want string }{
		{"zero width", `overflow:hidden;width:0`, "unknown"},
		{"zero height", `overflow:clip;height:0px`, "unknown"},
		{"zero max width", `overflow:hidden;max-width:0`, "unknown"},
		{"zero max height", `overflow:hidden;max-height:0%`, "unknown"},
		{"subpixel height", `overflow:hidden;height:.001px`, "unknown"},
		{"tiny width", `overflow:hidden;width:1e-30px`, "unknown"},
		{"subpixel max height", `overflow:hidden;max-height:.0001px`, "unknown"},
		{"one pixel clipped width", `overflow:hidden;width:1px`, "unknown"},
		{"one pixel clipped height", `overflow:hidden;height:1px`, "unknown"},
		{"two-axis vertical clipping", `overflow:visible hidden;height:0`, "unknown"},
		{"two-axis horizontal clipping", `overflow:hidden visible;width:0`, "unknown"},
		{"absolute left", `position:absolute;left:-1000px`, "unknown"},
		{"fixed top", `position:fixed;top:-9999px`, "unknown"},
		{"absolute relative-unit left", `position:absolute;left:-3000em`, "unknown"},
		{"overflowing absolute left", `position:absolute;left:-1e999px`, "unknown"},
		{"fixed bottom", `position:fixed;bottom:-3000px`, "unknown"},
		{"absolute right", `position:absolute;right:-3000px`, "unknown"},
		{"negative indent", `text-indent:-1000px`, "unknown"},
		{"percentage indent", `text-indent:-500%`, "unknown"},
		{"overflowing indent", `text-indent:-1e999px`, "unknown"},
		{"calculated overflowing offset", `position:absolute;left:calc(-1px * 1e400)`, "unknown"},
		{"extreme negative margin", `margin-left:-9999px`, "unknown"},
		{"extreme relative margin", `margin-top:-100vh`, "unknown"},
		{"extreme margin shorthand", `margin:0 0 0 -9999px`, "unknown"},
		{"unresolved margin shorthand", `margin:var(--possibly-extreme)`, "unknown"},
		{"zero zoom", `zoom:0`, "unknown"},
		{"tiny zoom", `zoom:.001`, "unknown"},
		{"tiny percentage zoom", `zoom:1%`, "unknown"},
		{"dimension without clipping", `width:0;height:0`, "visible"},
		{"clipping with readable dimension", `overflow:hidden;width:2px`, "visible"},
		{"contextual subunit dimension", `overflow:hidden;height:.001%`, "visible"},
		{"ordinary responsive maximum", `overflow:hidden;max-width:100%;height:auto`, "visible"},
		{"wrong-axis clipping", `overflow:hidden visible;height:0`, "visible"},
		{"invalid overflow ignored", `overflow:hidden;height:0;overflow:banana`, "unknown"},
		{"static offset", `position:static;left:-9999px`, "visible"},
		{"ordinary offset", `position:absolute;left:-999px`, "visible"},
		{"ordinary relative offset", `position:absolute;left:-2em`, "visible"},
		{"ordinary negative margin", `margin-left:-10px`, "visible"},
		{"overridden margin", `margin-left:-9999px;margin-left:0`, "visible"},
		{"shorthand overrides margin", `margin-left:-9999px;margin:0`, "visible"},
		{"ordinary zoom", `zoom:1`, "visible"},
		{"normal zoom", `zoom:normal`, "visible"},
		{"overridden zoom", `zoom:0;zoom:100%`, "visible"},
		{"overridden width", `overflow:hidden;width:0;width:auto`, "visible"},
		{"overridden overflow", `overflow:hidden;width:0;overflow:visible`, "visible"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, `<div style="`+test.style+`"><span>T</span></div>`)
			if got := findText(t, in, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}

	in := inspectHTML(t, `<style>.offscreen{position:absolute;left:-9999px}.offscreen{left:0}</style><div class="offscreen">T</div>`)
	if got := findText(t, in, "T").Label; got != "visible" {
		t.Fatalf("stylesheet cascade label = %q, want visible", got)
	}
	in = inspectHTML(t, `<style>@media(max-width:500px){p{overflow:hidden;width:0}}</style><p>T</p>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("media-dependent layout label = %q, want unknown", got)
	}
	in = inspectHTML(t, `<p style="--zero:0;overflow:hidden;width:var(--zero)">T</p>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("variable layout label = %q, want unknown", got)
	}
}

func TestUncertainLayoutWinnerCannotProduceTrustedReveal(t *testing.T) {
	for _, test := range []struct {
		name, css string
	}{
		{
			"environment media condition",
			`p{overflow:hidden;height:0}@media(prefers-color-scheme:dark){p{overflow:visible}}`,
		},
		{
			"unsupported selector",
			`p{overflow:hidden;height:0}p:has(b){overflow:visible}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, `<style>`+test.css+`</style><p>T</p>`)
			if got := findText(t, in, "T").Label; got != "unknown" {
				t.Fatalf("uncertain layout reveal label = %q, want unknown", got)
			}
		})
	}

	in := inspectHTML(t, `<style>p{overflow:hidden;height:0}@media(prefers-color-scheme:dark){p{overflow:visible}}p{overflow:visible}</style><p>T</p>`)
	if got := findText(t, in, "T").Label; got != "visible" {
		t.Fatalf("definite later layout override label = %q, want visible", got)
	}

	limits := DefaultLimits()
	limits.MediaCases = 1
	in, err := (processor{Limits: limits}).process([]byte(`<style>p{overflow:hidden;height:0}@media(max-width:500px){p{overflow:visible}}</style><p>T</p>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("fallback media layout reveal label = %q, want unknown", got)
	}
}

func TestVariables(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"root", `<style>:root{--Hidden:none}p{display:var(--Hidden)}</style><p>T</p>`, "concealed"},
		{"case sensitive", `<p style="--X:none;display:var(--x,block)">T</p>`, "visible"},
		{"inherit", `<div style="--x:none"><p style="display:var(--x)">T</p></div>`, "concealed"},
		{"local", `<div style="--x:none"><p style="--x:block;display:var(--x)">T</p></div>`, "visible"},
		{"computed inheritance", `<div style="--a:var(--b);--b:none"><p style="--b:block;display:var(--a)">T</p></div>`, "concealed"},
		{"initial resets", `<div style="--x:none"><p style="--x:initial;display:var(--x,block)">T</p></div>`, "visible"},
		{"unset inherits", `<div style="--x:none"><p style="--x:unset;display:var(--x)">T</p></div>`, "concealed"},
		{"important", `<style>p{--x:none!important}</style><p style="--x:block;display:var(--x)">T</p>`, "concealed"},
		{"nested fallback", `<p style="display:var(--missing,var(--other,none))">T</p>`, "concealed"},
		{"invalid winner", `<p style="display:none;display:var(--missing)">T</p>`, "visible"},
		{"invalid final", `<p style="--x:banana;display:none;display:var(--x)">T</p>`, "visible"},
		{"empty fallback", `<p style="display:none;display:var(--missing,)">T</p>`, "visible"},
		{"empty definition", `<p style="--x:;display:none;display:var(--x,none)">T</p>`, "visible"},
		{"self cycle fallback", `<p style="--x:var(--x);display:var(--x,none)">T</p>`, "concealed"},
		{"cycle fallback dependencies", `<p style="--a:var(--b);--b:var(--c,var(--a));--c:none;display:var(--a,block)">T</p>`, "visible"},
		{"consumer fallback from cycle", `<p style="--a:var(--a);--b:var(--a,none);display:var(--b)">T</p>`, "concealed"},
		{"boundary no concatenation", `<p style="--n:0;font-size:var(--n)px">T</p>`, "visible"},
		{"background shorthand", `<p style="--bg:white;background:var(--bg);color:white">T</p>`, "concealed"},
		{"escaped direct reference", `<p style="--hidden:none;display:var(\2d\2d hidden)">T</p>`, "concealed"},
		{"escaped transitive reference", `<p style="background:white;color:black;--white:white;--x:var(\2d\2d white);color:var(--x)">T</p>`, "concealed"},
		{"escaped definition name", `<p style="--\78:none;display:var(--x)">T</p>`, "concealed"},
		{"escaped reference remains case sensitive", `<p style="--X:none;display:var(\2d\2d x,block)">T</p>`, "visible"},
		{"escaped missing reference fallback", `<p style="display:var(\2d\2d missing,none)">T</p>`, "concealed"},
		{"escaped cycle dependency", `<p style="--a:var(\2d\2d b);--b:var(--a);display:var(--a,none)">T</p>`, "concealed"},
		{"string not substituted", `<p style="--x:'var(--missing)';display:var(--x,none)">T</p>`, "visible"},
		{"media variable", `<style>:root{--x:none}@media(max-width:500px){:root{--x:block}}p{display:var(--x)}</style><p>T</p>`, "client-dependent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := inspectHTML(t, c.src)
			if v := findText(t, in, "T"); v.Label != c.want {
				t.Fatalf("want %s: %+v", c.want, v)
			}
		})
	}
}

func TestMalformedCustomPropertyVariableDoesNotWinCascade(t *testing.T) {
	for _, src := range []string{
		`<p style="--x:hidden;--x:var(1);visibility:var(--x)">T</p>`,
		`<p style="--x:hidden;--x:var(foo);visibility:var(--x)">T</p>`,
		`<p style="--x:hidden;--x:var(--missing,var(1));visibility:var(--x)">T</p>`,
	} {
		in := inspectHTML(t, src)
		if got := findText(t, in, "T").Label; got != "concealed" {
			t.Errorf("malformed custom property label = %q for %s", got, src)
		}
	}

	s := sheet{limits: DefaultLimits()}
	if declarations := s.declarations("--x", "var(1)"); len(declarations) != 0 {
		t.Fatalf("malformed custom property was retained: %+v", declarations)
	}
	if declarations := s.declarations("visibility", "var(1)"); len(declarations) != 1 {
		t.Fatalf("ordinary property lost IACVT declaration: %+v", declarations)
	}
	if declarations := s.declarations("--x", "var(--missing"); len(declarations) != 1 {
		t.Fatalf("implicitly closed var() was rejected: %+v", declarations)
	}
}

func TestVariableFunctionValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{"reference", `var(--x)`, true},
		{"implicit close", `var(--x`, true},
		{"nested fallback", `var(--x,var(--y,var(--z,none)))`, true},
		{"function fallback", `var(--x,rgb(var(--r),0,0))`, true},
		{"empty fallback", `var(--x,)`, true},
		{"additional fallback commas", `var(--x,one,two)`, true},
		{"empty name", `var()`, false},
		{"ordinary identifier", `var(name)`, false},
		{"bare custom prefix", `var(--)`, false},
		{"two name tokens", `var(--x --y)`, false},
		{"function as name", `var(calc(--x))`, false},
		{"malformed nested fallback", `var(--x,var(name))`, false},
		{"malformed nested in function", `calc(var(name))`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tokens, status := lexValue(test.value)
			if status != 1 {
				t.Fatalf("lexing status = %d", status)
			}
			if got := validVariableFunctions(tokens); got != test.valid {
				t.Fatalf("validVariableFunctions(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestVariableFunctionValidationIsBoundedForDeepFallbacks(t *testing.T) {
	const depth = 1_000
	value := strings.Repeat(`var(--x,`, depth) + `none` + strings.Repeat(`)`, depth)
	tokens, status := lexValue(value)
	if status != 1 || len(tokens) > maxValueTokens || len(value) > maxValueBytes {
		t.Fatalf("invalid deep-fallback fixture: bytes=%d tokens=%d status=%d", len(value), len(tokens), status)
	}
	if !validVariableFunctions(tokens) {
		t.Fatal("valid deep fallback was rejected")
	}
}

func TestDeclarationValueTokensAreCached(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	ds := s.declarations("--payload", "var(--missing, none)")
	if len(ds) != 1 || !ds[0].tokensReady || ds[0].valueStatus != 1 || len(ds[0].valueTokens) == 0 {
		t.Fatalf("declaration was not prepared: %+v", ds)
	}

	// Cascading copies declarations. Resolution must use the immutable token
	// stream prepared by the parser rather than lexing the value again for each
	// element.
	d := ds[0]
	d.value = strings.Repeat("x", maxValueBytes+1)
	budget := expressionBudget{remaining: 100}
	scope := buildVariables(nil, map[string]declaration{"--payload": d}, &budget)
	if got := scope.get("--payload"); got.status != 1 || got.text != "none" {
		t.Fatalf("cached value was not used: %+v", got)
	}
}

func TestMalformedValueSuffixIsNotTruncated(t *testing.T) {
	in := inspectHTML(t, `<p style="--x:none;display:block;display:var(--x)<junk>">T</p>`)
	if got := findText(t, in, "T").Label; got == "concealed" {
		t.Fatalf("malformed suffix was truncated to concealed content")
	}

	in = inspectHTML(t, `<p style='display:block;display:none"'>T</p>`)
	if got := findText(t, in, "T").Label; got == "concealed" {
		t.Fatalf("unterminated string was truncated to concealed content")
	}

	tokens, status := lexValue(`var(--x)<junk>`)
	if status != 1 || tokenText(tokens) != `var(--x)<junk>` {
		t.Fatalf("tokens = %+v, status = %d", tokens, status)
	}
}

func TestExpressionBudgetStopsCachedVariableTraversal(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	d := s.declarations("--payload", "var(--a) var(--b) var(--c)")[0]
	budget := expressionBudget{remaining: 1}
	scope := buildVariables(nil, map[string]declaration{"--payload": d}, &budget)
	if !budget.exhausted {
		t.Fatal("expression budget was not exhausted")
	}
	if got := scope.get("--payload"); got.status != 2 {
		t.Fatalf("value after budget exhaustion = %+v", got)
	}
}

func TestArithmetic(t *testing.T) {
	cases := []struct {
		property string
		want     float64
		known    bool
	}{
		{`font-size:calc(10px - 10px)`, 0, true},
		{`font-size:calc(1pt * 3)`, 4, true},
		{`font-size:calc(25% + .25em)`, 8, true},
		{`font-size:calc(1rem / 8)`, 2, true},
		{`font-size:max(1px,min(2px,3px))`, 2, true},
		{`font-size:clamp(10px,1px,2px)`, 10, true},
		{`font-size:calc(-2px)`, 0, true},
		{`font-size:calc(2 * (2px + 1px))`, 6, true},
		{`font-size:calc(1vw - 1vw)`, 0, false},
		{`font-size:calc(1px / 0)`, 0, false},
		{`opacity:calc(1 - 1)`, 0, true},
		{`opacity:calc(50% * .02)`, .01, true},
		{`opacity:clamp(0,.5,1)`, .5, true},
		{`opacity:calc(1e-2 * 2)`, .02, true},
		{`opacity:calc(0 / 0)`, 0, false},
	}
	for _, c := range cases {
		t.Run(c.property, func(t *testing.T) {
			in := inspectHTML(t, `<p style="`+c.property+`">T</p>`)
			v := textStyle(findText(t, in, "T"), strings.Split(c.property, ":")[0])
			if v.Known != c.known {
				t.Fatal(v)
			}
			if c.known {
				near(t, v.Number, c.want, 1e-10)
			}
		})
	}
	for _, s := range []string{`calc(1px+ 2px)`, `calc(1px +2px)`, `calc(1px + 1)`, `calc(0)`, `calc(1px,2px)`} {
		in := inspectHTML(t, `<p style="font-size:10px;font-size:`+s+`">T</p>`)
		if v := textStyle(findText(t, in, "T"), "font-size"); v.Number != 10 || !v.Known {
			t.Fatal(s, v)
		}
	}
	in := inspectHTML(t, `<p style="--n:10px;font-size:calc(var(--n) - 10px)">T</p>`)
	if findText(t, in, "T").Label != "concealed" {
		t.Fatal(in)
	}
}

func TestExpressionLimitsAndDeterminism(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<p style="--v0:none;`)
	for i := 1; i < 30; i++ {
		fmt.Fprintf(&b, "--v%d:var(--v%d) var(--v%d);", i, i-1, i-1)
	}
	b.WriteString(`display:var(--v29)">T</p>`)
	for i := 0; i < 10; i++ {
		in, e := (processor{Limits: DefaultLimits()}).process([]byte(b.String()))
		if e != nil {
			t.Fatal(e)
		}
		if findText(t, in, "T").Label != "unknown" {
			t.Fatal(in)
		}
	}
	in := inspectHTML(t, `<p style="opacity:`+strings.Repeat("calc(", 40)+"1"+strings.Repeat(")", 40)+`">T</p>`)
	if findText(t, in, "T").Label != "unknown" {
		t.Fatal(in)
	}
}

func FuzzBoundedStyles(f *testing.F) {
	for _, s := range []string{"display:none", "--x:var(--x);display:var(--x,none)", "font-size:calc(1px - 1px)", "clip-path:circle(0px)", "--x:'var(--y)';opacity:var(--x)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		// Quoted HTML entities keep fuzzed CSS within a single attribute.
		src := `<p style="` + html.EscapeString(s) + `">T</p>`
		l := DefaultLimits()
		l.ExpressionWork = 10000
		_, _ = (processor{Limits: l}).process([]byte(src))
	})
}
