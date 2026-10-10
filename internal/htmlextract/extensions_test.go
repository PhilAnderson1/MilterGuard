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
		{"light colour scheme", `@media (prefers-color-scheme:light){p{display:none}}`, "concealed"},
		{"dark colour scheme", `@media (prefers-color-scheme:dark){p{display:none}}`, "visible"},
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

func TestMediaCasesShareSelectorWorkBudget(t *testing.T) {
	limits := DefaultLimits()
	s := sheet{limits: limits}
	s.parseCSS(`@media(max-width:500px){p{display:none}}@media(min-width:500px){p{display:block}}`, false)
	var firstCaseWork int64
	for ruleIndex := range s.rules {
		rule := &s.rules[ruleIndex]
		for _, selector := range rule.selectors {
			cost := selectorCost(selector.String(), 1, 1, limits.MatchWork)
			rule.costs = append(rule.costs, cost)
			rule.fallbackScopes = append(rule.fallbackScopes, uncertainSelectorScope(selector.String()))
			scopeCost := int64(len(selector.String()) + 1)
			rule.scopeCosts = append(rule.scopeCosts, scopeCost)
		}
		firstCaseWork++ // rule visit, including media-inactive rules
		if rule.mediaState(0, false) != mediaNo {
			firstCaseWork += rule.scopeCosts[0] + rule.costs[0]
		}
	}

	matches := matchBudget{limit: firstCaseWork}
	expressions := expressionBudget{remaining: limits.ExpressionWork}
	node := &xhtml.Node{Type: xhtml.ElementNode, Data: "p"}
	first, _, err := s.elementStyle(node, initial(), initial(), nil, nil, 0, false, &matches, &expressions)
	if err != nil {
		t.Fatal(err)
	}
	if !first[display].Known || first[display].Text != "none" {
		t.Fatalf("first media case = %+v", first[display])
	}
	second, _, err := s.elementStyle(node, initial(), initial(), nil, nil, 1000, false, &matches, &expressions)
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
