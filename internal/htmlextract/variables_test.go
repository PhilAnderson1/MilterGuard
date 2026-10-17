package htmlextract

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

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
		{"square block closer in foreground fallback", `<div style="background:#000;color:#fff"><p style="--a:#000;color:var(--a,[x)])">T</p></div>`, "concealed"},
		{"curly block closer in foreground fallback", `<div style="background:#000;color:#fff"><p style="--a:#000;color:var(--a,{x)})">T</p></div>`, "concealed"},
		{"square block closer in background fallback", `<div style="background:#000;color:#fff"><p style="--bg:#fff;background:var(--bg,[x)])">T</p></div>`, "concealed"},
		{"curly block closer in background fallback", `<div style="background:#000;color:#fff"><p style="--bg:#fff;background:var(--bg,{x)})">T</p></div>`, "concealed"},
		{"square block closer in stylesheet variable", `<style>div{background:#000;color:#fff}p{--a:#000;color:var(--a,[x)])}</style><div><p>T</p></div>`, "concealed"},
		{"curly block closer in stylesheet variable", `<style>div{background:#000;color:#fff}p{--a:#000;color:var(--a,{x)})}</style><div><p>T</p></div>`, "concealed"},
		{"escaped direct reference", `<p style="--hidden:none;display:var(\2d\2d hidden)">T</p>`, "concealed"},
		{"escaped transitive reference", `<p style="background:white;color:black;--white:white;--x:var(\2d\2d white);color:var(--x)">T</p>`, "concealed"},
		{"escaped definition name", `<p style="--\78:none;display:var(--x)">T</p>`, "concealed"},
		{"escaped initial dashes preserve uppercase name", `<p style="\2d\2dX:block;display:var(--X,none)">T</p>`, "visible"},
		{"escaped initial dashes remain case sensitive", `<p style="\2d\2dX:none;display:var(--x,block)">T</p>`, "visible"},
		{"escaped stylesheet definition preserves uppercase name", `<style>p{\2d\2dX:block;display:var(--X,none)}</style><p>T</p>`, "visible"},
		{"escaped colon remains in definition name", `<p style="--x\:Y:none;display:var(--x\:Y)">T</p>`, "concealed"},
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

func TestCSSWhitespaceIsNotUnicodeWhitespace(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"NBSP after background colour", `<span style="color:#fff;background:black ">T</span>`, "concealed"},
		{"ideographic space after background colour", `<span style="color:#fff;background:black　">T</span>`, "concealed"},
		{"vertical tab after visibility", "<span style=\"visibility:hidden\v\">T</span>", "visible"},
		{"vertical tab after font size", "<span style=\"font-size:0px\v\">T</span>", "visible"},
		{"vertical tab after opacity", "<span style=\"opacity:0\v\">T</span>", "visible"},
		{"NBSP after display value", `<span style="display:none;display:block ">T</span>`, "concealed"},
		{"NBSP is not a colour component separator", `<span style="background:#fff;color:rgb(255 255 255)">T</span>`, "visible"},
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
			tokens, status := lexValue(test.value, nil)
			if status != valueResolved {
				t.Fatalf("lexing status = %d", status)
			}
			if got := validVariableFunctions(tokens); got != test.valid {
				t.Fatalf("validVariableFunctions(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
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

	tokens, status := lexValue(`var(--x)<junk>`, nil)
	if status != valueResolved || tokenText(tokens) != `var(--x)<junk>` {
		t.Fatalf("tokens = %+v, status = %d", tokens, status)
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
		{`font-size:calc(.05pc)`, .8, true},
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

func TestAbsoluteLengthUnitsDetectTinyText(t *testing.T) {
	for _, size := range []string{".05pc", ".02cm", ".2mm", ".01in", "1q", "calc(.05pc)"} {
		t.Run(size, func(t *testing.T) {
			document := inspectHTML(t, `<p style="font-size:`+size+`">T</p>`)
			text := findText(t, document, "T")
			if text.Label != "concealed" || strings.Join(text.ConcealmentReasons, ",") != "font-size" {
				t.Fatalf("font-size %s = %+v, want concealed by font-size", size, text)
			}
		})
	}
}

func TestVariableExpansionUsesSharedMemoryBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<p style="--v0:none;`)
	for i := 1; i < 30; i++ {
		fmt.Fprintf(&b, "--v%d:var(--v%d) var(--v%d);", i, i-1, i-1)
	}
	b.WriteString(`display:var(--v29)">T</p>`)
	limits := DefaultLimits()
	limits.MemoryBytes = 1 << 20
	document, err := (processor{Limits: limits}).process([]byte(b.String()))
	if err == nil || !strings.Contains(err.Error(), "memory bytes") {
		t.Fatalf("document=%+v err=%v", document, err)
	}
	if document.Usage.MemoryBytes != limits.MemoryBytes {
		t.Fatalf("memory usage=%d want=%d", document.Usage.MemoryBytes, limits.MemoryBytes)
	}
}

func TestExpandedValueLexingUsesSharedResourceBudget(t *testing.T) {
	memory := resourceguard.NewMemory(8 << 10)
	budget := &cpuGuard{memory: memory}
	if _, status := lexValue(strings.Repeat("()", 1_000), budget); status != valueUnsupported {
		t.Fatalf("status=%v, want valueUnsupported", status)
	}
	if !memory.Exhausted() {
		t.Fatal("token-dense value did not exhaust the shared memory budget")
	}

	stops := 0
	budget = &cpuGuard{shouldStop: func() bool {
		stops++
		return true
	}}
	if _, status := lexValue(strings.Repeat("()", 1_000), budget); status != valueUnsupported {
		t.Fatalf("CPU-stopped status=%v, want valueUnsupported", status)
	}
	if stops == 0 || !budget.stopped {
		t.Fatalf("CPU stop callback calls=%d stopped=%v", stops, budget.stopped)
	}
}

func TestCSSValueRecursionLimits(t *testing.T) {
	mathValue := strings.Repeat("calc(", maxCSSValueDepth+1) + "1px" + strings.Repeat(")", maxCSSValueDepth+1)
	if _, status := evalMath(fontSize, mathValue, &initialStyle, &initialStyle, &cpuGuard{}); status != valueUnsupported {
		t.Fatalf("deep math status=%v, want valueUnsupported", status)
	}
	if value := substituteTokens(nil, nil, &cpuGuard{}, maxCSSValueDepth); value.status != valueUnsupported {
		t.Fatalf("deep variable substitution status=%v, want valueUnsupported", value.status)
	}
}

func TestVariableExpandedShorthandLexingCannotEscapeMemoryBudget(t *testing.T) {
	var cssText strings.Builder
	cssText.WriteString(`div{--v0:`)
	cssText.WriteString(strings.Repeat("(", 64))
	cssText.WriteString(`red`)
	cssText.WriteString(strings.Repeat(")", 64))
	cssText.WriteByte(';')
	for i := 1; i <= 10; i++ {
		fmt.Fprintf(&cssText, "--v%d:var(--v%d) var(--v%d);", i, i-1, i-1)
	}
	fmt.Fprintf(&cssText, "background:var(--v10)}")
	input := []byte(`<style>` + cssText.String() + `</style><div>T</div>`)
	limits := DefaultLimits()
	limits.MemoryBytes = 4 << 20
	document, err := (processor{Limits: limits}).process(input)
	if err == nil || !strings.Contains(err.Error(), "memory bytes") {
		t.Fatalf("document=%+v err=%v", document, err)
	}
	if document.Usage.MemoryBytes != limits.MemoryBytes {
		t.Fatalf("memory usage=%d want=%d", document.Usage.MemoryBytes, limits.MemoryBytes)
	}
}
