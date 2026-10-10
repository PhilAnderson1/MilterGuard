package htmlextract

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func inspectHTML(t *testing.T, src string) (Inspection, int) {
	t.Helper()
	// Existing four-property policy tests supply an explicit canvas. New colour
	// tests below deliberately do not inject a background.
	p := Processor{Limits: DefaultLimits()}
	src = `<style>html{background-color:white}</style>` + src
	r, e := p.Process([]byte(src), "styles", true)
	if e != nil {
		t.Fatal(e)
	}
	return r.Inspection.(Inspection), r.Uncertainties
}
func findText(t *testing.T, in Inspection, text string) Text {
	t.Helper()
	for _, v := range in.Text {
		if v.Text == text {
			return v
		}
	}
	t.Fatalf("missing %q in %+v", text, in.Text)
	return Text{}
}
func TestSelectors(t *testing.T) {
	for _, sel := range []string{"*", "p", ".x", "#target", "[data-x]", "[data-x=a]", "div p", "div > p", "i + p", "i ~ p", "p:not(.other)", "#absent,p"} {
		t.Run(sel, func(t *testing.T) {
			in, _ := inspectHTML(t, `<div><i></i><p id="target" class="x" data-x="a">T</p></div><style>`+sel+`{display:none}</style>`)
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
			in, _ := inspectHTML(t, `<p id=t class=c style="`+c.inline+`">T</p><style>`+c.css+`</style>`)
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
		in, _ := inspectHTML(t, `<span style="`+style+`">T</span>`)
		if got := findText(t, in, "T").Label; got != "concealed" {
			t.Errorf("style %q label = %q, want concealed", style, got)
		}
	}
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
			in, _ := inspectHTML(t, c.src)
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
	in, _ := inspectHTML(t, `<div style="color:red;background-color:blue"><p style="background-color:currentColor">T</p><p>U</p></div>`)
	v := findText(t, in, "T")
	if v.Style["color"].Text != "rgba(255,0,0,1)" || v.Style["background-color"].Text != v.Style["color"].Text {
		t.Fatal(v)
	}
	if findText(t, in, "U").Style["background-color"].Text != "rgba(0,0,0,0)" {
		t.Fatal(in)
	}
}
func TestConditionsAndRecovery(t *testing.T) {
	for _, c := range []struct{ css, want string }{{"@media all{p{display:none}}", "concealed"}, {"@media screen{p{display:none}}", "concealed"}, {"@media print{p{display:none}}", "visible"}, {"@media screen and (min-width:1px){p{display:none}}", "client-dependent"}, {"@supports(display:grid){p{display:none}}", "unknown"}, {"p:hover{display:none}", "visible"}, {"p::before{display:none}", "unknown"}, {"p{broken;display:none}", "concealed"}, {"p{display:banana}p{display:none}", "concealed"}, {"@media print{@supports(display:grid){p{display:none}}}", "visible"}} {
		t.Run(c.css, func(t *testing.T) {
			in, _ := inspectHTML(t, `<p>T</p><style>`+c.css+`</style>`)
			if got := findText(t, in, "T").Label; got != c.want {
				t.Fatalf("%s want %s %+v", got, c.want, in)
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
		in, _ := inspectHTML(t, src)
		if got := findText(t, in, "T").Label; got != "visible" {
			t.Errorf("%q label = %q", src, got)
		}
	}
}
func TestUnsupportedSelectorUncertaintyIsLimitedToRelevantDeclarations(t *testing.T) {
	in, _ := inspectHTML(t, `<style>p::before{display:none}</style><p>T</p><div>U</div>`)
	if got := findText(t, in, "T").Label; got != "unknown" {
		t.Fatalf("label = %q", got)
	}
	if got := findText(t, in, "U").Label; got != "visible" {
		t.Fatalf("unrelated label = %q", got)
	}

	in, _ = inspectHTML(t, `<style>div:has(.x) .offer{visibility:hidden}.other:has(.x){opacity:0}</style><div class="offer">offer</div><div class="other">other</div><div>ordinary</div>`)
	for text, want := range map[string]string{"offer": "unknown", "other": "unknown", "ordinary": "visible"} {
		if got := findText(t, in, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
	}
}

func TestAttributeSelectorOperatorsAreEvaluated(t *testing.T) {
	in, _ := inspectHTML(t, `<style>[class~="mobile"]{display:none}[style*="margin: 16px"]{font-size:100%}[data-prefix^="yes"]{visibility:hidden}</style><p class="mobile">hidden</p><p style="margin: 16px 0">ordinary</p><p data-prefix="no">also ordinary</p>`)
	if got := findText(t, in, "hidden").Label; got != "concealed" {
		t.Fatalf("attribute word selector label = %q", got)
	}
	for _, value := range []string{"ordinary", "also ordinary"} {
		if got := findText(t, in, value).Label; got != "visible" {
			t.Errorf("%q label = %q", value, got)
		}
	}
}

func TestSelectorWorkLimitRetainsScopedText(t *testing.T) {
	limits := DefaultLimits()
	limits.MatchWork = 2
	result, err := (Processor{Limits: limits}).Process([]byte(`<style>p{display:none}</style><p>T</p><div>U</div>`), "styles", true)
	if err != nil {
		t.Fatal(err)
	}
	inspection := result.Inspection.(Inspection)
	if got := findText(t, inspection, "T").Label; got != "unknown" {
		t.Fatalf("affected text label = %q", got)
	}
	if got := findText(t, inspection, "U").Label; got != "visible" {
		t.Fatalf("unaffected text label = %q", got)
	}
}
func TestTreeEvidence(t *testing.T) {
	in, _ := inspectHTML(t, `<p>&amp;lt;b&amp;gt;&#x200b;&lt;style&gt;hidden&lt;/style&gt;</p><script>script</script><style>p{color:red}</style><!--comment--><template>inert</template><iframe>fallback</iframe>`)
	v := findText(t, in, "&lt;b&gt;\u200b<style>hidden</style>")
	if v.Label != "visible" {
		t.Fatal(v)
	}
	if len(in.Text) != 1 {
		t.Fatal(in)
	}
	in, _ = inspectHTML(t, `<div style="display:none"><table>foster<tr><td>cell</table></div><p>end`)
	if findText(t, in, "foster").Label != "concealed" || findText(t, in, "cell").Label != "concealed" || findText(t, in, "end").Label != "visible" {
		t.Fatal(in)
	}
	in, _ = inspectHTML(t, `<table style="display:none">foster<tr><td>cell</td></tr></table>`)
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
			p := Processor{Limits: DefaultLimits()}
			a, e := p.Process(b, "styles", false)
			if e != nil {
				t.Fatal(e)
			}
			v, e := p.Process(b, "styles", true)
			if e != nil || a.Checksum != v.Checksum {
				t.Fatal(e, a, v)
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
			src = `<style>p,i,b,u,div{display:none}</style>`
		case "work":
			l.MatchWork = 2
			src = `<style>*{display:none}</style><p>T</p>`
		case "diagnostics":
			l.Diagnostics = 1
			src = `<p style="font-size:2ex;filter:blur(1px)">T</p>`
		case "malformed":
			src = `<style>` + strings.Repeat(`x{bad;;;;color:;}`, 1000) + `</style><p>T</p>`
		case "transitions":
			src = strings.Repeat(`<p style="visibility:hidden"><span style="visibility:visible">T</span></p>`, 1000)
		}
		_, e := (Processor{Limits: l}).Process([]byte(src), "styles", false)
		expected := name != "malformed" && name != "transitions" && name != "work"
		if expected != (e != nil) {
			t.Fatal(name, e)
		}
		return
	}
	for _, name := range []string{"depth", "attribute", "rules", "selectors", "work", "diagnostics", "malformed", "transitions"} {
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
func TestInspectionJSON(t *testing.T) {
	in, _ := inspectHTML(t, "<p>T</p>")
	b, e := json.Marshal(in)
	if e != nil || !bytes.Contains(b, []byte(`"body_text"`)) {
		t.Fatal(e, string(b))
	}
}
func BenchmarkLargest(b *testing.B) {
	src := []byte(`<style>.quiet{opacity:.005}</style><p>` + strings.Repeat(`<span class="quiet">padding</span> visible `, 24000) + `</p>`)
	p := Processor{Limits: DefaultLimits()}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := p.Process(src, "styles", false); e != nil {
			b.Fatal(e)
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
			r, e := (Processor{Limits: DefaultLimits()}).Process(b, "styles", true)
			if e != nil {
				t.Fatal(e)
			}
			var text []string
			for _, v := range r.Inspection.(Inspection).Text {
				if strings.TrimSpace(v.Text) != "" {
					text = append(text, strings.TrimSpace(v.Text)+":"+v.Label)
				}
			}
			if strings.Join(text, "|") != c.want {
				t.Fatal(text)
			}
		})
	}
}
func TestPropertyUncertainty(t *testing.T) {
	in, _ := inspectHTML(t, `<div style="color:lab(10% 2 3);font-size:2ex;display:none"><p style="font-size:16px">T</p></div><p style="color:banana;font-size:banana;background-color:lab(10% 2 3)">U</p>`)
	v := findText(t, in, "T")
	if v.Label != "concealed" || v.Style["color"].Known || !v.Style["font-size"].Known {
		t.Fatal(v)
	}
	v = findText(t, in, "U")
	if !v.Style["color"].Known || !v.Style["font-size"].Known || v.Style["background-color"].Known {
		t.Fatal(v)
	}
}

func TestAdditionalBoundsAndUnsupportedWinners(t *testing.T) {
	for _, property := range []string{"opacity:0;opacity:sin(1)", "display:none;display:ruby", "display:none;display:run-in"} {
		in, _ := inspectHTML(t, `<p style="`+property+`">T</p>`)
		if findText(t, in, "T").Label != "unknown" {
			t.Fatal(property, in)
		}
	}
	for _, c := range []struct {
		src    string
		limits Limits
	}{
		{"<style>" + strings.Repeat("@media screen{", 200) + strings.Repeat("}", 200) + "</style>", DefaultLimits()},
	} {
		_, e := (Processor{Limits: c.limits}).Process([]byte(c.src), "styles", false)
		if e == nil || !strings.Contains(e.Error(), "limit:") {
			t.Fatal(e)
		}
	}
}
