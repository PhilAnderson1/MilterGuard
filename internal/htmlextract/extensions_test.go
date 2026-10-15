package htmlextract

import (
	"fmt"
	"strings"
	"testing"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

func TestCanonicalLightColourSchemeVisibility(t *testing.T) {
	cases := []struct{ name, css, want string }{
		{"visible despite dark colour", `p{color:black}@media(prefers-color-scheme:dark){p{color:white}}`, "visible"},
		{"dark colour can reveal", `p{color:white;background:white}@media(prefers-color-scheme:dark){p{color:black}}`, "unknown"},
		{"dark display can reveal", `p{display:none}@media(prefers-color-scheme:dark){p{display:block}}`, "unknown"},
		{"unrelated dark colour cannot reveal display", `p{display:none}@media(prefers-color-scheme:dark){p{color:white}}`, "concealed"},
		{"one changed property can reveal multiply hidden text in opacity-ignoring clients", `p{display:none;opacity:0}@media(prefers-color-scheme:dark){p{display:block}}`, "unknown"},
		{"dark colour variable cannot reveal display", `p{display:none;color:var(--ink,black)}@media(prefers-color-scheme:dark){:root{--ink:white}}`, "concealed"},
		{"dark display variable can reveal", `p{display:var(--show,none)}@media(prefers-color-scheme:dark){:root{--show:block}}`, "unknown"},
		{"inherited dark display variable can reveal", `:root{--show:none}body{--show:inherit}p{display:var(--show)}@media(prefers-color-scheme:dark){:root{--show:block}}`, "unknown"},
		{"dark colour variable can reveal matching colour", `p{color:var(--ink,white);background:white}@media(prefers-color-scheme:dark){:root{--ink:black}}`, "unknown"},
		{"contradictory nested schemes never apply", `p{display:none}@media(prefers-color-scheme:light){@media(prefers-color-scheme:dark){p{display:block}}}`, "concealed"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, `<style>`+test.css+`</style><p>T</p>`)
			if got := findText(t, in, "T"); got.Label != test.want {
				t.Fatalf("label = %q, want %q", got.Label, test.want)
			}
		})
	}
}

func independentMediaState(frame *conditionFrame, width float64, fallback bool) int {
	light, dark := mediaYes, mediaYes
	for ; frame != nil; frame = frame.parent {
		frameLight, frameDark := frame.condition.states(width, fallback)
		light = intersectMediaState(light, frameLight)
		dark = intersectMediaState(dark, frameDark)
	}
	return combinedMediaState(light, dark)
}

func TestRulesShareImmutableConditionStack(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseCSS(`@media all{@media screen{p{display:none}b{display:none}i{display:none}}}`, false)
	if len(s.rules) != 3 {
		t.Fatalf("rules = %d, want 3", len(s.rules))
	}
	conditions := s.rules[0].conditions
	if conditions == nil || conditions.parent == nil {
		t.Fatalf("nested condition chain missing: %+v", conditions)
	}
	for i := 1; i < len(s.rules); i++ {
		if s.rules[i].conditions != conditions {
			t.Fatalf("rule %d copied rather than shared its condition stack", i)
		}
	}
}

func TestEmptyClipping(t *testing.T) {
	cases := []struct{ style, want string }{
		{`clip-path:circle(0px)`, "unknown"},
		{`clip-path:inset(50%)`, "unknown"},
		{`clip-path:circle(1px)`, "unknown"},
		{`clip-path:circle(0px);clip-path:none`, "visible"},
		{`clip-path:circle(0px)!important;clip-path:none`, "unknown"},
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
	if findText(t, in, "T").Label != "unknown" {
		t.Fatal(in)
	}
}

func TestDisplayContentsHasNoClippableBox(t *testing.T) {
	style := initial()
	style[display] = Value{Text: "contents", Known: true}
	style[clipPath] = Value{Text: "circle(0px)", Number: 1, Known: true}
	node := &xhtml.Node{Type: xhtml.ElementNode, Data: "div"}
	empty, known, inlineUncertain, clientDependent := emptyClip(&style, node, true)
	if empty || !known || inlineUncertain || clientDependent {
		t.Fatalf("display:contents clipping = empty:%t known:%t inline-uncertain:%t client-dependent:%t", empty, known, inlineUncertain, clientDependent)
	}

	foreign := &xhtml.Node{Type: xhtml.ElementNode, Data: "g", Namespace: "svg"}
	if _, foreignKnown, _, _ := emptyClip(&style, foreign, true); foreignKnown {
		t.Fatal("foreign-namespace clipping was treated as known")
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
		{"declared block span", `<span style="display:block;clip-path:circle(0)">T</span>`, "unknown"},
		{"default block element", `<div style="clip-path:circle(0)">T</div>`, "unknown"},
		{"positioned inline element", `<span style="position:absolute;clip-path:circle(0)">T</span>`, "unknown"},
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

func TestClientDivergentConcealmentIsUncertain(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{"opacity", `<span style="opacity:0">T</span>`, "unknown"},
		{"content visibility", `<div style="content-visibility:hidden">T</div>`, "unknown"},
		{"clip path", `<div style="clip-path:circle(0)">T</div>`, "unknown"},
		{"hidden attribute", `<div hidden>T</div>`, "unknown"},
		{"hidden until found", `<div hidden="until-found">T</div>`, "unknown"},
		{"author reveals hidden attribute", `<div hidden style="display:block">T</div>`, "visible"},
		{"display remains authoritative", `<div style="opacity:0;display:none">T</div>`, "concealed"},
		{"visibility remains authoritative", `<div style="clip-path:circle(0);visibility:hidden">T</div>`, "concealed"},
		{"legacy clip remains authoritative", `<div style="position:absolute;clip-path:circle(0);clip:rect(0,0,0,0)">T</div>`, "concealed"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
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

func TestActiveCSSAnimationsMakePresentationUncertain(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{
			"animation can reveal hidden text",
			`<style>@keyframes reveal{to{visibility:visible}}</style><p style="visibility:hidden;animation:reveal 0s forwards">T</p>`,
			"unknown",
		},
		{
			"animation can hide visible text",
			`<style>@keyframes hide{to{visibility:hidden}}</style><p style="animation:hide 0s forwards">T</p>`,
			"unknown",
		},
		{
			"animation uncertainty propagates to descendants",
			`<style>@keyframes hide{to{font-size:0}}</style><div style="animation-name:hide"><p>T</p></div>`,
			"unknown",
		},
		{
			"webkit animation aliases",
			`<style>@-webkit-keyframes reveal{to{visibility:visible}}</style><p style="visibility:hidden;-webkit-animation:reveal 0s forwards">T</p>`,
			"unknown",
		},
		{
			"variable animation name",
			`<style>@keyframes reveal{to{visibility:visible}}</style><p style="--name:reveal;visibility:hidden;animation-name:var(--name)">T</p>`,
			"unknown",
		},
		{
			"explicit shorthand none",
			`<style>@keyframes reveal{to{visibility:visible}}</style><p style="visibility:hidden;animation:none">T</p>`,
			"concealed",
		},
		{
			"explicit longhand none list",
			`<style>@keyframes reveal{to{visibility:visible}}</style><p style="visibility:hidden;animation-name:none, none">T</p>`,
			"concealed",
		},
		{
			"later none wins cascade",
			`<style>@keyframes reveal{to{visibility:visible}}</style><p style="visibility:hidden;animation:reveal 1s;animation:none">T</p>`,
			"concealed",
		},
		{
			"undefined animation cannot run",
			`<p style="visibility:hidden;animation:missing 0s forwards">T</p>`,
			"concealed",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMalformedCSSDelimiterCannotDesynchroniseAtRuleState(t *testing.T) {
	for _, test := range []struct {
		name, css string
	}{
		{"audit stray bracket", `@media print{#x]{a:b}} #b{display:none}`},
		{"stray parenthesis", `@media print{#x){a:b}} #b{display:none}`},
		{"stray brace", `@media print{a}} #b{display:none}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			document, err := Analyze([]byte(`<style>`+test.css+`</style><p id="b">T</p>`), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if got := findText(t, document, "T").Label; got != "unknown" {
				t.Fatalf("label = %q, want unknown", got)
			}
			if !document.Usage.CSSLimitExceeded {
				t.Fatal("malformed stylesheet did not abandon confident cascade analysis")
			}
		})
	}
}

func TestOpaqueRuleBearingAtRulesReportUnresolvedStylesheet(t *testing.T) {
	for _, test := range []struct {
		name, css string
	}{
		{"container", `@container (min-width:0px){#target{display:none}}`},
		{"scope", `@scope (#wrapper){#target{display:none}}`},
		{"starting style", `@starting-style{#target{display:none}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.css+`</style><div id="wrapper"><p id="target">T</p></div>`)
			if !document.UnresolvedStylesheet {
				t.Fatal("opaque rule-bearing at-rule was treated as fully resolved")
			}
			if got := findText(t, document, "T").Label; got != "visible" {
				t.Fatalf("opaque body unexpectedly entered the parsed cascade: %q", got)
			}
		})
	}
}

func TestDescriptorAtRulesDoNotReportUnresolvedStylesheet(t *testing.T) {
	document := inspectHTML(t, `<style>@font-face{font-family:x;src:url(x)}@page{margin:0}p{display:none}</style><p>T</p>`)
	if document.UnresolvedStylesheet {
		t.Fatal("known descriptor-only at-rule made the stylesheet unresolved")
	}
	if got := findText(t, document, "T").Label; got != "concealed" {
		t.Fatalf("ordinary rule after descriptor blocks = %q, want concealed", got)
	}
}

func TestRecoverableDeclarationErrorInsideMediaRetainsCascade(t *testing.T) {
	document, err := Analyze([]byte(`<style>@media screen{p{broken;display:none}}</style><p>T</p>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "concealed" {
		t.Fatalf("label = %q, want concealed", got)
	}
	if document.Usage.CSSLimitExceeded {
		t.Fatal("recoverable declaration error abandoned the shared cascade")
	}
}

func TestMalformedInlineDelimiterUncertaintyRemainsLocal(t *testing.T) {
	document, err := Analyze([]byte(`<p style="visibility:hidden;color:red]">T</p><b>U</b>`), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("malformed inline element label = %q, want unknown", got)
	}
	if got := findText(t, document, "U").Label; got != "visible" {
		t.Fatalf("unrelated element label = %q, want visible", got)
	}
	if document.Usage.CSSLimitExceeded {
		t.Fatal("local inline syntax error abandoned the shared stylesheet cascade")
	}
}

func TestCSSParserAcceptsBalancedComponents(t *testing.T) {
	limits := DefaultLimits()
	for _, source := range []string{
		`[data-x="("]{color:rgb(1 2 3 / .5)}`,
		`@media (width >= 1px){p:not([data-x]){display:none}}`,
		`p{--x:{a:[b(c)]};color:var(--x, red)}`,
		`p{--x:red;color:var(--x,[unused)])}`,
	} {
		s := sheet{limits: limits}
		s.parseCSS(source, false)
		if s.cascadeIncomplete {
			t.Errorf("valid CSS rejected: %s", source)
		}
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
		{"horizontal longhand clipping", `overflow-x:hidden;width:0`, "unknown"},
		{"vertical longhand clipping", `overflow-y:clip;height:0`, "unknown"},
		{"vertical longhand after shorthand", `overflow:visible;overflow-y:hidden;height:0`, "unknown"},
		{"important vertical longhand", `overflow-y:hidden!important;overflow:visible;height:0`, "unknown"},
		{"important shorthand beats vertical longhand", `overflow:hidden!important;overflow-y:visible;height:0`, "unknown"},
		{"variable vertical longhand", `--clip:hidden;overflow-y:var(--clip);height:0`, "unknown"},
		{"calculated zero height", `overflow:hidden;height:calc(100vh - 100vh)`, "unknown"},
		{"calculated zero width", `overflow:hidden;width:calc(1px - 1px)`, "unknown"},
		{"minimum zero width", `overflow:hidden;width:min(0px,1px)`, "unknown"},
		{"maximum calculated zero height", `overflow:hidden;height:max(0px,calc(1vh - 1vh))`, "unknown"},
		{"clamped zero width", `overflow:hidden;width:clamp(0px,0vw,1px)`, "unknown"},
		{"absolute left", `position:absolute;left:-1000px`, "unknown"},
		{"sub-threshold absolute left", `position:absolute;left:-250px`, "unknown"},
		{"sub-threshold positive absolute left", `position:absolute;left:250px`, "unknown"},
		{"fixed top", `position:fixed;top:-9999px`, "unknown"},
		{"absolute relative-unit left", `position:absolute;left:-3000em`, "unknown"},
		{"overflowing absolute left", `position:absolute;left:-1e999px`, "unknown"},
		{"fixed bottom", `position:fixed;bottom:-3000px`, "unknown"},
		{"absolute right", `position:absolute;right:-3000px`, "unknown"},
		{"positive absolute left", `position:absolute;left:100000px`, "unknown"},
		{"positive absolute right", `position:absolute;right:100000px`, "unknown"},
		{"positive fixed top", `position:fixed;top:5000px`, "unknown"},
		{"positive relative-unit left", `position:absolute;left:100em`, "unknown"},
		{"negative indent", `text-indent:-1000px`, "unknown"},
		{"sub-threshold negative indent", `text-indent:-300px`, "unknown"},
		{"positive indent", `text-indent:50000px`, "unknown"},
		{"percentage indent", `text-indent:-500%`, "unknown"},
		{"positive percentage indent", `text-indent:100%`, "unknown"},
		{"overflowing indent", `text-indent:-1e999px`, "unknown"},
		{"extreme negative letter spacing", `letter-spacing:-9999px`, "unknown"},
		{"boundary negative letter spacing", `letter-spacing:-8px`, "unknown"},
		{"extreme relative letter spacing", `letter-spacing:-1em`, "unknown"},
		{"extreme negative word spacing", `word-spacing:-9999px`, "unknown"},
		{"calculated negative letter spacing", `letter-spacing:calc(-1em)`, "unknown"},
		{"calculated overflowing offset", `position:absolute;left:calc(-1px * 1e400)`, "unknown"},
		{"extreme negative margin", `margin-left:-9999px`, "unknown"},
		{"extreme positive margin", `margin-left:100000px`, "unknown"},
		{"extreme relative margin", `margin-top:-100vh`, "unknown"},
		{"extreme margin shorthand", `margin:0 0 0 -9999px`, "unknown"},
		{"uppercase unit in extreme margin shorthand", `margin:0 0 0 -9999PX`, "unknown"},
		{"unresolved margin shorthand", `margin:var(--possibly-extreme)`, "unknown"},
		{"zero line height with vertical clipping", `overflow:hidden;line-height:0`, "unknown"},
		{"zero zoom", `zoom:0`, "unknown"},
		{"tiny zoom", `zoom:.001`, "unknown"},
		{"tiny percentage zoom", `zoom:1%`, "unknown"},
		{"dimension without clipping", `width:0;height:0`, "visible"},
		{"calculated dimension without clipping", `height:calc(100vh - 100vh)`, "visible"},
		{"minimum dimension without clipping", `width:min(0px,1px)`, "visible"},
		{"clipping with readable dimension", `overflow:hidden;width:2px`, "visible"},
		{"contextual subunit dimension", `overflow:hidden;height:.001%`, "visible"},
		{"ordinary responsive maximum", `overflow:hidden;max-width:100%;height:auto`, "visible"},
		{"wrong-axis clipping", `overflow:hidden visible;height:0`, "visible"},
		{"wrong horizontal longhand", `overflow-x:hidden;height:0`, "visible"},
		{"wrong vertical longhand", `overflow-y:hidden;width:0`, "visible"},
		{"shorthand overrides horizontal longhand", `overflow-x:hidden;overflow:visible;width:0`, "visible"},
		{"horizontal longhand overrides shorthand", `overflow:hidden;overflow-x:visible;width:0`, "visible"},
		{"shorthand overrides vertical longhand", `overflow-y:hidden;overflow:visible;height:0`, "visible"},
		{"invalid overflow ignored", `overflow:hidden;height:0;overflow:banana`, "unknown"},
		{"static offset", `position:static;left:-9999px`, "visible"},
		{"just below offset threshold", `position:absolute;left:-249px`, "visible"},
		{"just below positive offset threshold", `position:absolute;left:249px`, "visible"},
		{"just below indent threshold", `text-indent:-249px`, "visible"},
		{"ordinary negative letter spacing", `letter-spacing:-.7px`, "visible"},
		{"ordinary negative word spacing", `word-spacing:-2px`, "visible"},
		{"positive letter spacing", `letter-spacing:9999px`, "visible"},
		{"normal letter spacing", `letter-spacing:normal`, "visible"},
		{"overridden letter spacing", `letter-spacing:-9999px;letter-spacing:normal`, "visible"},
		{"zero line height alone", `line-height:0`, "visible"},
		{"ordinary relative offset", `position:absolute;left:-2em`, "visible"},
		{"ordinary positive relative offset", `position:absolute;left:99em`, "visible"},
		{"ordinary negative margin", `margin-left:-10px`, "visible"},
		{"ordinary positive margin", `margin-left:999px`, "visible"},
		{"overridden margin", `margin-left:-9999px;margin-left:0`, "visible"},
		{"shorthand overrides margin", `margin-left:-9999px;margin:0`, "visible"},
		{"uppercase auto shorthand overrides margin", `margin-left:-9999px;margin:AUTO`, "visible"},
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
	for _, test := range []struct {
		name, source, want string
	}{
		{
			"relative vertical offset under vertical clipping",
			`<div style="overflow:hidden;height:14px"><div style="position:relative;top:60px">T</div></div>`,
			"unknown",
		},
		{
			"relative horizontal offset under clipping",
			`<div style="overflow:hidden;width:14px"><div style="position:relative;left:60px">T</div></div>`,
			"unknown",
		},
		{
			"relative offset without clipping",
			`<div><div style="position:relative;top:60px">T</div></div>`,
			"visible",
		},
		{
			"inherited zero line height with clipping",
			`<div style="line-height:0"><div style="overflow:hidden">T</div></div>`,
			"unknown",
		},
		{
			"legacy table-cell height with clipping",
			`<table><tr><td height="1" style="overflow:hidden">T</td></tr></table>`,
			"unknown",
		},
		{
			"author height overrides legacy table-cell height",
			`<table><tr><td height="1" style="overflow:hidden;height:auto">T</td></tr></table>`,
			"visible",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := inspectHTML(t, test.source)
			if got := findText(t, in, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestElementPaintAndGeometryVisibility(t *testing.T) {
	cases := []struct {
		name, source, want string
		reason             string
	}{
		{"filter", `<img style="filter:opacity(0)">`, "unknown", ""},
		{"transform", `<img style="transform:scale(0)">`, "unknown", ""},
		{"blend", `<img style="mix-blend-mode:multiply">`, "unknown", ""},
		{"mask", `<img style="mask-image:url(mask.png)">`, "unknown", ""},
		{"zero CSS width", `<img style="width:0">`, "concealed", "empty-clip"},
		{"one-pixel CSS height", `<img style="height:1px">`, "concealed", "empty-clip"},
		{"percentage zero width", `<img style="width:0%">`, "concealed", "empty-clip"},
		{"ordinary CSS size", `<img style="width:2px;height:2px">`, "visible", ""},
		{"legacy one-pixel width", `<img width="1">`, "concealed", "empty-clip"},
		{"author width overrides legacy image width", `<img width="1" style="width:2px">`, "visible", ""},
		{"hidden input", `<input type="hidden">`, "concealed", "display-none"},
		{"ordinary input", `<input type="text">`, "visible", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if len(document.Elements) != 1 {
				t.Fatalf("elements = %d, want 1", len(document.Elements))
			}
			element := document.Elements[0]
			if element.Label != test.want {
				t.Fatalf("label = %q, want %q", element.Label, test.want)
			}
			if test.reason != "" && (len(element.ConcealmentReasons) == 0 || element.ConcealmentReasons[0] != test.reason) {
				t.Fatalf("reasons = %v, want %q", element.ConcealmentReasons, test.reason)
			}
		})
	}
}

func TestForeignNamespaceStylesheetIsUncertain(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{"SVG style", `<svg><style>div.secret{display:none}</style></svg><div class="secret">T</div>`, "unknown"},
		{"MathML style", `<math><style>div.secret{display:none}</style></math><div class="secret">T</div>`, "unknown"},
		{"ordinary HTML style", `<style>div.secret{display:none}</style><div class="secret">T</div>`, "concealed"},
		{"unmatched SVG style", `<svg><style>div.other{display:none}</style></svg><div class="secret">T</div>`, "visible"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestNoscriptVisibilityIsClientDependent(t *testing.T) {
	document := inspectHTML(t, `<html><body><noscript><p>Fallback</p><p style="display:none">Hidden fallback</p></noscript></body></html>`)
	if got := findText(t, document, "Fallback").Label; got != "unknown" {
		t.Fatalf("noscript fallback label = %q, want unknown", got)
	}
	hidden := findText(t, document, "Hidden fallback")
	if hidden.Label != "concealed" || len(hidden.ConcealmentReasons) == 0 || hidden.ConcealmentReasons[0] != "display-none" {
		t.Fatalf("concealed noscript fallback = %+v", hidden)
	}
}

func TestNoscriptStylesheetIsClientDependent(t *testing.T) {
	cases := []struct {
		name, source string
	}{
		{
			"body stylesheet reveals hidden text",
			`<noscript><style>#target{visibility:visible!important}</style></noscript><p id="target" style="visibility:hidden">T</p>`,
		},
		{
			"body stylesheet hides visible text",
			`<noscript><style>#target{display:none}</style></noscript><p id="target">T</p>`,
		},
		{
			"head stylesheet hides visible text",
			`<html><head><noscript><style>#target{display:none}</style></noscript></head><body><p id="target">T</p></body></html>`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != "unknown" {
				t.Fatalf("label = %q, want unknown", got)
			}
		})
	}
}

func TestMalformedStylesheetDeclarationMakesCascadeUncertain(t *testing.T) {
	cases := []struct {
		name string
		css  string
	}{
		{
			name: "later hiding declaration may be swallowed",
			css:  `#target{color:blue];display:none}`,
		},
		{
			name: "later revealing declaration may be swallowed",
			css:  `#target{display:none;color:blue];display:block}`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+test.css+`</style><p id="target">T</p>`)
			if got := findText(t, document, "T").Label; got != "unknown" {
				t.Fatalf("label = %q, want unknown", got)
			}
		})
	}
}

func TestMalformedInlineDeclarationUncertaintyIsLocal(t *testing.T) {
	cases := []struct {
		name  string
		style string
	}{
		{
			name:  "later hiding declaration may be swallowed",
			style: `color:blue];display:none`,
		},
		{
			name:  "later revealing declaration may be swallowed",
			style: `display:none;color:blue];display:block`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, `<div style="`+test.style+`"><span>T</span></div><p>U</p>`)
			if got := findText(t, document, "T").Label; got != "unknown" {
				t.Fatalf("affected descendant label = %q, want unknown", got)
			}
			if got := findText(t, document, "U").Label; got != "visible" {
				t.Fatalf("unrelated sibling label = %q, want visible", got)
			}
		})
	}
}

func TestCSSCommentsPreserveSelectorTokenBoundaries(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{
			"comment does not concatenate class and type",
			`<style>.a/**/p{display:none}</style><p class="ap">T</p>`,
			"visible",
		},
		{
			"comment separates descendant selector components",
			`<style>.a/**/p{display:none}</style><div class="a"><p>T</p></div>`,
			"concealed",
		},
		{
			"comment does not concatenate type names",
			`<style>di/**/v p{display:none}</style><div><p>T</p></div>`,
			"visible",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHexEscapeTerminatorIsNotASelectorCombinator(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{
			"synthetic planner chain must not match",
			`<style>\64 iv p{display:none}</style><d><iv><p>T</p></iv></d>`,
			"visible",
		},
		{
			"decoded browser selector must match",
			`<style>\64 iv p{display:none}</style><div><p>T</p></div>`,
			"concealed",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMSOConditionalStylesheetIsUncertain(t *testing.T) {
	cases := []struct {
		name, source, want string
	}{
		{"MSO style", `<!--[if mso]><style>#target{visibility:hidden}</style><![endif]--><p id="target">T</p>`, "unknown"},
		{"versioned MSO style", `<!--[if gte mso 9]><STYLE media="all">#target{display:none}</STYLE><![endif]--><p id="target">T</p>`, "unknown"},
		{"ordinary comment", `<!--<style>#target{display:none}</style>--><p id="target">T</p>`, "visible"},
		{"unrelated conditional", `<!--[if IE]><style>#target{display:none}</style><![endif]--><p id="target">T</p>`, "visible"},
		{"unmatched MSO style", `<!--[if mso]><style>#other{display:none}</style><![endif]--><p id="target">T</p>`, "visible"},
		{"later HTML override", `<!--[if mso]><style>#target{display:none}</style><![endif]--><style>#target{display:block}</style><p id="target">T</p>`, "visible"},
		{"ordinary conditional width", `<!--[if lte mso 11]><style>#target{width:100%!important}</style><![endif]--><div id="target" style="width:100%"><p>T</p></div>`, "visible"},
		{"conditional layout reveal", `<style>#target{overflow:hidden;height:0}</style><!--[if mso]><style>#target{overflow:visible}</style><![endif]--><p id="target">T</p>`, "unknown"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			document := inspectHTML(t, test.source)
			if got := findText(t, document, "T").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMSODownlevelRevealedContentIsClientDependent(t *testing.T) {
	document := inspectHTML(t, `<!--[if !mso]><!--><style>#target{display:none}</style><p>Conditional</p><!--<![endif]--><p id="target">Styled target</p><p>Ordinary</p>`)
	for text, want := range map[string]string{
		"Conditional":   "unknown",
		"Styled target": "unknown",
		"Ordinary":      "visible",
	} {
		if got := findText(t, document, text).Label; got != want {
			t.Errorf("%s label = %q, want %q", text, got, want)
		}
	}
}

func TestMSODownlevelRevealedConditionEvaluation(t *testing.T) {
	for _, test := range []struct {
		name      string
		condition string
		universal bool
	}{
		{"mso", `mso`, true},
		{"minimum supported version", `gte mso 9`, true},
		{"common wrapper", `(gte mso 9)|(IE)`, true},
		{"case insensitive", `(GTE MSO 9)|(ie)`, true},
		{"not mso", `!mso`, false},
		{"conjunction", `!mso & !IE`, false},
		{"obsolete version", `lte mso 8`, false},
		{"version dependent", `gte mso 16`, false},
		{"IE dependent", `IE`, false},
		{"unsupported", `mso && future`, false},
		{"unbalanced", `(mso`, false},
		{"over byte limit", strings.Repeat("!", maxMSOConditionBytes) + `mso`, false},
		{"deep nesting", strings.Repeat("(", 100) + `mso` + strings.Repeat(")", 100), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := msoConditionAlwaysTrue(test.condition); got != test.universal {
				t.Fatalf("msoConditionAlwaysTrue(%q) = %t, want %t", test.condition, got, test.universal)
			}
		})
	}
}

func TestMSODownlevelRevealedPredicatesControlConfidence(t *testing.T) {
	for _, test := range []struct {
		name, condition, want string
	}{
		{"conjunction", `!mso & !IE`, "unknown"},
		{"obsolete version", `lte mso 8`, "unknown"},
		{"version dependent", `gte mso 16`, "unknown"},
		{"unparseable", `mso && future`, "unknown"},
		{"always true", `(gte mso 9)|(IE)`, "visible"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := `<!--[if ` + test.condition + `]><!--><p>Conditional</p><!--<![endif]-->`
			document := inspectHTML(t, source)
			if got := findText(t, document, "Conditional").Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestMSODownlevelRevealedFosteredTextMakesDocumentUncertain(t *testing.T) {
	document := inspectHTML(t, `<p>Legit notice</p><table><!--[if !mso]><!-->APPROVE WIRE TRANSFER NOW<!--<![endif]--></table>`)
	for _, text := range []string{"Legit notice", "APPROVE WIRE TRANSFER NOW"} {
		if got := findText(t, document, text).Label; got != "unknown" {
			t.Errorf("%q label = %q, want unknown", text, got)
		}
	}
}

func TestMSODownlevelRevealedTableCellKeepsLocalUncertainty(t *testing.T) {
	for _, container := range []string{
		`<table><tr><td><!--[if !mso]><!-->Conditional<!--<![endif]--></td></tr></table>`,
		`<table><caption><!--[if !mso]><!-->Conditional<!--<![endif]--></caption></table>`,
	} {
		document := inspectHTML(t, `<p>Ordinary</p>`+container+`<p>After</p>`)
		if got := findText(t, document, "Conditional").Label; got != "unknown" {
			t.Errorf("conditional label = %q, want unknown", got)
		}
		for _, text := range []string{"Ordinary", "After"} {
			if got := findText(t, document, text).Label; got != "visible" {
				t.Errorf("%q label = %q, want visible", text, got)
			}
		}
	}
}

func TestMSOConditionalStyleRetainsOnlyConsumedAttributes(t *testing.T) {
	var style xhtml.Node
	retainConditionalStyleAttribute(&style, []byte("data-unused"), []byte(strings.Repeat("x", 1024)))
	retainConditionalStyleAttribute(&style, []byte("type"), []byte("text/plain"))
	retainConditionalStyleAttribute(&style, []byte("type"), []byte("text/css"))
	retainConditionalStyleAttribute(&style, []byte("media"), []byte("screen"))
	retainConditionalStyleAttribute(&style, []byte("title"), []byte("unused"))
	if len(style.Attr) != 2 {
		t.Fatalf("retained attributes = %+v, want only type and media", style.Attr)
	}
	if got := attr(&style, "type"); got != "text/plain" {
		t.Fatalf("retained type = %q, want first value", got)
	}
	if got := attr(&style, "media"); got != "screen" {
		t.Fatalf("retained media = %q", got)
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
			tokens, status := lexValue(test.value)
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

	tokens, status := lexValue(`var(--x)<junk>`)
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
