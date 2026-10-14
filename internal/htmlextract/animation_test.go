package htmlextract

import (
	"html"
	"strings"
	"testing"
)

func TestAnimationNamesMustMatchDefinedKeyframes(t *testing.T) {
	for _, c := range []struct{ name, definitions, style, want string }{
		{"unrelated dummy", `@keyframes dummy{from{}}`, `animation:missing 1s`, "concealed"},
		{"missing longhand", `@keyframes dummy{from{}}`, `animation-name:missing`, "concealed"},
		{"matching name", `@keyframes Reveal{to{visibility:visible}}`, `animation:Reveal 0s forwards`, "unknown"},
		{"name case differs", `@keyframes Reveal{to{visibility:visible}}`, `animation:reveal 0s forwards`, "concealed"},
		{"quoted name", `@keyframes "Reveal Text"{to{visibility:visible}}`, `animation:1s "Reveal Text"`, "unknown"},
		{"quoted name case differs", `@keyframes "Reveal Text"{to{visibility:visible}}`, `animation-name:"reveal text"`, "concealed"},
		{"escaped definition", `@keyframes R\65 veal{to{visibility:visible}}`, `animation-name:Reveal`, "unknown"},
		{"escaped reference", `@keyframes Reveal{to{visibility:visible}}`, `animation-name:R\65 veal`, "unknown"},
		{"escaped quoted reference", `@keyframes "Reveal Text"{to{visibility:visible}}`, `animation-name:"Reveal\20 Text"`, "unknown"},
		{"quoted keyword name", `@keyframes "none"{to{visibility:visible}}`, `animation-name:"none"`, "unknown"},
		{"quoted keyword shorthand", `@keyframes "none"{to{visibility:visible}}`, `animation:"none" 1s`, "unknown"},
		{"comma inside quoted name", `@keyframes "Reveal, Text"{to{visibility:visible}}`, `animation:"Reveal, Text" 1s`, "unknown"},
		{"dashed identifier", `@keyframes --reveal{to{visibility:visible}}`, `animation:--reveal 1s`, "unknown"},
		{"missing names list", `@keyframes dummy{from{}}`, `animation:missing 1s, absent 2s`, "concealed"},
		{"mixed names list", `@keyframes reveal{to{visibility:visible}}`, `animation:missing 1s, reveal 2s`, "unknown"},
		{"mixed longhand list", `@keyframes reveal{to{visibility:visible}}`, `animation-name:none, missing, reveal`, "unknown"},
		{"keyword fills timing first", `@keyframes ease{to{visibility:visible}}`, `animation:1s ease`, "concealed"},
		{"repeated keyword names keyframes", `@keyframes ease{to{visibility:visible}}`, `animation:1s ease ease`, "unknown"},
		{"repeated keyword preserves name case", `@keyframes FoRWaRdS{to{visibility:visible}}`, `animation:1s forwards FoRWaRdS`, "unknown"},
		{"all shorthand slots", `@keyframes reveal{to{visibility:visible}}`, `animation:1s ease 2s infinite alternate both running reveal`, "unknown"},
		{"none with duration", `@keyframes dummy{from{}}`, `animation:none 1s`, "concealed"},
		{"escaped none", `@keyframes dummy{from{}}`, `animation:\6e one 1s`, "concealed"},
		{"steps shorthand missing", `@keyframes dummy{from{}}`, `animation:missing 1s steps(2, jump-none)`, "concealed"},
		{"bezier shorthand missing", `@keyframes dummy{from{}}`, `animation:1s cubic-bezier(.2, -1, .8, 2) missing`, "concealed"},
		{"timing-function comma and list", `@keyframes reveal{to{visibility:visible}}`, `animation:1s steps(2, end) missing, 1s reveal`, "unknown"},
		{"variable missing", `@keyframes dummy{from{}}`, `--name:missing;animation-name:var(--name)`, "concealed"},
		{"variable match", `@keyframes Reveal{to{visibility:visible}}`, `--name:Reveal;animation:var(--name) 1s`, "unknown"},
		{"variable fallback match", `@keyframes Reveal{to{visibility:visible}}`, `animation-name:var(--absent, Reveal)`, "unknown"},
		{"unresolved variable", `@keyframes dummy{from{}}`, `animation-name:var(--invalid, env(unknown))`, "unknown"},
		{"initial value", `@keyframes dummy{from{}}`, `animation:initial`, "concealed"},
		{"unset value", `@keyframes dummy{from{}}`, `animation-name:unset`, "concealed"},
		{"explicit inheritance unresolved", `@keyframes dummy{from{}}`, `animation-name:inherit`, "unknown"},
		{"vendor names", `@-webkit-keyframes Reveal{to{visibility:visible}}`, `-webkit-animation:Reveal 1s`, "unknown"},
		{"later missing overrides real", `@keyframes reveal{to{visibility:visible}}`, `animation:reveal 1s;animation-name:missing`, "concealed"},
		{"important real wins", `@keyframes reveal{to{visibility:visible}}`, `animation-name:reveal!important;animation:missing 1s`, "unknown"},
		{"invalid keyframe prelude", `@keyframes dummy extra{to{visibility:visible}}`, `animation-name:dummy`, "concealed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			document := inspectHTML(t, `<style>`+c.definitions+`</style><p style="visibility:hidden;`+html.EscapeString(c.style)+`">T</p>`)
			if got := findText(t, document, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUnrelatedKeyframesDoNotWipeDocumentVisibility(t *testing.T) {
	document := inspectHTML(t, `<style>@keyframes dummy{from{}}*{animation:missing 1s}</style><p style="display:none">T</p><p>U</p>`)
	if got := findText(t, document, "T").Label; got != "concealed" {
		t.Fatalf("hidden text label = %q", got)
	}
	if got := findText(t, document, "U").Label; got != "visible" {
		t.Fatalf("visible text label = %q", got)
	}
}

func TestAnimationDefinitionSources(t *testing.T) {
	for _, c := range []struct{ name, source, want string }{
		{"definition after usage", `<p style="visibility:hidden;animation:reveal 1s">T</p><style>@keyframes reveal{to{visibility:visible}}</style>`, "unknown"},
		{"inline keyframes are not definitions", `<div style="@keyframes dummy{from{}}"></div><p style="visibility:hidden;animation:dummy 1s">T</p>`, "concealed"},
		{"external definition unresolved", `<link rel="stylesheet" href="https://example.test/style.css"><p style="visibility:hidden;animation:reveal 1s">T</p>`, "unknown"},
		{"external stylesheet with explicit none", `<link rel="stylesheet" href="https://example.test/style.css"><p style="visibility:hidden;animation:none 1s">T</p>`, "concealed"},
		{"data URL definition", `<link rel="stylesheet" href="data:text/css,@keyframes%20reveal%7Bto%7Bvisibility:visible%7D%7D"><p style="visibility:hidden;animation:reveal 1s">T</p>`, "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			document := inspectHTML(t, c.source)
			if got := findText(t, document, "T").Label; got != c.want {
				t.Fatalf("label = %q, want %q", got, c.want)
			}
		})
	}
}

func TestAnimationNameResolutionRemainsBounded(t *testing.T) {
	document := inspectHTML(t, `<style>@keyframes dummy{from{}}</style><p style="visibility:hidden;animation-name:`+strings.Repeat("x", maxValueBytes+1)+`">T</p>`)
	if got := findText(t, document, "T").Label; got != "unknown" {
		t.Fatalf("oversized value label = %q, want unknown", got)
	}
	// A name lookup still hashes its bytes on each evaluation. Exhaustion must
	// be charged rather than letting long static names evade the work budget.
	s := sheet{keyframeNames: map[string]struct{}{"dummy": {}}}
	d := prepareDeclaration(declaration{prop: animationProperty, value: strings.Repeat("x", 128), shorthand: true})
	budget := expressionBudget{remaining: 1000}
	matches := matchBudget{limit: 1}
	if !s.potentiallyActiveAnimation(candidate{d: &d, set: true}, evaluationContext{budget: &budget}, &matches) || !matches.exhausted {
		t.Fatal("name lookup exhaustion did not preserve uncertainty")
	}
}
