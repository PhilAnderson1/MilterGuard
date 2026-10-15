package htmlextract

import (
	"reflect"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

func TestUnstyledPaddingDoesNotExhaustStyleResolution(t *testing.T) {
	for _, c := range []struct{ name, prefix string }{
		{"node-producing end tags", strings.Repeat(`</br>`, 78500)},
		{"optional paragraph ends", strings.Repeat(`<p>`, 78500)},
		{"irrelevant responsive rule", `<style>@media(max-width:500px){q{color:red}}</style>` + strings.Repeat(`<p>`, 45000)},
	} {
		t.Run(c.name, func(t *testing.T) {
			document, err := Analyze([]byte(c.prefix+`<div style="display:none">PAYLOAD</div>`), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if got := findText(t, document, "PAYLOAD").Label; got != "concealed" {
				t.Fatalf("padding erased concealment: label=%q usage=%+v", got, document.Usage)
			}
			if document.Usage.MatchWorkExhausted {
				t.Fatalf("unstyled padding exhausted work: %+v", document.Usage)
			}
		})
	}
}

func TestInheritanceFastPathAgreesWithFullCascade(t *testing.T) {
	for _, source := range []string{
		`<div><section><span>T</span></section></div>`,
		`<div style="display:none"><section><span>T</span></section></div>`,
		`<div style="font-size:0"><section><span>T</span></section></div>`,
		`<div style="visibility:hidden"><section><span>T</span></section></div>`,
		`<div style="opacity:0"><section><span>T</span></section></div>`,
		`<div style="mso-hide:all"><section><span>T</span></section></div>`,
		`<div style="color:white;background:white"><section><span>T</span></section></div>`,
		`<font color="white"><section><span>T</span></section></font>`,
		`<div style="font-size:1vw"><section><span>T</span></section></div>`,
		`<div style="--state:none"><section><span style="display:var(--state)">T</span></section></div>`,
		`<div style="overflow:hidden;height:0"><section><span>T</span></section></div>`,
		`<style>@keyframes reveal{to{visibility:visible}}</style><div style="visibility:hidden;animation:reveal 1s"><section><span>T</span></section></div>`,
		`<style>@media(max-width:500px){div{visibility:hidden}}</style><div><section><span>T</span></section></div>`,
	} {
		t.Run(source, func(t *testing.T) {
			fast := findText(t, inspectHTML(t, source), "T")
			// Explicitly setting the default position changes no fixture's
			// presentation, but makes every element resolve a real declaration.
			// Empty rules would be removed by selector-index preparation.
			full := findText(t, inspectHTML(t, `<style>*{position:static}</style>`+source), "T")
			if fast.Label != full.Label || fast.FontSize != full.FontSize || fast.EffectiveOpacity != full.EffectiveOpacity ||
				!reflect.DeepEqual(fast.ConcealmentReasons, full.ConcealmentReasons) || fast.inspection.style != full.inspection.style {
				t.Fatalf("inheritance differs from full cascade: fast=%+v full=%+v", fast, full)
			}
		})
	}
}

func TestInheritanceFastPathRetainsExhaustionAndUncertainty(t *testing.T) {
	for _, c := range []struct {
		name                                     string
		cascade, planning, matching, expressions bool
	}{
		{"incomplete cascade", true, false, false, false},
		{"incomplete planning", false, true, false, false},
		{"exhausted matching", false, false, true, false},
		{"exhausted expressions", false, false, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := sheet{limits: DefaultLimits(), cascadeIncomplete: c.cascade, workIncomplete: c.planning}
			matches := matchBudget{limit: s.limits.MatchWork, exhausted: c.matching}
			budget := expressionBudget{remaining: s.limits.ExpressionWork, exhausted: c.expressions}
			node := &html.Node{Type: html.ElementNode, Data: "span"}
			result := s.elementStyle(node, initialPtr(), initialPtr(), nil, nil, nil, mediaAt(1024), selectorMatchContext{}, &matches, &budget)
			if result.style[display].Known {
				t.Fatalf("fast path trusted incomplete analysis: %+v", result.style)
			}
		})
	}
}
