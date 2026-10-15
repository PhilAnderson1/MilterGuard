package htmlextract

import (
	"reflect"
	"testing"
)

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
