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

func TestStableConcealmentFastPathPreservesPrimaryEvidence(t *testing.T) {
	for _, source := range []string{
		`<div style="display:none;color:white"><p>T</p></div>`,
		`<style>@keyframes k{to{color:red}}</style><div style="display:none"><p style="animation:k 1s">T</p></div>`,
		`<div style="display:none"><p style="font-size:0;opacity:0">T</p></div>`,
		`<style>div{display:none}@media(min-width:600px){div{display:block;color:white}}</style><div>T</div>`,
		`<style>@keyframes k{to{display:block}}</style><p style="display:none;animation:k 1s">T</p>`,
	} {
		t.Run(source, func(t *testing.T) {
			fast, err := Analyze([]byte(source), DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			diagnostic := inspectHTML(t, source)
			a, b := findText(t, fast, "T"), findText(t, diagnostic, "T")
			if a.Label != b.Label || a.ConcealmentReasons.Primary() != b.ConcealmentReasons.Primary() || a.FontSize != b.FontSize || a.EffectiveOpacity != b.EffectiveOpacity {
				t.Fatalf("annotation evidence differs: fast=%+v diagnostic=%+v", a, b)
			}
		})
	}
}

func TestInertPresentationPruningPreservesSelectorDOM(t *testing.T) {
	for _, c := range []struct{ source, want string }{
		{`<body><style>template + p{display:none}</style><template><div style="color:red">INERT</div></template><p>T</p>`, "concealed"},
		// :has remains conservative, exactly as before presentation pruning.
		{`<style>div:has(.needle){display:none}</style><div><template><i class=needle>INERT</i></template><p>T</p></div>`, "unknown"},
	} {
		d, err := Analyze([]byte(c.source), DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Text) != 1 || findText(t, d, "T").Label != c.want {
			t.Fatalf("inert DOM changed selector result for %s: %+v", c.source, d.Text)
		}
	}
}
