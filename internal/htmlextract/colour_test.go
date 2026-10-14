package htmlextract

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

func colourText(t *testing.T, src string) Text {
	t.Helper()
	r, e := (processor{Limits: DefaultLimits(), retainInspection: true}).process([]byte(src))
	if e != nil {
		t.Fatal(e)
	}
	return findText(t, r, "T")
}
func near(t *testing.T, got, want, tolerance float64) {
	t.Helper()
	if math.Abs(got-want) > tolerance {
		t.Fatalf("got %.15g want %.15g (tolerance %g)", got, want, tolerance)
	}
}
func expectRGBA(t *testing.T, got *RGBA, want RGBA) {
	t.Helper()
	if got == nil {
		t.Fatal("unknown effective pixel")
	}
	near(t, got.R, want.R, 1e-12)
	near(t, got.G, want.G, 1e-12)
	near(t, got.B, want.B, 1e-12)
	near(t, got.A, want.A, 1e-12)
}
func TestOklabIndependentValues(t *testing.T) {
	// Independent rounded primary reference values from the XYZ->Oklab route,
	// not generated with oklab(). The fuller machine-readable fixture is in
	// testdata/colour/reference-values.json and exercised below.
	for _, c := range []struct {
		rgb RGBA
		lab [3]float64
	}{
		{RGBA{0, 0, 0, 1}, [3]float64{0, 0, 0}},
		{RGBA{1, 1, 1, 1}, [3]float64{1, 0, 0}},
		{RGBA{1, 0, 0, 1}, [3]float64{.628, .225, .126}},
		{RGBA{0, 1, 0, 1}, [3]float64{.866, -.234, .179}},
		{RGBA{0, 0, 1, 1}, [3]float64{.452, -.032, -.312}},
		{RGBA{.5, .5, .5, 1}, [3]float64{.5981807305268476, 0, 0}},
	} {
		got := oklab(c.rgb)
		tolerance := .00051
		if c.rgb.R == c.rgb.G && c.rgb.G == c.rgb.B {
			tolerance = 5e-8
		}
		for i := range got {
			near(t, got[i], c.lab[i], tolerance)
		}
	}
	// These encode the sRGB transfer function breakpoints independently.
	near(t, linearChannel(.04045), .0031308049535603713, 1e-15)
	near(t, linearChannel(.5), .21404114048223255, 1e-15)
	near(t, linearChannel(1), 1, 1e-15)
}
func TestCompositionIndependentArithmetic(t *testing.T) {
	// Hand-computed source-over values; encoded sRGB, not linear-light mixing.
	for _, c := range []struct{ src, dst, want RGBA }{
		{RGBA{1, 0, 0, .5}, RGBA{0, 0, 1, 1}, RGBA{.5, 0, .5, 1}},
		{RGBA{1, 0, 0, .5}, RGBA{0, 0, 1, .5}, RGBA{2.0 / 3, 0, 1.0 / 3, .75}},
		{RGBA{}, RGBA{.2, .4, .6, 1}, RGBA{.2, .4, .6, 1}},
		{RGBA{.2, .4, .6, 1}, RGBA{}, RGBA{.2, .4, .6, 1}},
	} {
		got := over(c.src, c.dst)
		expectRGBA(t, &got, c.want)
	}
}
func TestColourThreshold(t *testing.T) {
	for _, c := range []struct {
		d         float64
		concealed bool
	}{{0, true}, {math.Nextafter(.005, 0), true}, {.005, true}, {math.Nextafter(.005, 1), false}, {.005001, false}} {
		distance := labDistance([3]float64{}, [3]float64{c.d, 0, 0})
		if colourConcealed(distance) != c.concealed {
			t.Fatal(c, distance)
		}
	}
	// Independent neutral-grey L differences straddle the fixed threshold.
	inside := colourText(t, `<p style="color:#fefefe;background:white">T</p>`)
	outside := colourText(t, `<p style="color:#fdfdfd;background:white">T</p>`)
	if !inside.inspection.colour.Concealed || inside.Label != "concealed" || outside.inspection.colour.Concealed || outside.Label != "visible" {
		t.Fatal(inside, outside)
	}
	near(t, *inside.inspection.colour.Distance, .00297480818, 2e-9)
	near(t, *outside.inspection.colour.Distance, .00595183731, 2e-9)
}

func TestNamedColours(t *testing.T) {
	if got := len(named); got != 148 {
		t.Fatalf("named colour count = %d, want 148", got)
	}
	for name := range named {
		if _, status := readColour(name); status != valueResolved {
			t.Errorf("named colour %q status = %d, want resolved", name, status)
		}
	}
	for name := range unsupportedColourNames {
		if _, status := readColour(name); status != valueUnsupported {
			t.Errorf("system colour %q status = %d, want unsupported", name, status)
		}
	}

	for _, test := range []struct {
		alias, canonical string
	}{
		{"grey", "gray"},
		{"cyan", "aqua"},
		{"magenta", "fuchsia"},
	} {
		t.Run(test.alias, func(t *testing.T) {
			alias, aliasStatus := readColour(test.alias)
			canonical, canonicalStatus := readColour(test.canonical)
			if aliasStatus != valueResolved || canonicalStatus != valueResolved || alias != canonical {
				t.Fatalf("%s = (%+v, %d), %s = (%+v, %d)", test.alias, alias, aliasStatus, test.canonical, canonical, canonicalStatus)
			}
			text := colourText(t, `<p style="color:`+test.alias+`;background:`+test.canonical+`">T</p>`)
			if text.Label != "concealed" || !text.inspection.colour.Known {
				t.Fatalf("matching alias colours = %+v", text)
			}
		})
	}
}

func TestCSSKeywordsUseASCIICaseFolding(t *testing.T) {
	for _, test := range []struct {
		name, source, want string
	}{
		{"mixed-case ASCII colour", `<p style="color:white;background:BLaCK">T</p>`, "visible"},
		{"Kelvin sign is not ASCII k", `<p style="color:white;background:blacK">T</p>`, "concealed"},
		{"Kelvin sign cannot fabricate property", `<p style="color:white;background:white;masK-image:url(x)">T</p>`, "concealed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := colourText(t, test.source).Label; got != test.want {
				t.Fatalf("label = %q, want %q", got, test.want)
			}
		})
	}
}

func TestColourInheritanceAttributesAndCascade(t *testing.T) {
	cases := []struct {
		name, src, want string
		known           bool
	}{
		{"inherited foreground", `<div style="color:red;background:red"><p>T</p></div>`, "concealed", true},
		{"currentColour background", `<div style="color:red"><p style="background:currentColor">T</p></div>`, "concealed", true},
		{"currentColour foreground", `<div style="color:blue;background:blue"><p style="color:currentColor">T</p></div>`, "concealed", true},
		{"legacy", `<table bgcolor="FFFFFF"><tr><td><font color="#fff">T</font></td></tr></table>`, "concealed", true},
		{"legacy foreground CSS override", `<body bgcolor=white><font color=white style="color:black">T</font></body>`, "visible", true},
		{"universal CSS beats hint", `<body bgcolor=white><font color=white>T</font><style>*{color:black}</style></body>`, "visible", true},
		{"late CSS beats background hint", `<body bgcolor=white><font color=white>T</font><style>body{background-color:black}</style></body>`, "visible", true},
		{"inline background beats hint", `<table bgcolor=white style="background:black"><tr><td><font color=white>T</font></td></tr></table>`, "visible", true},
		{"important CSS beats hint", `<body bgcolor=white style="background:black"><font color=white>T</font><style>body{background:white!important}</style></body>`, "concealed", true},
		{"unsupported legacy", `<body bgcolor=unknown><font color=white>T</font></body>`, "unknown", false},
		{"unknown foreground", `<p style="color:var(--c);background:white">T</p>`, "visible", true},
		{"invalid foreground ignored", `<p style="color:white;color:banana;background:white">T</p>`, "concealed", true},
		{"unresolved winner", `<p style="background:white;color:white;color:lab(100% 0 0)">T</p>`, "unknown", false},
		{"unsupported losing declaration", `<p style="background:var(--bg);background:white;color:white">T</p>`, "concealed", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := colourText(t, c.src)
			if v.Label != c.want || v.inspection.colour.Known != c.known {
				t.Fatal(v)
			}
		})
	}
}

func TestModernRGBAndHSLColours(t *testing.T) {
	cases := []struct {
		value string
		want  RGBA
	}{
		{`rgb(100% 0 0 / 50%)`, RGBA{1, 0, 0, .5}},
		{`rgba(255 0 0)`, RGBA{1, 0, 0, 1}},
		{`rgb(255,0,0,.25)`, RGBA{1, 0, 0, .25}},
		{`rgba(255,0,0)`, RGBA{1, 0, 0, 1}},
		{`hsl(0 100% 50% / 25%)`, RGBA{1, 0, 0, .25}},
		{`hsla(120,100%,25%,.5)`, RGBA{0, .5, 0, .5}},
		{`hsl(.5turn 100 50)`, RGBA{0, 1, 1, 1}},
		{`hsl(-120deg 100% 50%)`, RGBA{0, 0, 1, 1}},
		{`rgb(none 0 0 / none)`, RGBA{0, 0, 0, 0}},
		{`hsl(none none none / none)`, RGBA{0, 0, 0, 0}},
		{`hwb(0 0% 0%)`, RGBA{1, 0, 0, 1}},
		{`hwb(120deg 0% 0% / 50%)`, RGBA{0, 1, 0, .5}},
		{`hwb(0 20% 30%)`, RGBA{.7, .2, .2, 1}},
		{`hwb(240 60% 60%)`, RGBA{.5, .5, .5, 1}},
		{`hwb(none none none / none)`, RGBA{1, 0, 0, 0}},
		{`rgba(1e400,-1e400,1e-4000,1e400)`, RGBA{1, 0, 0, 1}},
		{`hsl(0 1e400% 1e400% / -1e400)`, RGBA{1, 1, 1, 0}},
	}
	for _, c := range cases {
		t.Run(c.value, func(t *testing.T) {
			got, status := readColour(c.value)
			if status != valueResolved {
				t.Fatalf("status = %d", status)
			}
			near(t, got.R, c.want.R, 1e-12)
			near(t, got.G, c.want.G, 1e-12)
			near(t, got.B, c.want.B, 1e-12)
			near(t, got.A, c.want.A, 1e-12)
		})
	}

	for _, value := range []string{
		`rgb(0, 0%, 0)`,
		`rgb(0, 0, 0 / .5)`,
		`rgb(none, 0, 0)`,
		`rgba(0, 0, 0, none)`,
		`hsl(0, 100, 50%)`,
		`hsl(none, 100%, 50%)`,
		`rgb(0 0 / 1)`,
		`hwb(0, 0%, 0%)`,
		`hwb(0 0 0)`,
	} {
		if _, status := readColour(value); status != valueInvalid {
			t.Errorf("%q status = %d, want invalid", value, status)
		}
	}
	for _, value := range []string{`rgb(from red r g b)`, `lab(50% 0 0)`} {
		if _, status := readColour(value); status != valueUnsupported {
			t.Errorf("%q status = %d, want unresolved", value, status)
		}
	}

	v := colourText(t, `<p style="background:rgb(255 255 255);color:hsl(0 0% 100%)">T</p>`)
	if !v.inspection.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
	v = colourText(t, `<p style="background:white;color:hwb(0 100% 0%)">T</p>`)
	if !v.inspection.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
	v = colourText(t, `<p style="background:black;color:rgb(none none none)">T</p>`)
	if !v.inspection.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
	v = colourText(t, `<p style="background:white;color:rgba(255,255,255,1e400)">T</p>`)
	if !v.inspection.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
}

func TestNonFiniteHSLResultsRemainUncertain(t *testing.T) {
	for _, value := range []string{
		`hsl(1e306turn 0% 0%)`,
		`hsl(1e307rad 0% 0%)`,
		`hsla(-1e306turn,0%,0%,1)`,
	} {
		colour, status := readColour(value)
		if status != valueUnsupported {
			t.Errorf("readColour(%q) status = %d, want unresolved", value, status)
		}
		if !finite(colour.R) || !finite(colour.G) || !finite(colour.B) || !finite(colour.A) {
			t.Errorf("readColour(%q) returned non-finite channels: %+v", value, colour)
		}
	}

	for _, src := range []string{
		`<body style="background-color:white"><span style="color:white"><span style="color:hsl(1e306turn,0%,0%)">T</span></span></body>`,
		`<body style="background-color:white;color:white"><span style="background:hsl(1e307rad,0%,0%)">T</span></body>`,
	} {
		v := colourText(t, src)
		if v.Label != "unknown" || v.inspection.colour.Known {
			t.Errorf("non-finite HSL was trusted: %+v", v)
		}
	}
}

func TestBackgroundLayersAndResets(t *testing.T) {
	cases := []struct {
		name, src     string
		known, hidden bool
	}{
		{"no canvas", `<p style="color:white">T</p>`, true, true},
		{"transparent unknown canvas", `<p style="color:white;background:transparent">T</p>`, true, true},
		{"equal translucent layers unknown canvas", `<p style="color:rgba(255,255,255,.5);background:rgba(255,255,255,.5)">T</p>`, true, true},
		{"transparent child", `<div style="background:white"><p style="color:white;background-color:transparent">T</p></div>`, true, true},
		{"nearest background", `<div style="background:red"><section style="background:blue"><p style="color:blue">T</p></section></div>`, true, true},
		{"bg noninherit property", `<div style="background:red"><p style="color:red">T</p></div>`, true, true},
		{"reset colour to transparent", `<div style="background:white"><p style="background:red;background:none;color:white">T</p></div>`, true, true},
		{"reset image", `<p style="background-image:url(https://invalid.example/x);background:white;color:white">T</p>`, true, true},
		{"reset by unset", `<div style="background:white"><p style="background:red;background-image:url(x);background:unset;color:white">T</p></div>`, true, true},
		{"stray close invalid", `<p style="background:black;background:) white;color:black">T</p>`, false, false},
		{"colour alone keeps image", `<p style="background:url(x) white;background-color:white;color:white">T</p>`, false, false},
		{"image then fallback colour", `<p style="background:url(x) red;color:red">T</p>`, false, false},
		{"fallback colour then image", `<p style="background:red url(x);color:red">T</p>`, false, false},
		{"multilayer final fallback colour", `<p style="background:url(x),red;color:red">T</p>`, false, false},
		{"gradient with fallback colour", `<p style="background:linear-gradient(blue,green) red;color:red">T</p>`, false, false},
		{"contrasting image fallback", `<p style="background:url(x) red;color:black">T</p>`, false, false},
		{"uniform gradient over contrasting fallback", `<p style="background:linear-gradient(#111,#111) white;color:#111">T</p>`, false, false},
		{"repeating gradient over contrasting fallback", `<p style="background:repeating-linear-gradient(red 0,red 1px) white;color:red">T</p>`, false, false},
		{"invalid colour in non-final layer", `<p style="background:white;background:red,url(x);color:white">T</p>`, true, true},
		{"image after shorthand", `<p style="background:white;background-image:url(x);color:white">T</p>`, false, false},
		{"gradient", `<p style="background:linear-gradient(white,white);color:white">T</p>`, false, false},
		{"unknown shorthand winner", `<p style="background:white;background:var(--bg);color:white">T</p>`, true, true},
		{"none and colour", `<p style="background:none white;color:white">T</p>`, true, true},
		{"image important", `<p style="background-image:url(x)!important;background:white;color:white">T</p>`, false, false},
		{"shorthand important", `<p style="background-image:url(x);background:white!important;color:white">T</p>`, true, true},
		{"legacy image", `<body bgcolor=white background=x><p style="color:white">T</p></body>`, false, false},
		{"legacy image reset", `<body bgcolor=white background=x style="background:white"><p style="color:white">T</p></body>`, true, true},
		{"opaque descendant masks ancestor image", `<div style="background-image:url(x)"><p style="background:white;color:white">T</p></div>`, true, true},
		{"transparent fg over known", `<p style="background:white;color:transparent">T</p>`, true, true},
		{"transparent fg unknown backdrop", `<p style="color:transparent">T</p>`, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := colourText(t, c.src)
			if v.inspection.colour.Known != c.known || v.inspection.colour.Concealed != c.hidden {
				t.Fatal(v)
			}
			if !c.known && (v.inspection.colour.Distance != nil || v.inspection.colour.Foreground != nil || v.Label != "unknown") {
				t.Fatal(v)
			}
		})
	}
	v := colourText(t, `<div style="background:blue"><p style="color:rgba(255,0,0,.5);background:rgba(0,255,0,.5)">T</p></div>`)
	expectRGBA(t, v.inspection.colour.Background, RGBA{0, .5, .5, 1})
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.5, .25, .25, 1})
	if textStyle(v, "background-color").RGBA.A != .5 {
		t.Fatal("background was incorrectly inherited/composited into property", v)
	}
}

func TestBackgroundShorthandRejectsUnmatchedClosingParenthesis(t *testing.T) {
	if declarations := backgroundDeclarations(`) none`, false, 0); len(declarations) != 0 {
		t.Fatalf("unmatched closing parenthesis produced declarations: %+v", declarations)
	}
}

func TestHTMLBodyBackgroundIsPropagatedToCanvas(t *testing.T) {
	// A propagated body background is painted as the root background. Body
	// opacity therefore affects its text but not the canvas background itself.
	v := colourText(t, `<html><body style="background:black;opacity:.5;color:white"><p>T</p></body></html>`)
	expectRGBA(t, v.inspection.colour.Background, RGBA{0, 0, 0, 1})
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.5, .5, .5, 1})
	if !v.inspection.colour.Known || v.inspection.colour.Concealed || v.Label != "visible" {
		t.Fatalf("propagated body background produced %+v", v)
	}

	// Once the root supplies a background, the body background remains on the
	// body and is grouped with its opacity, as for an ordinary element.
	v = colourText(t, `<html style="background:blue"><body style="background:black;opacity:.5;color:white"><p>T</p></body></html>`)
	expectRGBA(t, v.inspection.colour.Background, RGBA{0, 0, .5, 1})
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.5, .5, 1, 1})

	// Propagated values are treated as root values, so root opacity applies to
	// the canvas background while body opacity does not.
	v = colourText(t, `<html style="opacity:.5"><body style="background:black;color:white"><p>T</p></body></html>`)
	expectRGBA(t, v.inspection.colour.Background, RGBA{.5, .5, .5, 1})
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{1, 1, 1, 1})
}

func TestBackgroundFallbackColour(t *testing.T) {
	tests := []struct {
		value, colour string
		status        valueStatus
		valid         bool
	}{
		{`url(x) red`, "red", 1, true},
		{`red url(x)`, "red", 1, true},
		{`linear-gradient(red,blue) #fff`, "#fff", 1, true},
		{`url(x),rgb(1 2 3)`, "rgb(1 2 3)", 1, true},
		{`url(x) center/cover no-repeat`, "transparent", 1, true},
		{`url(x) aliceblue`, "aliceblue", 1, true},
		{`red,url(x)`, "", 0, false},
		{`url(x) red blue`, "", 0, false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			colour, status, valid := backgroundFallbackColour(test.value)
			if colour != test.colour || status != test.status || valid != test.valid {
				t.Fatalf("backgroundFallbackColour() = %q, %d, %t; want %q, %d, %t", colour, status, valid, test.colour, test.status, test.valid)
			}
		})
	}
}

func TestGroupOpacity(t *testing.T) {
	v := colourText(t, `<div style="background:white"><p style="background:white;color:black;opacity:.5">T</p></div>`)
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.5, .5, .5, 1})
	expectRGBA(t, v.inspection.colour.Background, RGBA{1, 1, 1, 1})
	near(t, *v.inspection.colour.Distance, .4018192694731524, 5e-8)
	v = colourText(t, `<div style="background:blue"><section style="background:white;opacity:.5"><p style="color:black;opacity:.5">T</p></section></div>`)
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.25, .25, .75, 1})
	expectRGBA(t, v.inspection.colour.Background, RGBA{.5, .5, 1, 1})
	v = colourText(t, `<div style="background:blue"><p style="background:white;color:white;opacity:.5">T</p></div>`)
	expectRGBA(t, v.inspection.colour.Foreground, RGBA{.5, .5, 1, 1})
	expectRGBA(t, v.inspection.colour.Background, RGBA{.5, .5, 1, 1})
	if !v.inspection.colour.Concealed {
		t.Fatal(v)
	}
	// Known transparent groups compose onto the agreed white canvas.
	v = colourText(t, `<p style="background:white;color:white;opacity:.5">T</p>`)
	if !v.inspection.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
}
func TestCompositionUncertaintyAndIndependentReasons(t *testing.T) {
	for _, property := range []string{"filter:blur(1px)", "mix-blend-mode:multiply", "backdrop-filter:blur(1px)", "background-blend-mode:multiply", "mask-image:url(x)", "opacity:env(unknown)", "background-clip:text", "text-shadow:1px 1px red", "-webkit-text-fill-color:red", "transform:translateX(10px)", "position:absolute", "-webkit-text-stroke:1px red", "display:contents"} {
		v := colourText(t, `<p style="background:white;color:white;`+property+`">T</p>`)
		if v.inspection.colour.Known || v.Label != "unknown" {
			t.Fatal(property, v)
		}
		for _, independent := range []string{"display:none", "visibility:hidden", "font-size:0", "opacity:0"} {
			// A later opacity:0 legitimately resolves an earlier opacity var().
			v = colourText(t, `<p style="background-image:url(x);color:white;`+property+`;`+independent+`">T</p>`)
			want := "concealed"
			if independent == "opacity:0" {
				want = "unknown"
			}
			if v.Label != want || v.inspection.colour.Concealed {
				t.Fatal(property, independent, v)
			}
		}
	}
	v := colourText(t, `<div style="filter:blur(1px)"><p style="background:white;color:white">T</p></div>`)
	if v.inspection.colour.Known {
		t.Fatal(v)
	}
	v = colourText(t, `<p style="filter:blur(1px);filter:none;background:white;color:white">T</p>`)
	if !v.inspection.colour.Concealed {
		t.Fatal(v)
	}
}

func TestVendorPrefixedConcealmentEffectsMakeVisibilityUncertain(t *testing.T) {
	for _, effect := range []string{
		`-webkit-mask-image:url(mask.png)`,
		`-webkit-mask:url(mask.png)`,
		`-webkit-transform:scale(0)`,
		`-ms-transform:scale(0)`,
		`-webkit-text-stroke-width:20px;-webkit-text-stroke-color:white`,
	} {
		t.Run(effect, func(t *testing.T) {
			v := colourText(t, `<p style="background:red;color:white;`+effect+`">T</p>`)
			if v.inspection.colour.Known || v.Label != "unknown" {
				t.Fatalf("vendor effect %q remained trusted: %+v", effect, v)
			}
		})
	}
}

func TestVendorPrefixedAliasesShareCanonicalCascadeSlots(t *testing.T) {
	for _, style := range []string{
		`-webkit-mask-image:url(mask.png);mask-image:none`,
		`mask-image:url(mask.png);-webkit-mask-image:none`,
		`-webkit-transform:scale(0);transform:none`,
		`transform:scale(0);-webkit-transform:none`,
		`-ms-transform:scale(0);transform:none`,
		`-webkit-text-stroke:20px white;-webkit-text-stroke-width:0`,
	} {
		t.Run(style, func(t *testing.T) {
			v := colourText(t, `<p style="background:red;color:white;`+style+`">T</p>`)
			if !v.inspection.colour.Known || v.Label != "visible" {
				t.Fatalf("vendor alias did not share canonical cascade for %q: %+v", style, v)
			}
		})
	}
}

func TestDecorativeEffectsDoNotMakeReadableTextUncertain(t *testing.T) {
	for _, property := range []string{
		`position:absolute`,
		`text-shadow:1px 1px 1px white`,
	} {
		v := colourText(t, `<p style="color:black;`+property+`">T</p>`)
		if !v.inspection.colour.Known || v.Label != "visible" {
			t.Errorf("%s: %+v", property, v)
		}
	}
	for _, property := range []string{
		`background:linear-gradient(to bottom,#fff,#ddd)`,
		`background-image:url(x)`,
	} {
		v := colourText(t, `<p style="color:black;`+property+`">T</p>`)
		if v.inspection.colour.Known || v.Label != "unknown" {
			t.Errorf("unresolved background %s was trusted: %+v", property, v)
		}
	}

	// An unresolved image also prevents a colour-based concealment claim when
	// the solid fallback itself matches the foreground.
	v := colourText(t, `<p style="color:white;background:white;background-image:url(x)">T</p>`)
	if v.inspection.colour.Known || v.Label != "unknown" {
		t.Fatal(v)
	}

	// Transparent gradient-filled text genuinely depends on unsupported
	// composition and remains uncertain.
	v = colourText(t, `<p style="color:black;background:linear-gradient(red,blue);background-clip:text;-webkit-text-fill-color:transparent">T</p>`)
	if v.inspection.colour.Known || v.Label != "unknown" {
		t.Fatal(v)
	}
}
func TestStandardParsingDecisions(t *testing.T) {
	src, e := os.ReadFile("testdata/offer.original.html")
	if e != nil {
		t.Fatal(e)
	}
	in, e := (processor{Limits: DefaultLimits()}).process(src)
	if e != nil {
		t.Fatal(e)
	}
	findText(t, in, "Visible offer")
	foundCSS := false
	for _, v := range in.Text {
		if v.Node != nil && strings.Contains(v.Node.Data, "@media") {
			foundCSS = true
		}
	}
	if !foundCSS {
		t.Fatal("standard parser's displayed CSS-looking text removed", in)
	}
	for _, c := range []struct {
		src       string
		concealed bool
	}{
		{`<table style="display:none">T<tr><td>cell</td></tr></table>`, false},
		{`<div style="display:none"><table>T<tr><td>cell</td></tr></table></div>`, true},
		{`<table style="display:none"><tr><td>T</td></tr></table>`, true},
	} {
		v := colourText(t, `<style>html{background:white}</style>`+c.src)
		if (v.Label == "concealed") != c.concealed {
			t.Fatal(v)
		}
	}
}
func TestColourDecisionAndConsumption(t *testing.T) {
	for _, src := range []string{`<p style="color:white;background:white">T</p>`, `<p style="color:white">T</p>`} {
		in, e := (processor{Limits: DefaultLimits(), retainInspection: true}).process([]byte(src))
		if e != nil {
			t.Fatal(e)
		}
		if colour := findText(t, in, "T").inspection.colour; colour.Distance == nil {
			t.Fatal("missing colour-distance decision", colour)
		}
	}
	white := colourText(t, `<p style="background:white;color:white">T</p>`)
	black := colourText(t, `<p style="background:white;color:black">T</p>`)
	if white.Label != "concealed" || black.Label != "visible" {
		t.Fatal("colour result was not consumed", white, black)
	}
}

func TestIndependentXYZRouteFixtures(t *testing.T) {
	data, e := os.ReadFile("testdata/colour/reference-values.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		Name string     `json:"name"`
		RGB  RGBA       `json:"srgb"`
		Lab  [3]float64 `json:"oklab"`
	}
	if e = json.Unmarshal(data, &rows); e != nil {
		t.Fatal(e)
	}
	if len(rows) != 7 {
		t.Fatal("incomplete independent reference fixtures")
	}
	for _, row := range rows {
		t.Run(row.Name, func(t *testing.T) {
			got := oklab(row.RGB)
			for i := range got {
				near(t, got[i], row.Lab[i], .0002)
			}
		})
	}
}
