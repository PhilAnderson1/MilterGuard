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
	r, e := (processor{Limits: DefaultLimits()}).process([]byte(src))
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
	// not generated with oklab(): see testdata/colour/REFERENCE.md.
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
	if !inside.colour.Concealed || inside.Label != "concealed" || outside.colour.Concealed || outside.Label != "visible" {
		t.Fatal(inside, outside)
	}
	near(t, *inside.colour.Distance, .00297480818, 2e-9)
	near(t, *outside.colour.Distance, .00595183731, 2e-9)
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
			if v.Label != c.want || v.colour.Known != c.known {
				t.Fatal(v)
			}
		})
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
		{"colour alone keeps image", `<p style="background:url(x) white;background-color:white;color:white">T</p>`, false, false},
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
			if v.colour.Known != c.known || v.colour.Concealed != c.hidden {
				t.Fatal(v)
			}
			if !c.known && (v.colour.Distance != nil || v.colour.Foreground != nil || v.Label != "unknown") {
				t.Fatal(v)
			}
		})
	}
	v := colourText(t, `<div style="background:blue"><p style="color:rgba(255,0,0,.5);background:rgba(0,255,0,.5)">T</p></div>`)
	expectRGBA(t, v.colour.Background, RGBA{0, .5, .5, 1})
	expectRGBA(t, v.colour.Foreground, RGBA{.5, .25, .25, 1})
	if textStyle(v, "background-color").RGBA.A != .5 {
		t.Fatal("background was incorrectly inherited/composited into property", v)
	}
}
func TestGroupOpacity(t *testing.T) {
	v := colourText(t, `<div style="background:white"><p style="background:white;color:black;opacity:.5">T</p></div>`)
	expectRGBA(t, v.colour.Foreground, RGBA{.5, .5, .5, 1})
	expectRGBA(t, v.colour.Background, RGBA{1, 1, 1, 1})
	near(t, *v.colour.Distance, .4018192694731524, 5e-8)
	v = colourText(t, `<div style="background:blue"><section style="background:white;opacity:.5"><p style="color:black;opacity:.5">T</p></section></div>`)
	expectRGBA(t, v.colour.Foreground, RGBA{.25, .25, .75, 1})
	expectRGBA(t, v.colour.Background, RGBA{.5, .5, 1, 1})
	v = colourText(t, `<div style="background:blue"><p style="background:white;color:white;opacity:.5">T</p></div>`)
	expectRGBA(t, v.colour.Foreground, RGBA{.5, .5, 1, 1})
	expectRGBA(t, v.colour.Background, RGBA{.5, .5, 1, 1})
	if !v.colour.Concealed {
		t.Fatal(v)
	}
	// Known transparent groups compose onto the agreed white canvas.
	v = colourText(t, `<p style="background:white;color:white;opacity:.5">T</p>`)
	if !v.colour.Known || v.Label != "concealed" {
		t.Fatal(v)
	}
}
func TestCompositionUncertaintyAndIndependentReasons(t *testing.T) {
	for _, property := range []string{"filter:blur(1px)", "mix-blend-mode:multiply", "backdrop-filter:blur(1px)", "background-blend-mode:multiply", "mask-image:url(x)", "opacity:env(unknown)", "background-clip:text", "text-shadow:1px 1px red", "-webkit-text-fill-color:red", "transform:translateX(10px)", "position:absolute", "-webkit-text-stroke:1px red", "display:contents"} {
		v := colourText(t, `<p style="background:white;color:white;`+property+`">T</p>`)
		if v.colour.Known || v.Label != "unknown" {
			t.Fatal(property, v)
		}
		for _, independent := range []string{"display:none", "visibility:hidden", "font-size:0", "opacity:0"} {
			// A later opacity:0 legitimately resolves an earlier opacity var().
			v = colourText(t, `<p style="background-image:url(x);color:white;`+property+`;`+independent+`">T</p>`)
			if v.Label != "concealed" || v.colour.Concealed {
				t.Fatal(property, independent, v)
			}
		}
	}
	v := colourText(t, `<div style="filter:blur(1px)"><p style="background:white;color:white">T</p></div>`)
	if v.colour.Known {
		t.Fatal(v)
	}
	v = colourText(t, `<p style="filter:blur(1px);filter:none;background:white;color:white">T</p>`)
	if !v.colour.Concealed {
		t.Fatal(v)
	}
}

func TestDecorativeEffectsDoNotMakeReadableTextUncertain(t *testing.T) {
	for _, property := range []string{
		`background:linear-gradient(to bottom,#fff,#ddd)`,
		`background-image:url(x)`,
		`position:absolute`,
		`text-shadow:1px 1px 1px white`,
	} {
		v := colourText(t, `<p style="color:black;`+property+`">T</p>`)
		if !v.colour.Known || v.Label != "visible" {
			t.Errorf("%s: %+v", property, v)
		}
	}

	// An unresolved effect still prevents a colour-based concealment claim
	// when the solid fallback itself matches the foreground.
	v := colourText(t, `<p style="color:white;background:white;background-image:url(x)">T</p>`)
	if v.colour.Known || v.Label != "unknown" {
		t.Fatal(v)
	}

	// Transparent gradient-filled text genuinely depends on unsupported
	// composition and remains uncertain.
	v = colourText(t, `<p style="color:black;background:linear-gradient(red,blue);background-clip:text;-webkit-text-fill-color:transparent">T</p>`)
	if v.colour.Known || v.Label != "unknown" {
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
		if strings.Contains(v.Text, "@media") {
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
		in, e := (processor{Limits: DefaultLimits()}).process([]byte(src))
		if e != nil {
			t.Fatal(e)
		}
		if colour := findText(t, in, "T").colour; colour.Distance == nil {
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
