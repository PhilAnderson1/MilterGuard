package htmlextract

import "testing"

func TestAdversarialVisibilityRegressions(t *testing.T) {
	for _, c := range []struct{ name, source, want string }{
		{"extension", `<style>p[x!=y]{display:none}</style><p>TEXT</p>`, "visible"},
		{"nested extension", `<style>p:not([x!=y]){display:none}</style><p x=y>TEXT</p>`, "visible"},
		{"regex extension", `<style>p[x#=y]{display:none}</style><p x=y>TEXT</p>`, "visible"},
		{"empty middle", `<style>p,,.absent{display:none}</style><p>TEXT</p>`, "visible"},
		{"empty first", `<style>,p{display:none}</style><p>TEXT</p>`, "visible"},
		{"empty last", `<style>p,{display:none}</style><p>TEXT</p>`, "visible"},
		{"valid list", `<style>p,.absent{display:none}</style><p>TEXT</p>`, "concealed"},
		{"variable inset", `<p style="position:absolute;--x:-9999px auto auto -9999px;inset:var(--x)">TEXT</p>`, "unknown"},
		{"logical variable inset", `<p style="position:absolute;--a:-9999px auto;inset-inline:var(--a)">TEXT</p>`, "unknown"},
		{"invalid variable arity", `<p style="position:absolute;--a:-9999px auto auto;inset-inline:var(--a)">TEXT</p>`, "visible"},
		{"variable longhand override", `<p style="position:absolute;--a:-9999px auto auto -9999px;inset:var(--a);top:auto;left:auto">TEXT</p>`, "visible"},
		{"variable important", `<p style="position:absolute;--a:-9999px auto auto -9999px;inset:var(--a)!important;top:auto;left:auto">TEXT</p>`, "unknown"},
		{"scale", `<p style="font-size:1px;scale:20">TEXT</p>`, "unknown"},
		{"ancestor scale", `<div style="scale:20"><p style="font-size:1px">TEXT</p></div>`, "unknown"},
		{"independent scale reset", `<p style="font-size:1px;scale:20;transform:none">TEXT</p>`, "unknown"},
		{"scale reset", `<p style="font-size:1px;scale:20;scale:none">TEXT</p>`, "concealed"},
		{"scale zero", `<p style="scale:0">TEXT</p>`, "unknown"},
		{"identity scale", `<p style="scale:1">TEXT</p>`, "visible"},
		{"translate", `<p style="translate:-9999px">TEXT</p>`, "unknown"},
		{"rotate", `<p style="rotate:y 90deg">TEXT</p>`, "unknown"},
		{"independent hide", `<div style="display:none"><p style="scale:20;translate:-9999px">TEXT</p></div>`, "concealed"},
		{"heading default", `<body style="font-size:1.5px"><h1>TEXT</h1></body>`, "visible"},
		{"heading inherit", `<body style="font-size:1.5px"><h1 style="font-size:inherit">TEXT</h1></body>`, "concealed"},
		{"heading zero", `<body style="font-size:0"><h1>TEXT</h1></body>`, "concealed"},
		{"small default", `<div style="font-size:2.2px"><small>TEXT</small></div>`, "concealed"},
		{"font adjustment", `<p style="font-size:1px;font-size-adjust:10">TEXT</p>`, "unknown"},
		{"font adjustment inherited", `<div style="font-size-adjust:10"><p style="font-size:1px">TEXT</p></div>`, "unknown"},
		{"font adjustment reset", `<div style="font-size-adjust:10"><p style="font-size:1px;font-size-adjust:none">TEXT</p></div>`, "concealed"},
		{"relative offset", `<p style="position:relative;left:-9999px">TEXT</p>`, "unknown"},
		{"static offset", `<p style="position:static;left:-9999px">TEXT</p>`, "visible"},
		{"logical overflow", `<div style="height:0;overflow-block:hidden">TEXT</div>`, "unknown"},
		{"logical overflow normal size", `<div style="height:20px;overflow-block:hidden">TEXT</div>`, "visible"},
		{"logical overflow contents", `<div style="display:contents;height:0;overflow-block:hidden">TEXT</div>`, "unknown"},
		{"column", `<div style="display:table-column">TEXT</div>`, "unknown"},
		{"column group", `<div style="display:table-column-group"><span>TEXT</span></div>`, "unknown"},
		{"column override", `<div style="display:table-column;display:block">TEXT</div>`, "visible"},
		{"popover unchanged", `<div popover>TEXT</div>`, "visible"},
		{"dark variable loses", `<style>p{--x:none!important;display:var(--x)}@media(prefers-color-scheme:dark){p{--x:block}}</style><p>TEXT</p>`, "concealed"},
		{"dark variable wins", `<style>p{--x:none;display:var(--x)}@media(prefers-color-scheme:dark){p{--x:block}}</style><p>TEXT</p>`, "unknown"},
		{"dark inherited dependency", `<style>div{--x:none}@media(prefers-color-scheme:dark){div{--x:block}}</style><div><p style="display:var(--x)">TEXT</p></div>`, "unknown"},
		{"dark indirect losing", `<style>p{--x:none!important;--y:var(--x);display:var(--y)}@media(prefers-color-scheme:dark){p{--x:block}}</style><p>TEXT</p>`, "concealed"},
		{"dark scale reveals", `<style>p{font-size:1px}@media(prefers-color-scheme:dark){p{scale:20}}</style><p>TEXT</p>`, "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := inspectHTML(t, c.source)
			if got := findText(t, d, "TEXT").Label; got != c.want {
				t.Fatalf("label = %s, want %s", got, c.want)
			}
		})
	}
}

func TestVariableEdgeShorthandEquivalence(t *testing.T) {
	for _, property := range []string{"inset", "inset-inline", "inset-block", "margin", "margin-inline", "margin-block"} {
		for _, value := range []string{"-9999px", "-9999px auto", "0 auto -9999px", "0 auto auto -9999px"} {
			t.Run(property+"/"+value, func(t *testing.T) {
				literal := inspectHTML(t, `<p style="position:absolute;`+property+`:`+value+`">TEXT</p>`)
				variable := inspectHTML(t, `<p style="position:absolute;--a:`+value+`;--b:var(--a);`+property+`:var(--b)">TEXT</p>`)
				if a, b := findText(t, literal, "TEXT").Label, findText(t, variable, "TEXT").Label; a != b {
					t.Fatalf("literal %s, variable %s", a, b)
				}
			})
		}
	}
}
