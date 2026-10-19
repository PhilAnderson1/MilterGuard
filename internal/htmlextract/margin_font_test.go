package htmlextract

import "testing"

func TestFontRelativeMargins(t *testing.T) {
	for _, c := range []struct{ name, html, want string }{
		{"ordinary paragraph", `<p style="font-size:14px;margin-bottom:1em">TEXT</p>`, "visible"},
		{"element font", `<div style="font-size:2000px"><p style="font-size:14px;margin:1em">TEXT</p></div>`, "visible"},
		{"extreme element font", `<div style="font-size:14px"><p style="font-size:2000px;margin:1em">TEXT</p></div>`, "unknown"},
		{"root font", `<html style="font-size:14px"><p style="font-size:2000px;margin:1rem">TEXT</p></html>`, "visible"},
		{"extreme root font", `<html style="font-size:2000px"><p style="font-size:14px;margin:1rem">TEXT</p></html>`, "unknown"},
		{"root own margin", `<html style="font-size:2000px;margin:1rem"><p style="font-size:14px">TEXT</p></html>`, "unknown"},
		{"negative boundary", `<p style="font-size:20px;margin-left:-50em">TEXT</p>`, "unknown"},
		{"below boundary", `<p style="font-size:20px;margin-left:-49em">TEXT</p>`, "visible"},
		{"variable shorthand", `<p style="font-size:14px;--m:1em 2rem;margin:var(--m)">TEXT</p>`, "visible"},
		{"logical margin", `<p style="font-size:14px;margin-block-end:1em">TEXT</p>`, "visible"},
		{"unresolved font", `<p style="font-size:1vw;margin:1em">TEXT</p>`, "unknown"},
		{"unresolved root", `<html style="font-size:1vw"><p style="font-size:14px;margin:1rem">TEXT</p></html>`, "unknown"},
		{"unresolved calculation", `<p style="font-size:14px;margin:calc(1em + 1px)">TEXT</p>`, "unknown"},
		{"unresolved viewport", `<p style="font-size:14px;margin:1vh">TEXT</p>`, "unknown"},
		{"overflow", `<p style="font-size:14px;margin:1e308em">TEXT</p>`, "unknown"},
		{"hidden ancestor", `<div style="display:none"><p style="font-size:14px;margin:1em">TEXT</p></div>`, "concealed"},
		{"responsive font", `<style>@media(max-width:768px){p{font-size:17px!important}}</style><p style="font-size:14px;margin-bottom:1em">TEXT</p>`, "visible"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := inspectHTML(t, c.html)
			if got := findText(t, d, "TEXT").Label; got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}
