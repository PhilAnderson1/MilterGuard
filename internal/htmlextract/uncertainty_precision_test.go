package htmlextract

import "testing"

func TestUncertaintyPrecision(t *testing.T) {
	for _, c := range []struct{ name, html, want string }{
		{"ordinary ex", `<p style="font-size:16px;margin-left:.8ex">TEXT</p>`, "visible"},
		{"extreme ex", `<p style="font-size:16px;margin-left:32ex">TEXT</p>`, "unknown"},
		{"negative ex", `<p style="font-size:16px;margin-left:-32ex">TEXT</p>`, "unknown"},
		{"unknown ex font", `<p style="font-size:1vw;margin-left:.8ex">TEXT</p>`, "unknown"},
		{"overflow ex", `<p style="font-size:16px;margin-left:1e308ex">TEXT</p>`, "unknown"},
		{"conditional zero", `<!--[if mso]><style>.x{margin:0!important}</style><![endif]--><div class=x>TEXT</div>`, "visible"},
		{"conditional zero unsafe ordinary", `<style>.x{margin-left:-2000px}</style><!--[if mso]><style>.x{margin:0!important}</style><![endif]--><div class=x>TEXT</div>`, "unknown"},
		{"conditional zero unresolved ordinary", `<style>.x{margin-left:calc(1px - 2000px)}</style><!--[if mso]><style>.x{margin:0!important}</style><![endif]--><div class=x>TEXT</div>`, "unknown"},
		{"earlier conditional dangerous", `<!--[if mso]><style>.x{margin-left:-2000px}</style><![endif]--><!--[if !mso]><style>.x{margin:0!important}</style><![endif]--><div class=x>TEXT</div>`, "unknown"},
		{"ordinary overrides dangerous", `<style>.x{margin-left:-2000px}.x{margin-left:5px}</style><!--[if mso]><style>.x{margin:0!important}</style><![endif]--><div class=x>TEXT</div>`, "visible"},
		{"conditional variable stays conservative", `<!--[if mso]><style>.x{margin:var(--m)!important}</style><![endif]--><div class=x style="--m:0">TEXT</div>`, "unknown"},
		{"percentage line height", `<div style="font-size:16px;line-height:160%"><p style="overflow:auto">TEXT</p></div>`, "visible"},
		{"em line height", `<div style="font-size:16px;line-height:1.6em"><p style="overflow:auto">TEXT</p></div>`, "visible"},
		{"zero font inherited length", `<div style="font-size:0;line-height:160%"><p style="font-size:16px;overflow:auto">TEXT</p></div>`, "unknown"},
		{"unknown line height", `<div style="font-size:1vw;line-height:160%"><p style="font-size:16px;line-height:inherit;overflow:auto">TEXT</p></div>`, "unknown"},
		{"missing checked sibling", `<style>#absent:checked+table{margin-left:-2000px}</style><table><tr><td>TEXT</td></tr></table>`, "visible"},
		{"possible checked sibling", `<style>#x:checked+table{margin-left:-2000px}</style><input id=x type=checkbox><table><tr><td>TEXT</td></tr></table>`, "unknown"},
		{"missing general sibling", `<style>#absent:checked~p{margin-left:-2000px}</style><p>TEXT</p>`, "visible"},
		{"possible general sibling", `<style>#x:checked~p{margin-left:-2000px}</style><input id=x type=checkbox><span></span><p>TEXT</p>`, "unknown"},
		{"negated constraint", `<style>:not(#absent):checked+p{margin-left:-2000px}</style><input type=checkbox><p>TEXT</p>`, "unknown"},
		{"covered gradient", `<div style="background:linear-gradient(red,blue)"><p style="color:black;background:white">TEXT</p></div>`, "visible"},
		{"uncovered gradient", `<div style="background:linear-gradient(red,blue)"><p style="color:black">TEXT</p></div>`, "unknown"},
		{"transparent child", `<div style="background:linear-gradient(red,blue)"><p style="color:black;background:rgba(255,255,255,.5)">TEXT</p></div>`, "unknown"},
		{"text clipped gradient", `<div style="background:linear-gradient(red,blue) text"><p style="color:black;background:white">TEXT</p></div>`, "unknown"},
		{"covered radial gradient", `<div style="background:radial-gradient(circle at center,#221d13 0%,#121216 85%)"><p style="color:black;background:white">TEXT</p></div>`, "visible"},
		{"invalid gradient keeps clip uncertain", `<div style="background:linear-gradient(nonsense,blue)"><p style="color:black;background:white">TEXT</p></div>`, "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := inspectHTML(t, c.html)
			if got := findText(t, d, "TEXT").Label; got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

func TestComputedLineHeightInheritance(t *testing.T) {
	for _, c := range []struct {
		name, decl, child string
		want              float64
	}{
		{"percent", "160%", "", 25.6}, {"em", "1.6em", "", 25.6},
		{"explicit inherit", "160%", "line-height:inherit;", 25.6},
		{"variable inherit", "160%", "--lh:inherit;line-height:var(--lh);", 25.6},
		{"unitless", "1.6", "", 1.6},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := inspectHTML(t, `<div style="font-size:16px;line-height:`+c.decl+`"><p style="font-size:32px;`+c.child+`">TEXT</p></div>`)
			v := findText(t, d, "TEXT").inspection.style[lineHeight]
			if !v.Known || v.Number != c.want {
				t.Fatalf("line height %+v want %g", v, c.want)
			}
		})
	}
}
