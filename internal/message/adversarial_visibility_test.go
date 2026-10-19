package message

import "testing"

func TestAdversarialVisibilityOutput(t *testing.T) {
	for _, c := range []struct{ source, want string }{
		{`<input type=button value=TEXT style="font-size:0">`, `<invisible reason="font-size" value="0px">TEXT</invisible>`},
		{`<input type=submit value=TEXT style="font-size:0">`, `<invisible reason="font-size" value="0px">TEXT</invisible>`},
		{`<input type=reset value=TEXT style="font-size:0">`, `<invisible reason="font-size" value="0px">TEXT</invisible>`},
		{`<input type=button value=TEXT style="color:white;background:white">`, `<invisible reason="color-match">TEXT</invisible>`},
		{`<input type=button value=TEXT>`, `TEXT`},
		{`<style>p,{display:none}</style><p>TEXT</p>`, `TEXT`},
		{`<p style="font-size:1px;scale:20">TEXT</p>`, `<visibility-uncertain>TEXT</visibility-uncertain>`},
		{`<p style="position:absolute;--x:-9999px auto auto -9999px;inset:var(--x)">TEXT</p>`, `<visibility-uncertain>TEXT</visibility-uncertain>`},
	} {
		t.Run(c.source, func(t *testing.T) {
			m := New(10000)
			m.AddHeader("Content-Type", "text/html")
			m.AddBody([]byte(c.source))
			if got := m.ProcessedBody(10000); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}
