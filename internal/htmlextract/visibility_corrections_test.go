package htmlextract

import "testing"

func TestVisibilityAuditRegressions(t *testing.T) {
	for _, c := range []struct{ name, source, want string }{
		{"link-default-colour", "<body style=\"color:white\"><a href=\"https://example.invalid\">TEXT</a></body>", "visible"},
		{"body-text", "<body text=white>TEXT</body>", "concealed"},
		{"body-link-hint", "<body link=white><a href=\"https://example.invalid\">TEXT</a></body>", "unknown"},
		{"details-closed", "<details><summary>SUMMARY</summary><p>TEXT</p></details>", "unknown"},
		{"dialog-closed", "<dialog>TEXT</dialog>", "unknown"},
		{"datalist", "<datalist><option>TEXT</option></datalist>", "unknown"},
		{"ruby-fallback", "<ruby>A<rp>TEXT</rp><rt>B</rt></ruby>", "unknown"},
		{"canvas-fallback", "<canvas>TEXT</canvas>", "unknown"},
		{"object-fallback", "<object data=\"missing.png\" type=\"image/png\"><p>TEXT</p></object>", "unknown"},
		{"overflow-auto-zero", "<div style=\"height:0;overflow:auto\">TEXT</div>", "unknown"},
		{"overflow-scroll-zero", "<div style=\"height:0;overflow:scroll\">TEXT</div>", "unknown"},
		{"logical-size-zero", "<div style=\"block-size:0;overflow:hidden\">TEXT</div>", "unknown"},
		{"logical-offset", "<p style=\"position:absolute;inset-inline-start:-9999px\">TEXT</p>", "unknown"},
		{"logical-inset-shorthand", "<p style=\"position:absolute;inset:-9999px auto auto -9999px\">TEXT</p>", "unknown"},
		{"zoom-enlarges-small", "<p style=\"font-size:1px;zoom:20\">TEXT</p>", "unknown"},
		{"transform-enlarges-small", "<p style=\"font-size:1px;transform:scale(20);transform-origin:0 0\">TEXT</p>", "unknown"},
		{"zoom-enlarges-small-child", "<div style=\"zoom:20\"><p style=\"font-size:1px\">TEXT</p></div>", "unknown"},
		{"list-invalid-attribute", "<style>p, .absent[foo=]{display:none}</style><p>TEXT</p>", "visible"},
		{"background-reset", "<p style=\"background-clip:text;background:white;color:white\">TEXT</p>", "concealed"},
		{"shadow-reset", "<div style=\"color:white;text-shadow:0 0 1px black\"><span style=\"text-shadow:none\">TEXT</span></div>", "concealed"},
		{"indent-reset", "<div style=\"text-indent:-9999px\"><p style=\"text-indent:0\">TEXT</p></div>", "visible"},
		{"fill-currentcolor-reset", "<div style=\"-webkit-text-fill-color:transparent\"><span style=\"-webkit-text-fill-color:currentcolor;color:black\">TEXT</span></div>", "visible"},
		{"dark-rule-overridden", "<style>p{display:none!important}@media(prefers-color-scheme:dark){p{display:block}}</style><p>TEXT</p>", "concealed"},
		{"dark-child-ancestor", "<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p>TEXT</p></div>", "concealed"},
		{"animation-display-none", "<style>@keyframes k{to{color:red}}</style><div style=\"display:none\"><p style=\"animation:k 1s infinite\">TEXT</p></div>", "concealed"},
		{"animation-parent-child", "<style>@keyframes k{to{opacity:0}}</style><div style=\"animation:k 1s infinite\"><p style=\"display:none\">TEXT</p></div>", "concealed"},
		{"invalid-all", "<p style=\"display:none;all:bananas\">TEXT</p>", "concealed"},
		{"invalid-filter", "<p style=\"filter:bananas\">TEXT</p>", "visible"},
		{"invalid-clip", "<p style=\"clip-path:bananas\">TEXT</p>", "visible"},
		{"details-open", "<details open><summary>SUMMARY</summary><p>TEXT</p></details>", "visible"},
		{"dialog-open", "<dialog open>TEXT</dialog>", "visible"},
		{"body-text-author", "<body text=white style=\"color:black\">TEXT</body>", "visible"},
		{"link-explicit-inherit", "<body style=\"color:white\"><a href=\"https://example.invalid\" style=\"color:inherit\">TEXT</a></body>", "concealed"},
		{"dark-independent-hide", "<style>div{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><div><p style=\"visibility:hidden\">TEXT</p></div>", "concealed"},
		{"animation-none-important", "<style>@keyframes k{to{opacity:0}}</style><p style=\"animation-name:none!important;animation:k 1s infinite\">TEXT</p>", "visible"},
		{"logical margin", `<p style="margin-inline-start:-9999px">TEXT</p>`, "unknown"},
		{"shrinking zoom", `<p style="zoom:.1">TEXT</p>`, "unknown"},
		{"overflow axis interaction", "<div style=\"width:0;overflow-y:auto\">TEXT</div>", "unknown"},
		{"ordinary scroll container", "<div style=\"height:100px;overflow:auto\">TEXT</div>", "visible"},
		{"logical vertical size", "<div style=\"writing-mode:vertical-rl;block-size:0;overflow:hidden\">TEXT</div>", "unknown"},
		{"logical offset shorthand", "<div style=\"position:absolute;inset-inline:-9999px auto\">TEXT</div>", "unknown"},
		{"invalid two sided shorthand", "<div style=\"position:absolute;inset-inline:-9999px auto auto\">TEXT</div>", "visible"},
		{"scale independent hiding", "<div style=\"display:none\"><p style=\"font-size:1px;zoom:20\">TEXT</p></div>", "concealed"},
		{"scale zero invariant", "<p style=\"font-size:0;transform:scale(20)\">TEXT</p>", "concealed"},
		{"background variable reset", "<p style=\"--bg:white;background-clip:text;background:var(--bg);color:white\">TEXT</p>", "concealed"},
		{"background important clip", "<p style=\"background-clip:text!important;background:white;color:white\">TEXT</p>", "unknown"},
		{"shadow inherited", "<div style=\"color:white;text-shadow:0 0 1px black\"><span>TEXT</span></div>", "unknown"},
		{"group effect persists", "<div style=\"filter:blur(1px)\"><span style=\"filter:none\">TEXT</span></div>", "unknown"},
		{"indent inherited", "<div style=\"text-indent:-9999px\"><p>TEXT</p></div>", "unknown"},
		{"spacing reset", "<div style=\"letter-spacing:-9999px\"><p style=\"letter-spacing:normal\">TEXT</p></div>", "visible"},
		{"dark winning reveal", "<style>p{display:none}@media(prefers-color-scheme:dark){p{display:block}}</style><p>TEXT</p>", "unknown"},
		{"same node animation", "<style>@keyframes k{to{display:block}}</style><p style=\"display:none;animation:k 1s infinite\">TEXT</p>", "unknown"},
		{"both link hints white", "<body link=white vlink=white><a href=x>TEXT</a></body>", "concealed"},
		{"link author override", "<body link=white vlink=white><a href=x style=\"color:black\">TEXT</a></body>", "visible"},
		{"native author override", "<dialog style=\"display:block\">TEXT</dialog>", "visible"},
		{"details second summary", "<details><summary>SUMMARY</summary><summary>TEXT</summary></details>", "unknown"},
		{"details direct text", "<details><summary>SUMMARY</summary>TEXT</details>", "unknown"},
		{"object style uncertain", "<object><style>p{display:none}</style></object><p>TEXT</p>", "unknown"},
		{"invalid first selector", "<style>.absent[foo=], p{display:none}</style><p>TEXT</p>", "visible"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := inspectHTML(t, c.source)
			if got := findText(t, d, "TEXT").Label; got != c.want {
				t.Fatalf("label=%s, want %s", got, c.want)
			}
		})
	}
}
