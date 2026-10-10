package message

import (
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestHTMLPreservesLinkTextAndDestination(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>Sign in to <a href="https://evil.example/login"><strong>Microsoft</strong></a>.</p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "Sign in to [Microsoft](https://evil.example/login).") {
		t.Fatalf("link evidence missing: %s", prompt)
	}
}

func TestHTMLMarksQuotedContentAndPreservesItsLinks(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>Current reply</p><blockquote>Earlier message <a href="https://example.invalid/profile">profile</a></blockquote>`))
	prompt := m.Prompt(1000)
	want := "Current reply\n\n[quoted content begins]\nEarlier message [profile](https://example.invalid/profile)\n[quoted content ends]"
	if !strings.Contains(prompt, want) {
		t.Fatalf("HTML quote structure or link was not preserved: %s", prompt)
	}
}

func TestHTMLQuoteMarkersInsideAnchorDoNotBreakMarkdownLink(t *testing.T) {
	got := htmlToText(`<a href="https://example.invalid/"><blockquote>Quoted message</blockquote></a>`)
	want := `[\[quoted content begins\] Quoted message \[quoted content ends\]](https://example.invalid/)`
	if got.Text != want {
		t.Fatalf("quoted anchor = %q, want %q", got.Text, want)
	}
}

func TestHTMLExcludesScriptAndStyle(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<style>.hidden{display:none}</style><script>ignoreMe()</script><p>Visible</p>`))
	prompt := m.Prompt(1000)
	if strings.Contains(prompt, "ignoreMe") || strings.Contains(prompt, "display:none") {
		t.Fatalf("active HTML content leaked into prompt: %s", prompt)
	}
	if !strings.Contains(prompt, "Visible") {
		t.Fatalf("visible text missing: %s", prompt)
	}
}

func TestHTMLAnnotatesExplicitlyConcealedSubtrees(t *testing.T) {
	for _, test := range []struct {
		tag, reason string
	}{
		{`<div hidden>`, "display:none"},
		{`<div style="display:none">`, "display:none"},
		{`<div style="visibility: hidden">`, "visibility:hidden"},
		{`<div style="visibility:collapse">`, "visibility:collapse"},
		{`<div style="content:'display:none;'; display: none !important; display:block">`, "display:none"},
	} {
		t.Run(test.tag, func(t *testing.T) {
			got := htmlToText(`Before ` + test.tag + `<div>Forged conversation <a href="https://hidden.example/">trusted sender</a></div></div> After`)
			concealed := `<concealed reason="` + test.reason + `">Forged conversation [trusted sender](https://hidden.example/)</concealed>`
			if !strings.Contains(got.Text, concealed) {
				t.Fatalf("concealment annotation missing: %q", got.Text)
			}
			if strings.Contains(got.VisibleText, "Forged conversation") || strings.Contains(got.VisibleText, "trusted sender") {
				t.Fatalf("concealed text counted as visible: %q", got.VisibleText)
			}
			if !strings.Contains(got.StrippedText, "<hidden-content-stripped/>") || strings.Contains(got.StrippedText, "Forged conversation") {
				t.Fatalf("stripped representation = %q", got.StrippedText)
			}
			if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/" {
				t.Fatalf("concealed link evidence = %v", got.Links)
			}
		})
	}
}

func TestHTMLRawTextCannotEscapeConcealedAncestor(t *testing.T) {
	for _, test := range []struct {
		element   string
		retainRaw bool
	}{
		{element: "script"},
		{element: "style"},
		{element: "iframe"},
		{element: "title"},
		{element: "textarea", retainRaw: true},
		{element: "xmp", retainRaw: true},
		{element: "noembed"},
		{element: "noframes"},
	} {
		t.Run(test.element, func(t *testing.T) {
			html := `Before<div style="display:none"><` + test.element + `>raw </div> marker</` + test.element + `>` +
				`Forged conversation <a href="https://hidden.example/">trusted sender</a></div>After`
			got := htmlToText(html)
			concealedText := "Forged conversation "
			if test.retainRaw {
				concealedText = "raw </div> marker" + concealedText
			}
			concealed := `<concealed reason="display:none">` + concealedText + `[trusted sender](https://hidden.example/)</concealed>`
			if !strings.Contains(got.Text, concealed) {
				t.Fatalf("content escaped concealed ancestor: %q", got.Text)
			}
			if strings.Contains(got.VisibleText, "raw") || strings.Contains(got.VisibleText, "Forged conversation") || strings.Contains(got.VisibleText, "trusted sender") {
				t.Fatalf("concealed content counted as visible: %q", got.VisibleText)
			}
			if strings.Contains(got.Text, "raw </div> marker") != test.retainRaw {
				t.Fatalf("%s raw-text retention = %q", test.element, got.Text)
			}
			if !strings.Contains(got.StrippedText, "<hidden-content-stripped/>") || strings.Contains(got.StrippedText, "Forged conversation") {
				t.Fatalf("stripped representation = %q", got.StrippedText)
			}
			if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/" {
				t.Fatalf("concealed link evidence = %v", got.Links)
			}
		})
	}
}

func TestHTMLVisibilityUsesExactStylesAndCSSPrecedence(t *testing.T) {
	for _, tag := range []string{
		`<p data-hidden style="content:'display:none'; display:block">`,
		`<p style="display:none; display:block">`,
		`<p style="display:none; display:block !important">`,
	} {
		got := htmlToText(tag + `Visible</p>`)
		if got.Text != "Visible" {
			t.Fatalf("visible element omitted for %q: %q", tag, got.Text)
		}
	}
	got := htmlToText(`<p style="display:none !important; display:block">Hidden</p>Visible`)
	if got.Text != `<concealed reason="display:none">Hidden</concealed>`+"\nVisible" {
		t.Fatalf("important hidden style lost precedence: %q", got.Text)
	}
	if got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>\nVisible" {
		t.Fatalf("important hidden representations: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
}

func TestHTMLInlineDisplayCanOverrideHiddenAttribute(t *testing.T) {
	got := htmlToText(`<div hidden style="display:block">Visible ` +
		`<a href="https://visible.example/login">Open</a>` +
		`<img src="cid:visible-image" alt="Invoice"></div>`)
	if !strings.Contains(got.Text, "Visible [Open](https://visible.example/login)") ||
		!strings.Contains(got.Text, "![Invoice](cid:visible-image)") {
		t.Fatalf("display override content missing from text: %q", got.Text)
	}
	if got.VisibleText != "Visible Open" {
		t.Fatalf("display override visible text = %q", got.VisibleText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://visible.example/login" {
		t.Fatalf("display override links = %v", got.Links)
	}
	if len(got.ImageRefs) != 1 || got.ImageRefs[0] != "visible-image" {
		t.Fatalf("display override image references = %v", got.ImageRefs)
	}
}

func TestHTMLHiddenAttributesRespectEffectivePresentation(t *testing.T) {
	for _, test := range []struct {
		tag, reason string
	}{
		{`<div hidden style="display:not-a-display-value">`, "display:none"},
		{`<div hidden="until-found" style="display:block">`, "content-visibility:hidden"},
	} {
		got := htmlToText(test.tag + `Hidden</div>Visible`)
		want := `<concealed reason="` + test.reason + `">Hidden</concealed>` + "\nVisible"
		if got.Text != want || got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>\nVisible" {
			t.Fatalf("hidden presentation for %q: %+v", test.tag, got)
		}
	}
}

func TestHTMLVisibilityHiddenAllowsExplicitlyVisibleDescendants(t *testing.T) {
	got := htmlToText(`<div style="visibility:hidden">Hidden parent ` +
		`<section><span style="visibility:visible">Visible ` +
		`<a href="https://visible.example/login">Open</a>` +
		`<img src="cid:visible-image" alt="Invoice"></span></section>` +
		`Hidden tail</div>`)
	if !strings.Contains(got.Text, "Visible [Open](https://visible.example/login)") ||
		!strings.Contains(got.Text, "![Invoice](cid:visible-image)") ||
		!strings.Contains(got.Text, `<concealed reason="visibility:hidden">Hidden parent </concealed>`) ||
		!strings.Contains(got.Text, `<concealed reason="visibility:hidden">Hidden tail</concealed>`) {
		t.Fatalf("visibility override text = %q", got.Text)
	}
	if got.VisibleText != "Visible Open" {
		t.Fatalf("visibility override visible text = %q", got.VisibleText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://visible.example/login" {
		t.Fatalf("visibility override links = %v", got.Links)
	}
	if len(got.ImageRefs) != 1 || got.ImageRefs[0] != "visible-image" {
		t.Fatalf("visibility override image references = %v", got.ImageRefs)
	}
	if strings.Contains(got.StrippedText, "Hidden parent") || strings.Contains(got.StrippedText, "Hidden tail") ||
		!strings.Contains(got.StrippedText, "Visible [Open](https://visible.example/login)") {
		t.Fatalf("visibility override stripped text = %q", got.StrippedText)
	}
}

func TestHTMLDisplayNonePreventsVisibilityOverride(t *testing.T) {
	got := htmlToText(`<div style="display:none"><span style="visibility:visible">` +
		`Hidden <a href="https://hidden.example/">link</a>` +
		`<img src="cid:hidden-image"></span></div>Visible`)
	if !strings.Contains(got.Text, `<concealed reason="display:none">Hidden [link](https://hidden.example/) ![embedded image](cid:hidden-image) </concealed>`) {
		t.Fatalf("display-hidden evidence = %q", got.Text)
	}
	if got.VisibleText != "Visible" || strings.Contains(got.StrippedText, "Hidden") || !strings.Contains(got.StrippedText, "<hidden-content-stripped/>") {
		t.Fatalf("display-hidden representations: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/" || len(got.ImageRefs) != 1 || got.ImageRefs[0] != "hidden-image" {
		t.Fatalf("display-hidden metadata: links=%v images=%v", got.Links, got.ImageRefs)
	}
}

func TestHTMLHiddenVoidElementDoesNotHideFollowingText(t *testing.T) {
	got := htmlToText(`<img hidden src="https://hidden.example/image.png" alt="Forgery">Visible`)
	if got.Text != `<concealed reason="display:none"> ![Forgery](https://hidden.example/image.png) </concealed>Visible` {
		t.Fatalf("hidden void-element representation = %q", got.Text)
	}
	if got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>Visible" {
		t.Fatalf("hidden void-element visibility: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/image.png" {
		t.Fatalf("hidden image destination = %v", got.Links)
	}
}

func TestHTMLUnclosedHiddenSubtreeDoesNotLeakIntoAIText(t *testing.T) {
	got := htmlToText(`Visible<div style="display:none">Forged correspondence`)
	if got.Text != "Visible\n"+`<concealed reason="display:none">Forged correspondence</concealed>` ||
		got.VisibleText != "Visible" || got.StrippedText != "Visible\n<hidden-content-stripped/>" {
		t.Fatalf("unclosed hidden subtree leaked: %+v", got)
	}
}

func TestHTMLConcealedOptionalEndElementsFollowImpliedClosures(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "paragraph block start", source: `<p hidden>forged<div>Visible paragraph successor</div>`, want: "Visible paragraph successor"},
		{name: "paragraph ancestor end", source: `<div><p hidden>forged</div>Visible after container`, want: "Visible after container"},
		{name: "paragraph before plaintext", source: `<p hidden>forged<plaintext>Visible plaintext`, want: "Visible plaintext"},
		{name: "list item sibling", source: `<ul><li hidden>forged<li>Visible list item</ul>`, want: "Visible list item"},
		{name: "definition sibling", source: `<dl><dt hidden>forged<dd>Visible definition</dl>`, want: "Visible definition"},
		{name: "table cell sibling", source: `<table><tr><td hidden>forged<td>Visible cell</table>`, want: "Visible cell"},
		{name: "table row sibling", source: `<table><tr hidden><td>forged<tr><td>Visible row</table>`, want: "Visible row"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			if !strings.Contains(got.Text, `<concealed reason="display:none">forged</concealed>`) || !strings.Contains(got.Text, test.want) {
				t.Fatalf("implied-closure representation = %q", got.Text)
			}
			if got.VisibleText != test.want {
				t.Fatalf("implied-closure visible text = %q, want %q", got.VisibleText, test.want)
			}
			if strings.Contains(got.StrippedText, "forged") || !strings.Contains(got.StrippedText, "<hidden-content-stripped/>") || !strings.Contains(got.StrippedText, test.want) {
				t.Fatalf("implied-closure stripped text = %q", got.StrippedText)
			}
		})
	}
}

func TestHTMLHiddenOptionalEndElementsRespectNestedScopes(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		visible     string
		destination string
	}{
		{
			name: "nested list",
			source: `<ul><li hidden>outer<ul><li>nested <a href="https://hidden.example/list">link</a></li></ul>` +
				`still hidden</li><li>Visible list item</li></ul>`,
			visible:     "Visible list item",
			destination: "https://hidden.example/list",
		},
		{
			name: "nested table",
			source: `<table><tr><td hidden>outer<table><tr><td>nested <a href="https://hidden.example/table">link</a></td></tr></table>` +
				`still hidden</td><td>Visible cell</td></tr></table>`,
			visible:     "Visible cell",
			destination: "https://hidden.example/table",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			wantText := `<concealed reason="display:none">outer` + "\n\n" +
				`nested [link](` + test.destination + `)` + "\n\n" +
				`still hidden</concealed>` + "\n\n" + test.visible
			if got.Text != wantText {
				t.Fatalf("nested concealed subtree text = %q, want %q", got.Text, wantText)
			}
			if got.VisibleText != test.visible {
				t.Fatalf("nested concealed subtree visible text = %q, want %q", got.VisibleText, test.visible)
			}
			if got.StrippedText != "<hidden-content-stripped/>\n\n"+test.visible {
				t.Fatalf("nested concealed subtree stripped text = %q", got.StrippedText)
			}
			if len(got.Links) != 1 || got.Links[0] != test.destination {
				t.Fatalf("nested concealed subtree links = %v", got.Links)
			}
		})
	}
}

func TestConcealedHTMLDoesNotSatisfyFallbackImageTextThreshold(t *testing.T) {
	m := multipartRelatedMessage("Fallback", `<p>Short notice</p><div style="display:none">`+strings.Repeat("forged history ", 30)+`</div><img src="cid:scam-image" alt="Notice">`, "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("concealed text satisfied fallback threshold: selected images=%d", len(analysis.Images))
	}
	if !strings.Contains(analysis.Prompt, `<concealed reason="display:none">forged history `) {
		t.Fatalf("concealed evidence missing from prompt: %s", analysis.Prompt)
	}
}

func TestZeroOpacityHTMLDoesNotSatisfyFallbackImageTextThreshold(t *testing.T) {
	m := multipartRelatedMessage("Fallback", `<p>Short notice</p><div style="opacity:0">`+strings.Repeat("forged history ", 30)+`</div><img src="cid:scam-image" alt="Notice">`, "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("zero-opacity text satisfied fallback threshold: selected images=%d", len(analysis.Images))
	}
	if !strings.Contains(analysis.Prompt, `<concealed reason="opacity" value="0">forged history `) {
		t.Fatalf("zero-opacity evidence missing from prompt: %s", analysis.Prompt)
	}
}

func TestHTMLFontSizeZeroAllowsExplicitlySizedDescendants(t *testing.T) {
	got := htmlToText(`<div style="font-size:0">Hidden parent ` +
		`<span>Still hidden</span>` +
		`<span style="font-size:12px">Visible ` +
		`<a href="https://visible.example/login">Open</a>` +
		`<img src="cid:visible-image" alt="Invoice"></span>` +
		`<span style="font-size:1em">Relative remains hidden</span>` +
		`Hidden tail</div>`)
	want := `<concealed reason="font-size" value="0px">Hidden parent Still hidden</concealed>` +
		`Visible [Open](https://visible.example/login) ![Invoice](cid:visible-image) ` +
		`<concealed reason="font-size" value="0px">Relative remains hiddenHidden tail</concealed>`
	if got.Text != want {
		t.Fatalf("font-size override text = %q", got.Text)
	}
	if got.VisibleText != "Visible Open" {
		t.Fatalf("font-size override visible text = %q", got.VisibleText)
	}
	if got.StrippedText != `<hidden-content-stripped/>Visible [Open](https://visible.example/login) ![Invoice](cid:visible-image) <hidden-content-stripped/>` {
		t.Fatalf("font-size override stripped text = %q", got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://visible.example/login" {
		t.Fatalf("font-size override links = %v", got.Links)
	}
	if len(got.ImageRefs) != 1 || got.ImageRefs[0] != "visible-image" {
		t.Fatalf("font-size override image references = %v", got.ImageRefs)
	}
}

func TestHTMLZeroOpacityCannotBeOverriddenByDescendant(t *testing.T) {
	got := htmlToText(`<div style="opacity:0"><span style="opacity:1;font-size:12px;visibility:visible">` +
		`Hidden <a href="https://hidden.example/">link</a><img src="cid:hidden-image"></span></div>Visible`)
	want := `<concealed reason="opacity" value="0">Hidden [link](https://hidden.example/) ![embedded image](cid:hidden-image) </concealed>` + "\nVisible"
	if got.Text != want {
		t.Fatalf("zero-opacity evidence = %q, want %q", got.Text, want)
	}
	if got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>\nVisible" {
		t.Fatalf("zero-opacity representations: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/" || len(got.ImageRefs) != 1 || got.ImageRefs[0] != "hidden-image" {
		t.Fatalf("zero-opacity metadata: links=%v images=%v", got.Links, got.ImageRefs)
	}
}

func TestHTMLVisibilityStylesHonorCascadeAndZeroForms(t *testing.T) {
	for _, test := range []struct {
		source, concealed string
	}{
		{`<span style="opacity:0.0">Hidden</span>Visible`, `<concealed reason="opacity" value="0">Hidden</concealed>Visible`},
		{`<span style="opacity:0%">Hidden</span>Visible`, `<concealed reason="opacity" value="0">Hidden</concealed>Visible`},
		{`<span style="opacity:-1">Hidden</span>Visible`, `<concealed reason="opacity" value="0">Hidden</concealed>Visible`},
		{`<span style="opacity:0 !important;opacity:1">Hidden</span>Visible`, `<concealed reason="opacity" value="0">Hidden</concealed>Visible`},
		{`<span style="font-size:0px">Hidden</span>Visible`, `<concealed reason="font-size" value="0px">Hidden</concealed>Visible`},
		{`<span style="font-size:0 !important;font-size:12px">Hidden</span>Visible`, `<concealed reason="font-size" value="0px">Hidden</concealed>Visible`},
	} {
		got := htmlToText(test.source)
		if got.Text != test.concealed || got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>Visible" {
			t.Fatalf("concealed CSS value for %q: %+v", test.source, got)
		}
	}
	for _, source := range []string{
		`<span style="opacity:0;opacity:1">Visible</span>`,
		`<span style="font-size:0;font-size:12px">Visible</span>`,
	} {
		got := htmlToText(source)
		if got.Text != "Visible" || got.VisibleText != "Visible" {
			t.Fatalf("later visible CSS value was ignored for %q: %+v", source, got)
		}
	}
}

func TestHTMLVisibilityRecognizesCSSEscapes(t *testing.T) {
	for _, test := range []struct {
		source, want string
	}{
		{`<span style="displa\79 :none">Hidden</span>Visible`, `<concealed reason="display:none">Hidden</concealed>Visible`},
		{`<span style="display:n\6f ne">Hidden</span>Visible`, `<concealed reason="display:none">Hidden</concealed>Visible`},
		{`<span style="visi\62 ility:hidden">Hidden</span>Visible`, `<concealed reason="visibility:hidden">Hidden</concealed>Visible`},
		{`<span style="visibility:h\69 dden">Hidden</span>Visible`, `<concealed reason="visibility:hidden">Hidden</concealed>Visible`},
		{`<span style="opa\63 ity:0">Hidden</span>Visible`, `<concealed reason="opacity" value="0">Hidden</concealed>Visible`},
		{`<span style="font-si\7a e:0">Hidden</span>Visible`, `<concealed reason="font-size" value="0px">Hidden</concealed>Visible`},
	} {
		got := htmlToText(test.source)
		if got.Text != test.want || got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>Visible" {
			t.Fatalf("CSS escape concealment for %q: %+v", test.source, got)
		}
	}
}

func TestHTMLEscapedCSSPunctuationDoesNotBecomeDeclarationSyntax(t *testing.T) {
	for _, source := range []string{
		`<span style="display\:none">Visible</span>`,
		`<span style="display\3A none">Visible</span>`,
		`<span style="display:block\;visibility:hidden">Visible</span>`,
	} {
		got := htmlToText(source)
		if got.Text != "Visible" || got.VisibleText != "Visible" {
			t.Fatalf("escaped CSS punctuation became syntax for %q: %+v", source, got)
		}
	}
}

func TestHTMLFontSizeZeroPreservesImageEvidence(t *testing.T) {
	got := htmlToText(`<div style="font-size:0">Hidden padding` +
		`<img src="cid:visible-image" alt="Invoice"></div>`)
	want := `<concealed reason="font-size" value="0px">Hidden padding</concealed> ![Invoice](cid:visible-image)`
	if got.Text != want {
		t.Fatalf("zero-sized text and visible image = %q, want %q", got.Text, want)
	}
	if got.StrippedText != `<hidden-content-stripped/> ![Invoice](cid:visible-image)` {
		t.Fatalf("zero-sized stripped representation = %q", got.StrippedText)
	}
	if got.VisibleText != "" || len(got.ImageRefs) != 1 || got.ImageRefs[0] != "visible-image" {
		t.Fatalf("zero-sized image evidence = %+v", got)
	}
}

func TestHTMLAttributesRequireExactNames(t *testing.T) {
	m := New(4096)
	m.AddHeader("Content-Type", "text/html; charset=UTF-8")
	m.AddBody([]byte(`<a data-href="https://bad.example/" href="https://good.example/">Good</a><img data-src="https://bad.example/a.png" src="https://good.example/a.png" data-alt="Bad" alt="Good image">`))
	prompt := m.Prompt(4096)
	if !strings.Contains(prompt, "[Good](https://good.example/)") || !strings.Contains(prompt, "![Good image](https://good.example/a.png)") {
		t.Fatalf("exact href/src/alt attributes were not used: %s", prompt)
	}
	if strings.Contains(prompt, "bad.example") {
		t.Fatalf("prefixed attribute was mistaken for a real URL attribute: %s", prompt)
	}
}

func TestHTMLExcludesNonRenderedContainers(t *testing.T) {
	for _, element := range []string{"template", "iframe", "title"} {
		t.Run(element, func(t *testing.T) {
			got := htmlToText("Before<" + element + `><a href="https://hidden.example/">AI-only injection</a></` + element + ">After")
			if got.Text != "BeforeAfter" || got.VisibleText != "BeforeAfter" || len(got.Links) != 0 {
				t.Fatalf("non-rendered %s content leaked: text=%q links=%v", element, got.Text, got.Links)
			}
		})
	}
}

func TestHTMLRawTextContainersFollowEvidencePolicy(t *testing.T) {
	for _, test := range []struct {
		element, want string
	}{
		{element: "textarea", want: "Before<b>visible literal text</b>After"},
		{element: "xmp", want: "Before<b>visible literal text</b>After"},
		{element: "noembed", want: "BeforeAfter"},
		{element: "noframes", want: "BeforeAfter"},
	} {
		t.Run(test.element, func(t *testing.T) {
			got := htmlToText("Before<" + test.element + `><b>visible literal text</b></` + test.element + ">After")
			if got.Text != test.want || got.VisibleText != test.want {
				t.Fatalf("raw %s evidence: text=%q visible=%q, want %q", test.element, got.Text, got.VisibleText, test.want)
			}
		})
	}
}

func TestHTMLEntitiesAreDecodedExactlyOnce(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "ordinary text", source: `<p>&amp;#106; &amp;</p>`, want: `&#106; &`},
		{name: "image alt", source: `<img alt="&amp;#106;" src="https://example.test/image.png">`, want: `![&#106;](https://example.test/image.png)`},
		{name: "link URL", source: `<a href="https://example.test/?a=1&amp;amp;b=2">link</a>`, want: `[link](https://example.test/?a=1&amp;b=2)`},
		{name: "textarea", source: `<textarea>&amp;#106;</textarea>`, want: `&#106;`},
		{name: "xmp", source: `<xmp>&amp;#106;</xmp>`, want: `&amp;#106;`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			if got.Text != test.want {
				t.Fatalf("extracted text = %q, want %q", got.Text, test.want)
			}
		})
	}
}

func TestHTMLAnchorLabelsCannotInjectMarkdownLinks(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "literal brackets",
			source: `<a href="https://good.example/">Login to PayPal](https://evil.example/</a>`,
			want:   `[Login to PayPal\](https://evil.example/](https://good.example/)`,
		},
		{
			name:   "entity encoded brackets",
			source: `<a href="https://good.example/">x&#93;&#40;https&#58;//evil.example&#41;</a>`,
			want:   `[x\](https://evil.example)](https://good.example/)`,
		},
		{
			name:   "trailing backslash",
			source: `<a href="https://good.example/">label\</a>`,
			want:   `[label\\](https://good.example/)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			if got.Text != test.want {
				t.Fatalf("anchor text = %q, want %q", got.Text, test.want)
			}
			if len(got.Links) == 0 || got.Links[0] != "https://good.example/" {
				t.Fatalf("validated anchor destination missing or reordered: %v", got.Links)
			}
		})
	}
}

func TestHTMLURLsUseBrowserControlCharacterNormalization(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{
			name:   "literal tab",
			source: "<a href=\"https://paypal.com\t@evil.example/\">Secure login</a>",
		},
		{
			name:   "literal CRLF",
			source: "<a href=\"https://paypal.com\r\n@evil.example/\">Secure login</a>",
		},
		{
			name:   "entity encoded controls",
			source: `<a href="https://pay&#9;pal.com&#13;&#10;@evil.example/">Secure login</a>`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			wantURL := "https://paypal.com@evil.example/"
			if got.Text != "[Secure login]("+wantURL+")" {
				t.Fatalf("normalized anchor text = %q", got.Text)
			}
			if len(got.Links) != 1 || got.Links[0] != wantURL {
				t.Fatalf("normalized link evidence = %v, want [%s]", got.Links, wantURL)
			}
			parsed, err := url.Parse(got.Links[0])
			if err != nil || parsed.Hostname() != "evil.example" {
				t.Fatalf("normalized destination host = %q, err=%v", parsed.Hostname(), err)
			}
		})
	}
}

func TestHTMLURLsPercentEncodeC0ControlsOutsideAuthority(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "absolute path query and fragment",
			source: "<a href=\"https://evil.example/p\x01ath?q=\x02#f\x03ragment\">Open</a>",
			want:   "https://evil.example/p%01ath?q=%02#f%03ragment",
		},
		{
			name:   "entity encoded path control",
			source: `<a href="https://evil.example/p&#1;ath">Open</a>`,
			want:   "https://evil.example/p%01ath",
		},
		{
			name:   "relative reference",
			source: "<base href=\"https://evil.example/root/\"><a href=\"p\x01ath?q=\x02#f\x03ragment\">Open</a>",
			want:   "https://evil.example/root/p%01ath?q=%02#f%03ragment",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			if got.Text != "[Open]("+test.want+")" {
				t.Fatalf("normalized anchor text = %q, want URL %q", got.Text, test.want)
			}
			if len(got.Links) != 1 || got.Links[0] != test.want {
				t.Fatalf("normalized link evidence = %v, want [%s]", got.Links, test.want)
			}
		})
	}
}

func TestHTMLURLsRejectC0ControlsInAuthority(t *testing.T) {
	for _, source := range []string{
		"<a href=\"https://evil\x01.example/path\">Open</a>",
		"<base href=\"https://base.example/\"><a href=\"//evil\x01.example/path\">Open</a>",
	} {
		got := htmlToText(source)
		if got.Text != "Open" || len(got.Links) != 0 {
			t.Fatalf("invalid authority surfaced as text=%q links=%v", got.Text, got.Links)
		}
	}
}

func TestHTMLBaseResolvesRelativeLinksAndImages(t *testing.T) {
	got := htmlToText(`<base href="https://example.test/account/"><a href="pay-now">Pay now</a><a href="/help">Help</a><img src="//cdn.example.test/logo.png" alt="Logo">`)
	want := `[Pay now](https://example.test/account/pay-now)[Help](https://example.test/help) ![Logo](https://cdn.example.test/logo.png)`
	if got.Text != want {
		t.Fatalf("base-resolved text = %q, want %q", got.Text, want)
	}
	wantLinks := []string{
		"https://example.test/account/pay-now",
		"https://example.test/help",
		"https://cdn.example.test/logo.png",
	}
	if len(got.Links) != len(wantLinks) {
		t.Fatalf("base-resolved links = %v, want %v", got.Links, wantLinks)
	}
	for index := range wantLinks {
		if got.Links[index] != wantLinks[index] {
			t.Fatalf("base-resolved link %d = %q, want %q", index, got.Links[index], wantLinks[index])
		}
	}
}

func TestHTMLUsesOnlyFirstBaseHref(t *testing.T) {
	got := htmlToText(`<base href="https://first.example/path/"><base href="https://second.example/"><a href="target">Open</a>`)
	if got.Text != `[Open](https://first.example/path/target)` {
		t.Fatalf("multiple bases extracted as %q", got.Text)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://first.example/path/target" {
		t.Fatalf("multiple-base evidence = %v", got.Links)
	}
}

func TestHTMLBaseInsideHiddenElementStillResolvesLinks(t *testing.T) {
	tests := []string{
		`<div style="display:none"><base href="https://hidden.example/path/"></div><a href="target">Open</a>`,
		`<div hidden><base href="https://hidden.example/path/"></div><a href="target">Open</a>`,
		`<base hidden href="https://hidden.example/path/"><a href="target">Open</a>`,
	}
	for _, source := range tests {
		got := htmlToText(source)
		want := `[Open](https://hidden.example/path/target)`
		if got.Text != want {
			t.Fatalf("hidden base extracted as %q, want %q", got.Text, want)
		}
		if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/path/target" {
			t.Fatalf("hidden-base evidence = %v", got.Links)
		}
	}
}

func TestHTMLHiddenBaseRespectsFirstAndInertElements(t *testing.T) {
	got := htmlToText(`<div hidden><base href="https://first.example/path/"></div><base href="https://second.example/"><a href="target">Open</a>`)
	if got.Text != `[Open](https://first.example/path/target)` {
		t.Fatalf("first hidden base extracted as %q", got.Text)
	}

	for _, source := range []string{
		`<div hidden><!-- <base href="https://ignored.example/"> --></div><base href="https://visible.example/"><a href="target">Open</a>`,
		`<div hidden><script><base href="https://ignored.example/"></script></div><base href="https://visible.example/"><a href="target">Open</a>`,
		`<div hidden><style><base href="https://ignored.example/"></style></div><base href="https://visible.example/"><a href="target">Open</a>`,
		`<div hidden><template><base href="https://ignored.example/"></template></div><base href="https://visible.example/"><a href="target">Open</a>`,
	} {
		got := htmlToText(source)
		want := `[Open](https://visible.example/target)`
		if got.Text != want {
			t.Fatalf("inert hidden base extracted as %q, want %q", got.Text, want)
		}
	}
}

func TestHTMLInvalidFirstBaseDoesNotEnableLaterBase(t *testing.T) {
	for _, source := range []string{
		`<base href="javascript:alert(1)"><base href="https://later.example/"><a href="target">Open</a>`,
		`<base href><base href="https://later.example/"><a href="target">Open</a>`,
	} {
		got := htmlToText(source)
		if got.Text != `[Open](target)` || len(got.Links) != 1 || got.Links[0] != "target" {
			t.Fatalf("invalid first base enabled a later base: text=%q links=%v", got.Text, got.Links)
		}
		if strings.Contains(got.Text, "later.example") || strings.Contains(got.Links[0], "later.example") {
			t.Fatalf("invalid first base enabled a later base: text=%q links=%v", got.Text, got.Links)
		}
	}
}

func TestHTMLFirstDuplicateLinkAttributeWins(t *testing.T) {
	tests := []string{
		`<a href data-value="1" href="https://evil.example/">click</a>`,
		`<a href="" href="https://evil.example/">click</a>`,
	}
	for _, source := range tests {
		got := htmlToText(source)
		if got.Text != "click" || len(got.Links) != 0 {
			t.Fatalf("duplicate href surfaced later value: text=%q links=%v", got.Text, got.Links)
		}
	}
}

func TestHTMLFirstDuplicateImageAttributeWins(t *testing.T) {
	tests := []string{
		`<img src data-value="1" src="https://evil.example/image.png" alt="image">`,
		`<img src="" src="https://evil.example/image.png" alt="image">`,
	}
	for _, source := range tests {
		got := htmlToText(source)
		if got.Text != "" || len(got.Links) != 0 || len(got.ImageRefs) != 0 {
			t.Fatalf("duplicate src surfaced later value: text=%q links=%v images=%v", got.Text, got.Links, got.ImageRefs)
		}
	}
}

func TestHTMLBaseDoesNotPermitUnsafeSchemes(t *testing.T) {
	got := htmlToText(`<base href="https://example.test/"><a href="javascript:alert(1)">Run</a><img src="data:text/plain,bad" alt="Bad">`)
	if got.Text != "Run" || len(got.Links) != 0 {
		t.Fatalf("unsafe relative evidence surfaced: text=%q links=%v", got.Text, got.Links)
	}
}

func TestHTMLLinkedImageKeepsGeneratedMarkdownStructure(t *testing.T) {
	got := htmlToText(`<a href="https://good.example/"><img src="https://good.example/logo.png" alt="Company [logo]"></a>`)
	want := `[![Company \[logo\]](https://good.example/logo.png)](https://good.example/)`
	if got.Text != want {
		t.Fatalf("linked image text = %q, want %q", got.Text, want)
	}
	if len(got.Links) != 2 || got.Links[0] != "https://good.example/logo.png" || got.Links[1] != "https://good.example/" {
		t.Fatalf("linked image evidence = %v", got.Links)
	}
}

func TestHTMLCIDImageReferencesAreBoundedAndDeduplicated(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxExtractedLinks+10; index++ {
		contentID := "image-" + strconv.Itoa(index)
		source.WriteString(`<img src="cid:` + contentID + `">`)
		source.WriteString(`<img src="cid:` + contentID + `">`)
	}
	got := htmlToText(source.String())
	if len(got.ImageRefs) != maxExtractedLinks {
		t.Fatalf("CID reference count = %d, want %d", len(got.ImageRefs), maxExtractedLinks)
	}
	for index, ref := range got.ImageRefs {
		want := "image-" + strconv.Itoa(index)
		if ref != want {
			t.Fatalf("CID reference %d = %q, want %q", index, ref, want)
		}
	}
}

func TestCIDImageReferenceSizeLimits(t *testing.T) {
	var collector imageRefCollector
	collector.Add(strings.Repeat("x", maxExtractedLinkLength+1))
	if len(collector.refs) != 0 {
		t.Fatalf("oversized CID reference was retained: %v", collector.refs)
	}
	for index := 0; index < maxExtractedLinks; index++ {
		collector.Add(strings.Repeat("x", 100) + strconv.Itoa(index))
	}
	if collector.chars > maxExtractedLinkChars {
		t.Fatalf("CID character budget exceeded: %d", collector.chars)
	}
}

func TestHTMLLinkCollectionIsDeduplicatedAndBounded(t *testing.T) {
	var source strings.Builder
	for index := 0; index < maxExtractedLinks+10; index++ {
		link := "https://example.test/" + strconv.Itoa(index)
		source.WriteString(`<a href="` + link + `">link</a>`)
		source.WriteString(`<img src="` + link + `">`)
	}
	got := htmlToText(source.String())
	if len(got.Links) != maxExtractedLinks {
		t.Fatalf("collected links = %d, want %d", len(got.Links), maxExtractedLinks)
	}
	for index, link := range got.Links {
		want := "https://example.test/" + strconv.Itoa(index)
		if link != want {
			t.Fatalf("link %d = %q, want %q", index, link, want)
		}
	}
}

func TestMarkdownURLEncodesBackslashesWithoutChangingBrackets(t *testing.T) {
	tests := []struct {
		value string
		want  string
	}{
		{value: `https://example.test/path\`, want: `https://example.test/path%5C`},
		{value: `https://example.test/a\)b\]c`, want: `https://example.test/a%5C%29b%5C]c`},
		{value: `https://example.test/a]b`, want: `https://example.test/a]b`},
		{value: `https://[2001:db8::1]/path`, want: `https://[2001:db8::1]/path`},
	}
	for _, test := range tests {
		if got := markdownURL(test.value); got != test.want {
			t.Errorf("markdownURL(%q) = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestBoundedLinksRecognizesBackslashEscapedMarkdownURL(t *testing.T) {
	link := `https://example.test/path\`
	if missing := boundedLinksMissingFromBody([]string{link}, `[label](`+markdownURL(link)+`)`); len(missing) != 0 {
		t.Fatalf("escaped Markdown URL considered missing: %v", missing)
	}
}

func TestPlainURLHarvestingPreservesBalancedDelimiters(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "balanced parentheses",
			text: `See https://en.wikipedia.org/wiki/Foo_(bar) for details.`,
			want: `https://en.wikipedia.org/wiki/Foo_(bar)`,
		},
		{
			name: "surrounding sentence parentheses",
			text: `(see https://example.test/a_(b)).`,
			want: `https://example.test/a_(b)`,
		},
		{
			name: "unmatched closing parenthesis",
			text: `Open https://example.test/path) now`,
			want: `https://example.test/path`,
		},
		{
			name: "IPv6 brackets",
			text: `Open https://[2001:db8::1]/path.`,
			want: `https://[2001:db8::1]/path`,
		},
		{
			name: "ordinary trailing punctuation",
			text: `Open https://example.test/path?!`,
			want: `https://example.test/path`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := findHTTPURLs(test.text)
			if len(got) != 1 || got[0] != test.want {
				t.Fatalf("harvested URLs = %v, want [%s]", got, test.want)
			}
		})
	}
}

func TestExtractedLinksPreserveInvisibleFormatting(t *testing.T) {
	const normalized = "https://paypal.example/account"
	const encoded = "https://pay%E2%80%8Bpal.example/acc%E2%81%A0ount"
	obfuscated := "https://pay\u200bpal.example/acc\u2060ount"

	got := htmlToText(`<a href="` + obfuscated + `">Sign in</a>`)
	if got.Text != `[Sign in](`+encoded+`)` {
		t.Fatalf("HTML link text = %q", got.Text)
	}
	if len(got.Links) != 1 || got.Links[0] != encoded {
		t.Fatalf("HTML link evidence = %v", got.Links)
	}

	links := boundedLinks([]string{obfuscated, normalized})
	if len(links) != 2 || links[0] != obfuscated || links[1] != normalized {
		t.Fatalf("distinct links were changed or deduplicated: %v", links)
	}
}

func TestPlainTextLinksPreserveInvisibleFormatting(t *testing.T) {
	const obfuscated = "https://pay\u200bpal.example/acc\u2060ount"
	m := New(4096)
	m.AddHeader("Content-Type", "text/plain; charset=UTF-8")
	m.AddBody([]byte("Visit " + obfuscated))
	prompt := m.Prompt(4096)
	if !strings.Contains(prompt, obfuscated) {
		t.Fatalf("original URL missing from prompt: %q", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("body URL was emitted redundantly: %q", prompt)
	}
}

func TestHTMLIncludesNoscriptContent(t *testing.T) {
	m := New(4096)
	m.AddHeader("Content-Type", "text/html; charset=UTF-8")
	m.AddBody([]byte(`<noscript><p>Security warning: verify your account</p><a href="https://example.test/verify">Review account</a></noscript>`))
	prompt := m.Prompt(4096)
	for _, wanted := range []string{"Security warning: verify your account", "[Review account](https://example.test/verify)"} {
		if !strings.Contains(prompt, wanted) {
			t.Errorf("noscript content missing %q: %s", wanted, prompt)
		}
	}
}

func TestHTMLDoesNotApplyQuotedPrintableRepairsToEightBitContent(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddHeader("Content-Transfer-Encoding", "8bit")
	m.AddBody([]byte("<pre>value=\nnext line</pre>" +
		`<a href="https://example.test/?q=3D">link</a>` +
		`<img src="https://example.test/image.png" alt="code=3Dvalue">`))
	prompt := m.Prompt(10000)
	for _, wanted := range []string{
		"value=\nnext line",
		`[link](https://example.test/?q=3D)`,
		`![code=3Dvalue](https://example.test/image.png)`,
	} {
		if !strings.Contains(prompt, wanted) {
			t.Errorf("literal 8bit HTML missing %q: %s", wanted, prompt)
		}
	}
}

func TestHTMLPreservesRemoteImageReferenceAsMarkdown(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>Branding <img src="https://images.example/logo.png" alt="Example [logo]"></p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, `![Example \[logo\]](https://images.example/logo.png)`) {
		t.Fatalf("remote image evidence missing: %s", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("remote image URL retained in body was duplicated: %s", prompt)
	}
}

func TestMarkdownLinkEscapesDestinationParenthesesWithoutDuplicateInventory(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<a href="https://example.test/a_(b)">open account</a>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, `[open account](https://example.test/a_%28b%29)`) {
		t.Fatalf("Markdown destination was not escaped safely: %s", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("escaped link retained in body was duplicated: %s", prompt)
	}
}

func TestHTMLRendersCIDImageReferenceButOmitsDataImage(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<img src="cid:logo" alt="Company logo"><img src="data:image/png;base64,AAAA">Visible`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "![Company logo](cid:logo)") {
		t.Fatalf("CID image reference missing from text: %s", prompt)
	}
	if strings.Contains(prompt, "data:image") {
		t.Fatalf("data image reference leaked into text: %s", prompt)
	}
}
