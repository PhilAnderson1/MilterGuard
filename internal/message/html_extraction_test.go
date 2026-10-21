package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestHTMLCollapsesFormattingWhitespaceBetweenInlineLinkChildren(t *testing.T) {
	got := htmlToText(`<a href="https://worcora.example/"><span>W</span>
		<span>Worcora</span></a>`)
	want := `[W Worcora](https://worcora.example/)`
	if got.Text != want || got.VisibleText != "W Worcora" {
		t.Fatalf("inline link whitespace: text=%q visible=%q, want %q", got.Text, got.VisibleText, want)
	}

	got = htmlToText(`<a href="https://worcora.example/">W<br>Worcora</a>`)
	want = "[W\nWorcora](https://worcora.example/)"
	if got.Text != want {
		t.Fatalf("explicit link break = %q, want %q", got.Text, want)
	}

	got = htmlToText(`<a href="https://worcora.example/"><span style="display:block">W</span>
		<span style="display:block">Worcora</span></a>`)
	if got.Text != want {
		t.Fatalf("block link children = %q, want %q", got.Text, want)
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
		{`<div style="display:none">`, "display:none"},
		{`<div style="visibility: hidden">`, "visibility:hidden"},
		{`<div style="visibility:collapse">`, "visibility:collapse"},
		{`<div style="content:'display:none;'; display: none !important; display:block">`, "display:none"},
	} {
		t.Run(test.tag, func(t *testing.T) {
			got := htmlToText(`Before ` + test.tag + `<div>Forged conversation <a href="https://hidden.example/">trusted sender</a></div></div> After`)
			concealed := `<invisible reason="` + test.reason + `">Forged conversation [trusted sender](https://hidden.example/)</invisible>`
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
	got := htmlToText(`Before <div hidden><div>Forged conversation <a href="https://hidden.example/">trusted sender</a></div></div> After`)
	if !strings.Contains(got.Text, `<visibility-uncertain>Forged conversation [trusted sender](https://hidden.example/)</visibility-uncertain>`) {
		t.Fatalf("client-dependent hidden annotation missing: %q", got.Text)
	}
	if got.ConfidentVisibleChars != len("BeforeAfter") {
		t.Fatalf("hidden attribute counted as confidently visible: %+v", got)
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
			concealed := `<invisible reason="display:none">` + concealedText + `[trusted sender](https://hidden.example/)</invisible>`
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
	if got.Text != `<invisible reason="display:none">Hidden</invisible>`+"\nVisible" {
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
		want := `<visibility-uncertain>Hidden</visibility-uncertain>` + "\nVisible"
		if got.Text != want || got.VisibleText != "Hidden\nVisible" || got.ConfidentVisibleChars != len("Visible") {
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
		!strings.Contains(got.Text, `<invisible reason="visibility:hidden">Hidden parent </invisible>`) ||
		!strings.Contains(got.Text, `<invisible reason="visibility:hidden">Hidden tail</invisible>`) {
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
	if !strings.Contains(got.Text, `<invisible reason="display:none">Hidden [link](https://hidden.example/) ![embedded image](cid:hidden-image) </invisible>`) {
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
	if got.Text != `<visibility-uncertain> ![Forgery](https://hidden.example/image.png) </visibility-uncertain>Visible` {
		t.Fatalf("hidden void-element representation = %q", got.Text)
	}
	if got.VisibleText != "Visible" || got.ConfidentVisibleChars != len("Visible") {
		t.Fatalf("hidden void-element visibility: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/image.png" {
		t.Fatalf("hidden image destination = %v", got.Links)
	}
}

func TestHTMLUnclosedHiddenSubtreeDoesNotLeakIntoAIText(t *testing.T) {
	got := htmlToText(`Visible<div style="display:none">Forged correspondence`)
	if got.Text != "Visible\n"+`<invisible reason="display:none">Forged correspondence</invisible>` ||
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
			if !strings.Contains(got.Text, `<visibility-uncertain>forged</visibility-uncertain>`) || !strings.Contains(got.Text, test.want) {
				t.Fatalf("implied-closure representation = %q", got.Text)
			}
			if !strings.Contains(got.VisibleText, "forged") || !strings.Contains(got.VisibleText, test.want) {
				t.Fatalf("implied-closure visible text = %q", got.VisibleText)
			}
			if got.ConfidentVisibleChars != len(test.want) {
				t.Fatalf("implied-closure confident-visible count = %d, want %d", got.ConfidentVisibleChars, len(test.want))
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
			wantText := `<visibility-uncertain>outer` + "\n\n" +
				`nested [link](` + test.destination + `)` + "\n\n" +
				`still hidden</visibility-uncertain>` + "\n\n" + test.visible
			if got.Text != wantText {
				t.Fatalf("nested concealed subtree text = %q, want %q", got.Text, wantText)
			}
			if !strings.Contains(got.VisibleText, "outer") || !strings.Contains(got.VisibleText, test.visible) {
				t.Fatalf("nested uncertain subtree visible text = %q", got.VisibleText)
			}
			if got.ConfidentVisibleChars != len(test.visible) {
				t.Fatalf("nested uncertain subtree confident-visible count = %d, want %d", got.ConfidentVisibleChars, len(test.visible))
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
	if !strings.Contains(analysis.Prompt, `<invisible reason="display:none">forged history `) {
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
	if !strings.Contains(analysis.Prompt, `<visibility-uncertain>forged history `) {
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
	want := `<invisible reason="font-size" value="0px">Hidden parent Still hidden</invisible>` +
		`Visible [Open](https://visible.example/login) ![Invoice](cid:visible-image) ` +
		`<invisible reason="font-size" value="0px">Relative remains hiddenHidden tail</invisible>`
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
	want := `<visibility-uncertain>Hidden [link](https://hidden.example/) ![embedded image](cid:hidden-image) </visibility-uncertain>` + "\nVisible"
	if got.Text != want {
		t.Fatalf("zero-opacity evidence = %q, want %q", got.Text, want)
	}
	if got.VisibleText != "Hidden link\nVisible" || got.ConfidentVisibleChars != len("Visible") {
		t.Fatalf("zero-opacity representations: visible=%q stripped=%q", got.VisibleText, got.StrippedText)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://hidden.example/" || len(got.ImageRefs) != 1 || got.ImageRefs[0] != "hidden-image" {
		t.Fatalf("zero-opacity metadata: links=%v images=%v", got.Links, got.ImageRefs)
	}
}

func TestHTMLVisibilityStylesHonorCascadeAndZeroForms(t *testing.T) {
	for _, source := range []string{
		`<span style="opacity:0.0">Hidden</span>Visible`,
		`<span style="opacity:0%">Hidden</span>Visible`,
		`<span style="opacity:-1">Hidden</span>Visible`,
		`<span style="opacity:0 !important;opacity:1">Hidden</span>Visible`,
	} {
		got := htmlToText(source)
		if got.Text != `<visibility-uncertain>Hidden</visibility-uncertain>Visible` || got.VisibleText != "HiddenVisible" || got.ConfidentVisibleChars != len("Visible") {
			t.Fatalf("client-dependent opacity for %q: %+v", source, got)
		}
	}
	for _, test := range []struct {
		source, concealed string
	}{
		{`<span style="font-size:0px">Hidden</span>Visible`, `<invisible reason="font-size" value="0px">Hidden</invisible>Visible`},
		{`<span style="font-size:0 !important;font-size:12px">Hidden</span>Visible`, `<invisible reason="font-size" value="0px">Hidden</invisible>Visible`},
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
		{`<span style="displa\79 :none">Hidden</span>Visible`, `<invisible reason="display:none">Hidden</invisible>Visible`},
		{`<span style="display:n\6f ne">Hidden</span>Visible`, `<invisible reason="display:none">Hidden</invisible>Visible`},
		{`<span style="visi\62 ility:hidden">Hidden</span>Visible`, `<invisible reason="visibility:hidden">Hidden</invisible>Visible`},
		{`<span style="visibility:h\69 dden">Hidden</span>Visible`, `<invisible reason="visibility:hidden">Hidden</invisible>Visible`},
		{`<span style="font-si\7a e:0">Hidden</span>Visible`, `<invisible reason="font-size" value="0px">Hidden</invisible>Visible`},
	} {
		got := htmlToText(test.source)
		if got.Text != test.want || got.VisibleText != "Visible" || got.StrippedText != "<hidden-content-stripped/>Visible" {
			t.Fatalf("CSS escape concealment for %q: %+v", test.source, got)
		}
	}
	got := htmlToText(`<span style="opa\63 ity:0">Hidden</span>Visible`)
	if got.Text != `<visibility-uncertain>Hidden</visibility-uncertain>Visible` || got.VisibleText != "HiddenVisible" || got.ConfidentVisibleChars != len("Visible") {
		t.Fatalf("escaped opacity uncertainty: %+v", got)
	}
}

func TestHTMLEscapedCSSPunctuationDoesNotBecomeDeclarationSyntax(t *testing.T) {
	for _, source := range []string{
		`<span style="display\:none">Visible</span>`,
		`<span style="display\3A none">Visible</span>`,
	} {
		got := htmlToText(source)
		if got.Text != "Visible" || got.VisibleText != "Visible" {
			t.Fatalf("escaped CSS punctuation became syntax for %q: %+v", source, got)
		}
	}

	// The escaped semicolon remains part of the display value rather than
	// introducing a visibility declaration. Legacy clients may nevertheless
	// interpret escaped compatibility values differently, so it is uncertain.
	got := htmlToText(`<span style="display:block\;visibility:hidden">Visible</span>`)
	if got.Text != `<visibility-uncertain>Visible</visibility-uncertain>` || got.VisibleText != "Visible" || got.ConfidentVisibleChars != 0 {
		t.Fatalf("escaped CSS value punctuation was not kept uncertain: %+v", got)
	}
}

func TestHTMLOpaqueRuleBearingAtRuleReportsIncompleteCSS(t *testing.T) {
	got := htmlToText(`<style>@scope{#target{display:none}}</style><p id="target">Visible</p>`)
	if !got.CSSIncomplete {
		t.Fatal("opaque rule-bearing at-rule did not report incomplete CSS")
	}
	if got.ConfidentVisibleChars != 0 || got.VisibleText != "Visible" {
		t.Fatalf("incomplete CSS confidence was not propagated: %+v", got)
	}
}

func TestHTMLFontSizeZeroPreservesImageEvidence(t *testing.T) {
	got := htmlToText(`<div style="font-size:0">Hidden padding` +
		`<img src="cid:visible-image" alt="Invoice"></div>`)
	want := `<invisible reason="font-size" value="0px">Hidden padding</invisible> ![Invoice](cid:visible-image)`
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

func TestHTMLImagePaintAndCSSGeometryAnnotations(t *testing.T) {
	const image = `https://example.test/promo.png`
	geometry := htmlToText(`<img style="width:0" src="` + image + `" alt="Promotion">`)
	if want := `<invisible reason="empty-clip"> ![Promotion](` + image + `) </invisible>`; geometry.Text != want {
		t.Fatalf("zero-width image = %q, want %q", geometry.Text, want)
	}
	paint := htmlToText(`<img style="filter:opacity(0)" src="` + image + `" alt="Promotion">`)
	if want := `<visibility-uncertain> ![Promotion](` + image + `) </visibility-uncertain>`; paint.Text != want {
		t.Fatalf("paint-dependent image = %q, want %q", paint.Text, want)
	}
}

func TestHTMLForeignNamespaceStylesheetIsAnnotatedAsUncertain(t *testing.T) {
	got := htmlToText(`<svg><style>.secret{display:none}</style></svg><p class="secret">Visible in some clients</p>`)
	want := `<visibility-uncertain>Visible in some clients</visibility-uncertain>`
	if got.Text != want {
		t.Fatalf("foreign stylesheet output = %q, want %q", got.Text, want)
	}
}

func TestHTMLMSOConditionalStylesheetIsAnnotatedAsUncertain(t *testing.T) {
	got := htmlToText(`<!--[if mso]><style>#target{visibility:hidden}</style><![endif]--><p id="target">Visible outside Outlook</p>`)
	want := `<visibility-uncertain>Visible outside Outlook</visibility-uncertain>`
	if got.Text != want {
		t.Fatalf("conditional stylesheet output = %q, want %q", got.Text, want)
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
	collector.Add(strings.Repeat("x", maxExtractedReferenceLength+1))
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

func TestMissingLinkSearchBoundsMergedCandidatesFirst(t *testing.T) {
	candidates := make([]string, 1_000)
	for i := range candidates {
		candidates[i] = "https://example.test/" + strconv.Itoa(i)
	}
	if got := boundedLinksMissingFromBody(candidates, ""); len(got) != maxExtractedLinks {
		t.Fatalf("missing links=%d, want %d", len(got), maxExtractedLinks)
	}
}

func TestLongURLsAreRepresentedRatherThanDiscarded(t *testing.T) {
	link := "https://tracker.example/click/" + strings.Repeat("a", 700) + "?campaign=notice&signature=END"
	displayed := promptURL(link, true)
	if utf8.RuneCountInString(displayed) > maxPromptURLChars ||
		!strings.HasPrefix(displayed, "https://tracker.example/click/") ||
		strings.Contains(displayed, "…") || strings.Contains(displayed, "URL-truncated") ||
		!strings.HasSuffix(displayed, "signature=END") {
		t.Fatalf("bounded URL = %q", displayed)
	}

	got := htmlToText(`<a href="` + link + `">Review notice</a>`)
	if len(got.Links) != 1 || got.Links[0] != displayed {
		t.Fatalf("compacted URL was not retained for deduplication: %v", got.Links)
	}
	if !strings.Contains(got.Text, markdownURL(displayed)) || strings.Contains(got.Text, link) {
		t.Fatalf("HTML extraction did not render the compacted URL: %q", got.Text)
	}
	if links := boundedLinks([]string{displayed}); len(links) != 1 || links[0] != displayed {
		t.Fatalf("independent long-link evidence = %v, want %q", links, displayed)
	}
	if missing := boundedLinksMissingFromBody([]string{displayed}, got.Text); len(missing) != 0 {
		t.Fatalf("bounded inline URL was emitted again: %v", missing)
	}
}

func TestPromptURLCompactionCanBeDisabled(t *testing.T) {
	link := "https://tracker.example/click/" + strings.Repeat("a", 700) + "?campaign=notice&signature=END"
	m := New(4096)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<a href="` + link + `">Review notice</a>`))

	analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 2000, VisionOptions{Mode: "off"}, HTMLProcessingControl{DisableURLCompaction: true})
	if !strings.Contains(analysis.Prompt, markdownURL(link)) || strings.Contains(analysis.Prompt, promptURL(link, true)) {
		t.Fatalf("full URL was not preserved in prompt: %q", analysis.Prompt)
	}
}

func TestOverflowLinksUseSelectedURLRepresentation(t *testing.T) {
	link := "https://tracker.example/click/" + strings.Repeat("a", 700) + "?campaign=notice&signature=END"
	displayed := promptURL(link, true)
	for _, test := range []struct {
		name    string
		control HTMLProcessingControl
		want    string
		reject  string
	}{
		{name: "compacted", want: displayed, reject: link},
		{name: "full", control: HTMLProcessingControl{DisableURLCompaction: true}, want: link, reject: displayed},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := New(4096)
			m.AddHeader("Content-Type", "text/html")
			m.AddBody([]byte(`<p>` + strings.Repeat("body ", 100) + `</p><a href="` + link + `">Review notice</a>`))

			analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 100, VisionOptions{Mode: "off"}, test.control)
			if !strings.Contains(analysis.Prompt, "EXTRACTED LINKS") || !strings.Contains(analysis.Prompt, test.want) {
				t.Fatalf("selected overflow URL missing from prompt: %q", analysis.Prompt)
			}
			if test.reject != test.want && strings.Contains(analysis.Prompt, test.reject) {
				t.Fatalf("unselected overflow URL representation present: %q", analysis.Prompt)
			}
		})
	}
}

func TestVisibleBodyRetainsUncompactedPlainTextURL(t *testing.T) {
	link := "https://tracker.example/click/" + strings.Repeat("a", 700) + "?signature=END"
	m := New(4096)
	m.AddHeader("Content-Type", "text/plain")
	m.AddBody([]byte("Open " + link))

	if got := m.VisibleBody(4096); !strings.Contains(got, link) {
		t.Fatalf("visible body URL was compacted: %q", got)
	}
	if prompt := m.Prompt(4096); strings.Contains(prompt, link) || !strings.Contains(prompt, promptURL(link, true)) {
		t.Fatalf("prompt did not use compacted plain-text URL: %q", prompt)
	}
}

func TestPromptCompactsLinkedImageDestination(t *testing.T) {
	link := "https://click.example/ls/click?upn=" + strings.Repeat("tracking", 80)
	m := New(4096)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<a href="` + link + `"><img src="https://images.example/logo.png" alt="Logo"></a>`))

	prompt := m.Prompt(2000)
	if strings.Contains(prompt, link) || !strings.Contains(prompt, promptURL(link, true)) {
		t.Fatalf("linked-image destination was not compacted independently: %q", prompt)
	}
	if !strings.Contains(prompt, `https://images.example/logo.png`+`)](`) {
		t.Fatalf("linked-image Markdown structure was damaged: %q", prompt)
	}
}

func TestLongURLRepresentationMakesActualHostExplicit(t *testing.T) {
	link := "https://" + strings.Repeat("trusted.example", 40) + "@evil.example/verify/" + strings.Repeat("x", 300)
	displayed := promptURL(link, true)
	if !strings.HasPrefix(displayed, "https://[userinfo-omitted]@evil.example/verify/") ||
		strings.Contains(displayed, "…") || strings.Contains(displayed, "URL-truncated") ||
		utf8.RuneCountInString(displayed) > maxPromptURLChars {
		t.Fatalf("long user-information URL = %q", displayed)
	}
}

func TestLongURLRepresentationPreservesExecutablePathEnding(t *testing.T) {
	link := "https://downloads.example/releases/" + strings.Repeat("archive-", 20) + "setup.exe?signature=" + strings.Repeat("x", 700)
	displayed := promptURL(link, true)
	if utf8.RuneCountInString(displayed) > maxPromptURLChars ||
		!strings.HasPrefix(displayed, "https://downloads.example/") ||
		!strings.Contains(displayed, "setup.exe") || strings.Contains(displayed, "URL-truncated") {
		t.Fatalf("executable URL representation = %q", displayed)
	}
}

func TestLongURLRepresentationPreservesQueryStructure(t *testing.T) {
	embedded := "https%3A%2F%2Fwww.amazon.co.uk%2Fgp%2Fcss%2Forder-history%3Fref_%3Ddelivery"
	link := "https://www.amazon.co.uk/gp/r.html?C=campaign&M=" + strings.Repeat("message", 20) + "&U=" + embedded + "&H=" + strings.Repeat("signature", 20) + "&ref_=delivery_notice"
	displayed := promptURL(link, true)
	for _, evidence := range []string{
		"https://www.amazon.co.uk/gp/r.html?", "C=campaign", "&M=", "&U=https%3A%2F%2Fwww.amazon.co.uk", "&H=", "&ref_=delivery_notice",
	} {
		if !strings.Contains(displayed, evidence) {
			t.Fatalf("structured URL lacks %q: %q", evidence, displayed)
		}
	}
	if strings.Contains(displayed, "…") || strings.Contains(displayed, "URL-truncated") || utf8.RuneCountInString(displayed) > maxPromptURLChars {
		t.Fatalf("structured URL representation = %q", displayed)
	}
}

func TestLongPlainTextURLIsBoundedBeforeBodySampling(t *testing.T) {
	link := "https://plain.example/notice/" + strings.Repeat("z", 700) + "?signature=END"
	m := New(4096)
	m.AddHeader("Content-Type", "text/plain")
	m.AddBody([]byte("Open " + link + " after reading the important text which follows."))
	prompt := m.Prompt(600)
	if strings.Contains(prompt, link) || !strings.Contains(prompt, promptURL(link, true)) ||
		!strings.Contains(prompt, "important text which follows") || strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("plain-text long URL prompt = %q", prompt)
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
			var got []string
			walkPlainHTTPURLs(test.text, maxExtractedLinks*2, nil, func(link string, _, _ int) bool {
				got = append(got, link)
				return true
			})
			if len(got) != 1 || got[0] != test.want {
				t.Fatalf("harvested URLs = %v, want [%s]", got, test.want)
			}
		})
	}
}

func TestNextHTTPPrefixScansCaseInsensitively(t *testing.T) {
	text := "highway HAZE hTtPs://mixed.example then HTTP://upper.example"
	first := strings.Index(text, "hTtPs://")
	if got := nextHTTPPrefix(text, 0, nil); got != first {
		t.Fatalf("first prefix = %d, want %d", got, first)
	}
	second := strings.Index(text, "HTTP://")
	if got := nextHTTPPrefix(text, first+1, nil); got != second {
		t.Fatalf("second prefix = %d, want %d", got, second)
	}
	if got := nextHTTPPrefix(strings.Repeat("highway haze ", 4096), 0, nil); got != -1 {
		t.Fatalf("non-URL text matched at %d", got)
	}
}

func TestPlainURLWalkCanBeStoppedBetweenCandidates(t *testing.T) {
	text := strings.Repeat("http://example.test/a ", 300)
	checks := 0
	visited := 0
	expectTermination(t, termination.CPUExceeded, func() {
		walkPlainHTTPURLs(text, -1, func() {
			checks++
			if checks == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}
		}, func(string, int, int) bool { visited++; return true })
	})

	if visited != 256 {
		t.Fatalf("visited %d URLs before stop; want 256", visited)
	}
}

func TestPlainURLRewriteStopsCollectingAtLinkLimit(t *testing.T) {
	var text strings.Builder
	for i := range maxExtractedLinks + 50 {
		fmt.Fprintf(&text, "http://%d.example.test/ ", i)
	}
	collector := linkCollector{compactURLs: true}
	rewritten := rewritePlainTextURLs(text.String(), true, &collector, collector.memory, nil)
	if len(collector.links) != maxExtractedLinks || !collector.Full() {
		t.Fatalf("collected=%d full=%v, want %d/true", len(collector.links), collector.Full(), maxExtractedLinks)
	}
	if rewritten != text.String() {
		t.Fatal("ordinary URLs changed while testing collection limit")
	}
}

func TestLinkCollectorCachesRenderedDestination(t *testing.T) {
	raw := "https://example.test/" + strings.Repeat("segment/", 100)
	collector := linkCollector{compactURLs: true}
	first := collector.AddDestination(raw)
	second := collector.AddDestination(raw)
	if first == raw || second != first {
		t.Fatalf("rendered destinations: first=%q second=%q", first, second)
	}
	if len(collector.links) != 1 || collector.rendered.Len() != 1 {
		t.Fatalf("links=%d cached=%d, want 1/1", len(collector.links), collector.rendered.Len())
	}
}

func BenchmarkNextHTTPPrefixDenseNoMatch(b *testing.B) {
	text := strings.Repeat("highway haze ", 1<<16)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for range b.N {
		if nextHTTPPrefix(text, 0, nil) != -1 {
			b.Fatal("unexpected URL match")
		}
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
	m.AddBody([]byte(`<html><body><noscript><p>Security warning: verify your account</p><a href="https://example.test/verify">Review account</a></noscript></body></html>`))
	prompt := m.Prompt(4096)
	for _, wanted := range []string{"Security warning: verify your account", "[Review account](https://example.test/verify)"} {
		if !strings.Contains(prompt, wanted) {
			t.Errorf("noscript content missing %q: %s", wanted, prompt)
		}
	}
	if !strings.Contains(prompt, "<visibility-uncertain>") {
		t.Fatalf("noscript content was not marked visibility-uncertain: %s", prompt)
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
