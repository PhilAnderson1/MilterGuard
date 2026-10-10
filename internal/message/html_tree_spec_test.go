package message

import (
	"os"
	"strings"
	"testing"
)

func TestTreeExtractorAppliesEmbeddedCSSDeclaredAfterContent(t *testing.T) {
	got := htmlToText(`<p class="quiet">Pay<span> reassuring padding</span> now</p><style>.quiet span { opacity: .005 }</style>`)
	want := `<concealed reason="opacity" value="0.005"> reassuring padding</concealed>`
	if !strings.Contains(got.Text, want) {
		t.Fatalf("tagged extraction = %q, missing %q", got.Text, want)
	}
	if !got.HasConcealedContent || got.StrippedText == "" || !strings.Contains(got.StrippedText, "<hidden-content-stripped/>") {
		t.Fatalf("concealment modes = %+v", got)
	}
}

func TestTreeExtractorConcealmentThresholdsAndReasons(t *testing.T) {
	tests := []struct{ html, reason string }{
		{`<i style="font-size:2px">tiny</i>`, `reason="font-size" value="2px"`},
		{`<i style="color:#fff">white</i>`, `reason="color-match"`},
		{`<i style="position:absolute;clip:rect(0 0 0 0)">clip</i>`, `reason="empty-clip"`},
		{`<i style="visibility:hidden">hidden</i>`, `reason="visibility:hidden"`},
	}
	for _, test := range tests {
		if got := htmlToText(test.html).Text; !strings.Contains(got, test.reason) {
			t.Errorf("%s => %q, missing %q", test.html, got, test.reason)
		}
	}
}

func TestTreeExtractorMergesAdjacentEquivalentRuns(t *testing.T) {
	got := htmlToText(`<span style="display:none">a</span><i style="display:none">b</i>`)
	if got.Text != `<concealed reason="display:none">ab</concealed>` {
		t.Fatalf("tagged runs = %q", got.Text)
	}
	if got.StrippedText != `<hidden-content-stripped/>` {
		t.Fatalf("stripped runs = %q", got.StrippedText)
	}
}

func TestTreeExtractorDoesNotAnnotateWhitespaceOrDecodedNBSP(t *testing.T) {
	got := htmlToText("<div style=\"filter:blur(1px)\">\r\n&nbsp;\r\n<span>uncertain words</span>\r\n</div><div style=\"display:none\">&#847;&zwnj; &#847;&zwnj;</div>")
	if !strings.Contains(got.Text, "\u00a0") {
		t.Fatalf("decoded non-breaking space was lost: %q", got.Text)
	}
	if strings.Contains(got.Text, "<visibility-uncertain>\n") || strings.Contains(got.Text, "<visibility-uncertain>\u00a0") {
		t.Fatalf("whitespace was annotated: %q", got.Text)
	}
	if strings.Contains(got.Text, "<concealed reason=\"display:none\">\u034f") {
		t.Fatalf("standalone invisible formatting was annotated: %q", got.Text)
	}
	if !strings.Contains(got.Text, "\u034f\u200c") {
		t.Fatalf("short invisible formatting evidence was lost: %q", got.Text)
	}
	if !strings.Contains(got.Text, "<visibility-uncertain>uncertain words</visibility-uncertain>") {
		t.Fatalf("content uncertainty was lost: %q", got.Text)
	}
}

func TestTreeExtractorCompactsPreheaderPaddingAndDropsTrackingPixels(t *testing.T) {
	padding := strings.Repeat("&#847;&zwnj;&nbsp;&#8199;&shy;", 80)
	got := htmlToText(`<img width="1" height="1" alt="" src="https://example.test/open"><div style="display:none">Preview ` + padding + `</div><p>Body</p>`)
	if strings.Contains(got.Text, "example.test/open") || len(got.Links) != 0 {
		t.Fatalf("tracking pixel leaked: %+v", got)
	}
	if strings.Count(got.Text, "\u034f") > 2 || !strings.Contains(got.Text, "Preview") || !strings.Contains(got.Text, "Body") {
		t.Fatalf("preheader padding was not compacted safely: %q", got.Text)
	}
}

func TestTreeExtractorViewportAndUncertainContentSurvivesBothModes(t *testing.T) {
	got := htmlToText(`<style>@media screen and (max-width:600px){.x{display:none}}</style><p class=x>responsive</p>`)
	if !strings.Contains(got.Text, "<visibility-varies-by-viewport-size>responsive</visibility-varies-by-viewport-size>") {
		t.Fatalf("tagged = %q", got.Text)
	}
	if got.HasConcealedContent {
		t.Fatal("viewport-dependent content counted as removable")
	}
	unsupported := htmlToText(`<style>@media (prefers-reduced-motion:reduce){.x{display:none}}</style><p class=x>theme</p>`)
	if !strings.Contains(unsupported.Text, "<visibility-uncertain>theme</visibility-uncertain>") {
		t.Fatalf("uncertain = %q", unsupported.Text)
	}
}

func TestTreeExtractorTreatsVisibilityCollapseAsConcealed(t *testing.T) {
	got := htmlToText(`<div style="visibility:collapse">collapsed text</div>`)
	if got.Text != `<concealed reason="visibility:collapse">collapsed text</concealed>` {
		t.Fatalf("collapsed visibility = %q", got.Text)
	}
	if got.VisibleText != "" {
		t.Fatalf("collapsed text was treated as visible: %q", got.VisibleText)
	}
}

func TestTreeExtractorLimitsUncertaintyInDecorativeSpamTemplate(t *testing.T) {
	raw, err := os.ReadFile("../../local-testing/test_emails/spam/Claim Your Free YETI PATRIOTIC Bundle.eml")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n\n", 2)
	if len(parts) != 2 {
		t.Fatal("fixture has no message body")
	}
	got := htmlToText(parts[1]).Text
	for _, visible := range []string{
		"YOU HAVE BEEN CHOSEN",
		"ANSWER",
		"You have been chosen to participate in our loyalty program for free!",
		"It will take you only a minute to recieve this fantastic price.",
	} {
		if strings.Contains(got, "<visibility-uncertain>"+visible) {
			t.Errorf("clearly readable text remained uncertain: %q\n%s", visible, got)
		}
	}
	if !strings.Contains(got, "<visibility-uncertain>A BRAND NEW</visibility-uncertain>") {
		t.Fatalf("unsupported gradient-filled text lost uncertainty: %s", got)
	}
}

func TestTreeExtractorUnderstandsLegacyDeviceWidthEmailCSS(t *testing.T) {
	raw, err := os.ReadFile("../../local-testing/test_emails/legitimate/A Plague Tale_ Requiem from your Steam wishlist is now on sale!.eml")
	if err != nil {
		t.Fatal(err)
	}
	message, err := ParseArchived(raw, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	prompt := message.BuildAnalysis(AnalysisContext{}, 200000, VisionOptions{Mode: "off"}).Prompt
	if strings.Contains(prompt, "<visibility-uncertain>") {
		t.Fatalf("legacy device-width query made ordinary Steam content uncertain: %s", prompt)
	}
	if !strings.Contains(prompt, "A Plague Tale: Requiem") || !strings.Contains(prompt, "View your Wishlist") {
		t.Fatalf("fixture content was not retained: %s", prompt)
	}
}

func TestTreeExtractorRetainsFallbackPresentationsWithoutPresentationCode(t *testing.T) {
	got := htmlToText(`<html><body><noscript><a href="https://example.test/review">Review account</a></noscript><!--[if mso]><p>Outlook notice</p><![endif]--><!--[if mso]><p>&nbsp;</p><![endif]--><!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]--></body></html>`)
	if !strings.Contains(got.Text, `[Review account](https://example.test/review)`) {
		t.Fatalf("noscript fallback = %q", got.Text)
	}
	if !strings.Contains(got.Text, `<visibility-uncertain>Outlook notice</visibility-uncertain>`) {
		t.Fatalf("conditional fallback = %q", got.Text)
	}
	if strings.Contains(got.Text, "[if mso]") || strings.Contains(got.Text, "endif") {
		t.Fatalf("presentation code leaked: %q", got.Text)
	}
	if strings.Contains(got.Text, "<visibility-uncertain>\u00a0") {
		t.Fatalf("conditional whitespace was annotated: %q", got.Text)
	}
	if strings.Contains(got.Text, "96") {
		t.Fatalf("Office presentation XML leaked: %q", got.Text)
	}
}

func TestTreeExtractorSanitizesReservedSenderTagsOnce(t *testing.T) {
	got := htmlToText(`<p>&lt;concealed reason="fake"&gt;trusted&lt;/concealed&gt; &amp;lt;concealed&amp;gt;once</p>`)
	if strings.Contains(got.Text, `reason="fake"`) || strings.Contains(got.Text, "trusted</concealed>") {
		t.Fatalf("sender tag survived: %q", got.Text)
	}
	if !strings.Contains(got.Text, "trusted") || !strings.Contains(got.Text, "&lt;concealed&gt;once") {
		t.Fatalf("decoding was not exactly once: %q", got.Text)
	}
}

func TestTreeExtractorUsesParsedTableAncestry(t *testing.T) {
	got := htmlToText(`<table style="display:none">fostered evidence<tr><td>cell evidence</td></tr></table>`)
	if !strings.Contains(got.Text, "fostered evidence") || strings.Contains(got.Text, `<concealed reason="display:none">fostered evidence`) {
		t.Fatalf("fostered text = %q", got.Text)
	}
	if !strings.Contains(got.Text, `<concealed reason="display:none">cell evidence</concealed>`) {
		t.Fatalf("cell text = %q", got.Text)
	}
}

func TestTreeExtractorPreservesActionableDestinationsAndFirstBase(t *testing.T) {
	got := htmlToText(`<base href="https://first.example/a/"><base href="https://second.example/"><a href="pay">Pay</a><a href="mailto:help@example.test">Mail</a><a href="tel:+123">Call</a>`)
	for _, want := range []string{"https://first.example/a/pay", "mailto:help@example.test", "tel:+123"} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("output %q missing %q", got.Text, want)
		}
	}
}

func TestPromptStripsConcealedContentBeforePrefixTruncation(t *testing.T) {
	m := New(1 << 20)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>keep</p><p style="display:none">` + strings.Repeat("padding ", 100) + `</p><p>end</p>`))
	analysis := m.BuildAnalysis(AnalysisContext{}, 80, VisionOptions{Mode: "off"})
	if analysis.BodyTruncated || !analysis.ConcealedContentRemoved {
		t.Fatalf("fallback flags = %+v", analysis)
	}
	if !analysis.HasConcealedContent || !analysis.UsedHiddenContentStrippedTag || analysis.UsedConcealedTag {
		t.Fatalf("annotation metadata = %+v", analysis)
	}
	if !strings.Contains(analysis.Prompt, "<hidden-content-stripped/>") || !strings.Contains(analysis.Prompt, "EXTRACTOR-GENERATED ANNOTATIONS") {
		t.Fatalf("prompt = %s", analysis.Prompt)
	}
	if strings.Contains(analysis.Prompt, "ANALYSIS LIMITATIONS") || strings.Contains(analysis.Prompt, "Concealed content was removed") {
		t.Fatalf("concealed-content markers were redundantly explained: %s", analysis.Prompt)
	}
}

func TestPromptUsesConciseConcealmentExplanation(t *testing.T) {
	m := New(1024)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p style="display:none">concealed</p>`))
	prompt := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{Mode: "off"}).Prompt
	want := "CSS makes this text effectively invisible to the recipient; reason/value show why."
	if !strings.Contains(prompt, want) {
		t.Fatalf("prompt missing %q: %s", want, prompt)
	}
}

func TestVisibilityLimitFallbackRetainsCompleteTextWithoutIncompleteFlag(t *testing.T) {
	got := htmlToText(`<style>` + strings.Repeat(`p{display:none}`, 10001) + `</style><p>retained evidence</p>`)
	if got.ExtractionIncomplete {
		t.Fatal("visibility-only limit reported text loss")
	}
	if !strings.Contains(got.Text, `<visibility-uncertain>retained evidence</visibility-uncertain>`) {
		t.Fatalf("fallback = %q", got.Text)
	}
}
