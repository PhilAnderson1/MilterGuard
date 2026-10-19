package message

import (
	"strings"
	"testing"
	"unicode/utf8"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
)

func TestTreeExtractorAppliesEmbeddedCSSDeclaredAfterContent(t *testing.T) {
	got := htmlToText(`<p class="quiet">Pay<span> reassuring padding</span> now</p><style>.quiet span { opacity: .005 }</style>`)
	want := `<visibility-uncertain> reassuring padding</visibility-uncertain>`
	if !strings.Contains(got.Text, want) {
		t.Fatalf("tagged extraction = %q, missing %q", got.Text, want)
	}
	if got.HasConcealedContent || got.ConfidentVisibleChars != len("Paynow") {
		t.Fatalf("uncertain opacity modes = %+v", got)
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

func TestTreeExtractorAnnotatesLayoutHidingRisk(t *testing.T) {
	got := htmlToText(`<div style="overflow:hidden;width:0"><span>zero box</span></div><p style="position:absolute;left:-9999px">off screen</p>`)
	want := "<visibility-uncertain>zero box\n\noff screen</visibility-uncertain>"
	if got.Text != want {
		t.Fatalf("layout uncertainty = %q, want %q", got.Text, want)
	}
	if got.StrippedText != "" || got.HasConcealedContent {
		t.Fatalf("layout uncertainty was treated as concealment: %+v", got)
	}
}

func TestTreeExtractorMergesAdjacentEquivalentRuns(t *testing.T) {
	got := htmlToText(`<span style="display:none">a</span><i style="display:none">b</i>`)
	if got.Text != `<invisible reason="display:none">ab</invisible>` {
		t.Fatalf("tagged runs = %q", got.Text)
	}
	if got.StrippedText != `<hidden-content-stripped/>` {
		t.Fatalf("stripped runs = %q", got.StrippedText)
	}
}

func TestAnnotatedOutputAppendsEquivalentRunsWithoutFragmenting(t *testing.T) {
	var output annotatedOutput
	annotation := outputAnnotation{kind: "concealed", reason: "display:none"}
	for range 4096 {
		output.write(annotation, "x")
	}
	if len(output.chunks) != 1 || output.data.Len() != 4096 {
		t.Fatalf("buffer shape = %d chunks, %d bytes", len(output.chunks), output.data.Len())
	}
	if got, complete := output.String(); !complete || got != `<invisible reason="display:none">`+strings.Repeat("x", 4096)+`</invisible>` {
		t.Fatalf("rendered append-only output = %q", got)
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
	if strings.Contains(got.Text, "<invisible reason=\"display:none\">\u034f") {
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
	if got.Text != `<invisible reason="visibility:collapse">collapsed text</invisible>` {
		t.Fatalf("collapsed visibility = %q", got.Text)
	}
	if got.VisibleText != "" {
		t.Fatalf("collapsed text was treated as visible: %q", got.VisibleText)
	}
}

func TestTreeExtractorLimitsUncertaintyInDecorativeSpamTemplate(t *testing.T) {
	got := htmlToText(`<style>
		:root { --text-dark: #111; }
		.ppp { font-size:30px; color:var(--text-dark); }
		.ppp-1 { background:linear-gradient(to bottom,#e09b7e,#ff7e5f,#dd2f46,#c10a4a); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
		.ppp-2,.ppp-3 { text-shadow:1px 1px 1px white; position:absolute; }
		@media (max-width:500px) { .ppp-2 { left:20px; } }
	</style>
	<p class="ppp">YOU HAVE BEEN CHOSEN</p>
	<p class="ppp">ANSWER&amp;WIN</p>
	<p class="ppp ppp-1">A BRAND NEW</p>
	<p class="ppp-2">You have been chosen to participate in our loyalty program for free!</p>
	<p class="ppp-3">It will take you only a minute to recieve this fantastic price.</p>`).Text
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
	got := htmlToText(`<style>
		@media only screen and (max-device-width:480px), only screen and (max-width:480px) {
			.mfz-14 { font-size:14px !important; }
			.mpx-20 { padding-left:20px !important; padding-right:20px !important; }
		}
	</style>
	<p class="mfz-14">A Plague Tale: Requiem</p>
	<a class="mpx-20" href="https://store.example/wishlist">View your Wishlist</a>`)
	if strings.Contains(got.Text, "<visibility-uncertain>") {
		t.Fatalf("legacy device-width query made ordinary Steam content uncertain: %s", got.Text)
	}
	if !strings.Contains(got.Text, "A Plague Tale: Requiem") || !strings.Contains(got.Text, "View your Wishlist") {
		t.Fatalf("fixture content was not retained: %s", got.Text)
	}
}

func TestTreeExtractorIgnoresHarmlessMSOConditionalWidth(t *testing.T) {
	got := htmlToText(`<!--[if lte mso 11]><style>.column{width:100%!important}</style><![endif]-->
		<div class="column" style="width:100%"><img src="https://example.test/status.png" width="18" height="18" alt="Completed"><p>Package status</p></div>`)
	if strings.Contains(got.Text, "<visibility-uncertain>") {
		t.Fatalf("ordinary Outlook-only width made content uncertain: %s", got.Text)
	}
	if !strings.Contains(got.Text, "Package status") || !strings.Contains(got.Text, "![Completed]") {
		t.Fatalf("expected content was not retained: %s", got.Text)
	}
}

func TestTreeExtractorRetainsFallbackPresentationsWithoutPresentationCode(t *testing.T) {
	got := htmlToText(`<html><body><noscript><a href="https://example.test/review">Review account</a></noscript><!--[if mso]><p>Outlook notice</p><![endif]--><!--[if mso]><p>&nbsp;</p><![endif]--><!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]--></body></html>`)
	if !strings.Contains(got.Text, `Review account`) || !strings.Contains(got.Text, `https://example.test/review`) || !strings.Contains(got.Text, `<visibility-uncertain>`) {
		t.Fatalf("noscript fallback = %q", got.Text)
	}
	if !strings.Contains(got.Text, "Outlook notice</visibility-uncertain>") {
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
	if got.ExtractionIncomplete {
		t.Fatal("ordinary conditional content was reported as omitted")
	}
}

func TestTreeExtractorDoesNotCountFosteredMSOContentAsConfident(t *testing.T) {
	got := htmlToText(`<p>Legit notice</p><table><!--[if !mso]><!-->APPROVE WIRE TRANSFER NOW<!--<![endif]--></table>`)
	if got.ConfidentVisibleChars != 0 {
		t.Fatalf("fostered MSO content produced %d confident visible characters", got.ConfidentVisibleChars)
	}
	if !strings.Contains(got.Text, `<visibility-uncertain>`) || !strings.Contains(got.Text, `APPROVE WIRE TRANSFER NOW`) {
		t.Fatalf("fostered MSO content was not marked uncertain: %q", got.Text)
	}
}

func TestTreeExtractorDoesNotCountOutlookFalsePredicateAsConfident(t *testing.T) {
	got := htmlToText(`<p>Legit</p><!--[if !mso & !IE]><!-->TRANSFER FUNDS NOW<!--<![endif]-->`)
	if got.ConfidentVisibleChars != len("Legit") {
		t.Fatalf("confident visible characters = %d, want %d", got.ConfidentVisibleChars, len("Legit"))
	}
	if !strings.Contains(got.Text, `<visibility-uncertain>TRANSFER FUNDS NOW</visibility-uncertain>`) {
		t.Fatalf("Outlook-false content was not marked uncertain: %q", got.Text)
	}
}

func TestTreeExtractorAnnotatesMSOHiddenContent(t *testing.T) {
	got := htmlToText(`<p>Visible</p><p style="mso-hide:all">Outlook-hidden</p>`)
	if !strings.Contains(got.Text, `<visibility-uncertain>Outlook-hidden</visibility-uncertain>`) {
		t.Fatalf("mso-hide annotation = %q", got.Text)
	}
	if !strings.Contains(got.VisibleText, "Outlook-hidden") {
		t.Fatalf("content visible in non-Word clients was omitted from visible text: %q", got.VisibleText)
	}
}

func TestConditionalOmissionReachesPromptAndStrippedBody(t *testing.T) {
	source := `<p style="display:none">concealed</p>Before<!--[if mso]>` +
		strings.Repeat("x", maxConditionalFragmentBytes+1) +
		`<a href="https://example.test/omitted">omitted link</a><![endif]-->After`
	got := htmlToText(source)
	if !got.HasConcealedContent || !strings.Contains(got.Text, `<invisible reason="display:none">concealed</invisible>`) {
		t.Fatal("omitted conditional fragment lost ordinary concealment evidence")
	}
	if !strings.Contains(got.StrippedText, conditionalOmissionMarker) || strings.Contains(got.StrippedText, "concealed") || len(got.Links) != 0 {
		t.Fatalf("stripped body or links retained partial conditional evidence: %q %v", got.StrippedText, got.Links)
	}
	m := New(1 << 20)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(source))
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{Mode: "off"})
	if !analysis.BodyExtractionIncomplete || !strings.Contains(analysis.Prompt, "Content processing limits prevented complete extraction") || !strings.Contains(analysis.Prompt, conditionalOmissionMarker) {
		t.Fatalf("prompt did not report omitted conditional content: %s", analysis.Prompt)
	}
}

func TestConditionalFragmentUsesScriptingDisabledBoundedParser(t *testing.T) {
	got := htmlToText(`<!--[if mso]><noscript><a href="https://example.test/fallback">Fallback notice</a></noscript><![endif]-->`)
	if got.ExtractionIncomplete || !strings.Contains(got.Text, "Fallback notice") || len(got.Links) != 1 {
		t.Fatalf("conditional noscript content was not extracted: %+v", got)
	}
}

func TestConditionalFragmentReportsCooperativeStop(t *testing.T) {
	fragment := `[if mso]>` + strings.Repeat(`<p>notice</p>`, 300) + `<![endif]`
	for _, stopAt := range []int{1, 3} {
		calls := 0
		budget := newExtractionBudgetWithControl(HTMLProcessingControl{ShouldFallback: func() bool {
			calls++
			return calls >= stopAt
		}})
		var out annotatedOutput
		var visible guardedBuilder
		e := htmlExtraction{shouldStop: budget.useFallback}
		e.writeConditionalComment(fragment, &out, &visible)
		rendered, _ := out.String()
		if !e.extractionIncomplete || !budget.cpuLimitExceeded || !strings.Contains(rendered, conditionalOmissionMarker) || visible.Len() != 0 {
			t.Fatalf("stop at check %d was not reported: output=%q visible=%q", stopAt, rendered, visible.String())
		}
	}
}

func TestRenderReportsCooperativeStop(t *testing.T) {
	root := &xhtml.Node{Type: xhtml.DocumentNode}
	for range 1_000 {
		root.AppendChild(&xhtml.Node{Type: xhtml.ElementNode, Data: "div"})
	}
	checks := 0
	e := htmlExtraction{inspection: htmlextract.Document{Root: root}, shouldStop: func() bool {
		checks++
		return checks == 2
	}}
	e.render(TagHidden)
	if !e.stopped || !e.extractionIncomplete || checks != 2 {
		t.Fatalf("stopped=%v incomplete=%v checks=%d, want true/true/2", e.stopped, e.extractionIncomplete, checks)
	}
}

func TestTreeExtractorPreservesConditionalCommentOffsetsAcrossUnicodeCaseFolding(t *testing.T) {
	for _, test := range []struct {
		name   string
		prefix string
		end    string
	}{
		{name: "kelvin sign", prefix: strings.Repeat("\u212a", 20), end: "<![endif]"},
		{name: "ohm sign", prefix: strings.Repeat("\u2126", 20), end: "<![endif]"},
		{name: "capital sharp s", prefix: strings.Repeat("\u1e9e", 20), end: "<![endif]"},
		{name: "capital dotted i", prefix: strings.Repeat("\u0130", 20), end: "<![endif]"},
		{name: "mixed-case marker", prefix: "", end: "<![EnDiF]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(`Before<!--[if mso]>` + test.prefix + `URGENT hidden offer` + test.end + `-->After`)
			if !strings.Contains(got.Text, test.prefix+`URGENT hidden offer`) {
				t.Fatalf("conditional content was truncated: %q", got.Text)
			}
			if !utf8.ValidString(got.Text) {
				t.Fatalf("conditional content contains invalid UTF-8: %q", got.Text)
			}
		})
	}
}

func TestTreeExtractorSummarizesOrdinaryHTMLComments(t *testing.T) {
	got := htmlToText(`vi<!-- harmless project meeting -->agra<!-- ordinary note --><!--[if mso]><p>Outlook</p><![endif]-->`)
	if got.Text != "viagra<visibility-uncertain>Outlook</visibility-uncertain>" {
		t.Fatalf("extracted text = %q", got.Text)
	}
	if got.HTMLComments.Characters != 41 || got.HTMLComments.WithinWords != 1 {
		t.Fatalf("comment statistics = %+v", got.HTMLComments)
	}
}

func TestTreeExtractorSanitizesReservedSenderTagsOnce(t *testing.T) {
	got := htmlToText(`<p>&lt;invisible reason="fake"&gt;trusted&lt;/invisible&gt; &lt;concealed&gt;legacy&lt;/concealed&gt; &amp;lt;invisible&amp;gt;once</p>`)
	if strings.Contains(got.Text, `reason="fake"`) || strings.Contains(got.Text, "trusted</invisible>") {
		t.Fatalf("sender tag survived: %q", got.Text)
	}
	if !strings.Contains(got.Text, "trusted") || !strings.Contains(got.Text, "<concealed>legacy</concealed>") || !strings.Contains(got.Text, "&lt;invisible&gt;once") {
		t.Fatalf("decoding was not exactly once: %q", got.Text)
	}
}

func TestTreeExtractorUsesParsedTableAncestry(t *testing.T) {
	got := htmlToText(`<table style="display:none">fostered evidence<tr><td>cell evidence</td></tr></table>`)
	if !strings.Contains(got.Text, "fostered evidence") || strings.Contains(got.Text, `<invisible reason="display:none">fostered evidence`) {
		t.Fatalf("fostered text = %q", got.Text)
	}
	if !strings.Contains(got.Text, `<invisible reason="display:none">cell evidence</invisible>`) {
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
	if !analysis.HasConcealedContent || !analysis.UsedHiddenContentStrippedTag || analysis.UsedInvisibleTag {
		t.Fatalf("annotation metadata = %+v", analysis)
	}
	if !strings.Contains(analysis.Prompt, "<hidden-content-stripped/>") || !strings.Contains(analysis.Prompt, "HTML-TO-TEXT EXTRACTOR ANNOTATIONS") {
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

func TestOptionalParagraphEndsDoNotForceHTMLFallback(t *testing.T) {
	got := htmlToText(strings.Repeat(`<p>`, 200) + `<div style="display:none">concealed evidence</div>`)
	if got.HTMLFallbackUsed || got.ExtractionIncomplete || !got.HasConcealedContent {
		t.Fatalf("optional paragraph ends lost concealment analysis: %+v", got)
	}
	if got.ConfidentVisibleChars != 0 || !strings.Contains(got.Text, "<invisible") {
		t.Fatalf("concealed evidence counted as visible: %+v", got)
	}
}

func TestUnrelatedKeyframesPreserveConcealmentEvidence(t *testing.T) {
	got := htmlToText(`<style>@keyframes dummy{from{}}*{animation:missing 1s}</style><div style="display:none">concealed evidence</div><p>Visible notice</p>`)
	if !got.HasConcealedContent || !strings.Contains(got.Text, "<invisible") {
		t.Fatalf("unrelated keyframes removed concealment evidence: %+v", got)
	}
	if strings.Contains(got.StrippedText, "concealed evidence") || !strings.Contains(got.StrippedText, "Visible notice") {
		t.Fatalf("incorrect stripped text: %q", got.StrippedText)
	}
	if got.ConfidentVisibleChars != len("Visible notice") {
		t.Fatalf("confident visible character count = %d", got.ConfidentVisibleChars)
	}
}

func TestBoundedHTMLFallbackStreamsAttributesAndKeepsFirstDestination(t *testing.T) {
	got := extractBoundedHTMLFallback(`<base ignored="x" href="https://example.test/root/"><a class="offer" href="first" href="second">Review</a><img alt="notice" src="cid:image-id">`, true, nil)
	if len(got.Links) != 1 || got.Links[0] != "https://example.test/root/first" {
		t.Fatalf("fallback links = %#v", got.Links)
	}
	if len(got.ImageRefs) != 1 || got.ImageRefs[0] != "image-id" {
		t.Fatalf("fallback image references = %#v", got.ImageRefs)
	}
	if got.Text != "Review" || got.VisibleText != "" || !got.HTMLFallbackUsed {
		t.Fatalf("fallback content = %+v", got)
	}
}

func TestFallbackTokenizerHonoursSeparateCPUStop(t *testing.T) {
	checks := 0
	got := extractBoundedHTMLFallback(strings.Repeat("<x>", 2000)+"late text", true, func() bool {
		checks++
		return checks > 1
	})
	if !got.HTMLCPULimitExceeded || !got.ExtractionIncomplete || !got.HTMLFallbackUsed {
		t.Fatalf("fallback flags = %+v", got)
	}
	if checks < 2 {
		t.Fatalf("fallback stop checks = %d, want at least 2", checks)
	}
}

func TestBoundedHTMLFallbackCapsSingleTextToken(t *testing.T) {
	got := extractBoundedHTMLFallback(strings.Repeat("x", fallbackTextBytes*2)+"sentinel", true, nil)
	if len(got.Text) != fallbackTextBytes {
		t.Fatalf("fallback text length = %d, want %d", len(got.Text), fallbackTextBytes)
	}
	if strings.Contains(got.Text, "sentinel") {
		t.Fatal("fallback retained text beyond its limit")
	}
	if !got.ExtractionIncomplete || !got.HTMLFallbackUsed {
		t.Fatalf("fallback flags = %+v", got)
	}
}

func TestForeignAncestorUncertaintyDoesNotSuppressVision(t *testing.T) {
	body := `<style>foreignObject div{display:none}</style><foreignObject><div>` + strings.Repeat("padding ", 50) + `</div></foreignObject><img src="cid:scam-image">`
	got := htmlToText(body)
	if got.ConfidentVisibleChars != 0 {
		t.Fatalf("uncertain text counted as confident: %d", got.ConfidentVisibleChars)
	}
	m := multipartRelatedMessage("", body, "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 10000, VisionOptions{Mode: "fallback", MinTextChars: 200, MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100})
	if len(analysis.Images) != 1 {
		t.Fatalf("uncertain padding suppressed vision: %d", len(analysis.Images))
	}
}

func TestObjectFallbackRetainsUncertainText(t *testing.T) {
	got := htmlToText(`<object data="missing.png" type="image/png"><p>Fallback text</p></object>`)
	if !strings.Contains(got.Text, `<visibility-uncertain>Fallback text</visibility-uncertain>`) {
		t.Fatalf("fallback missing or confidently classified: %q", got.Text)
	}
	if got.ConfidentVisibleChars != 0 {
		t.Fatalf("fallback counted as confidently visible: %d", got.ConfidentVisibleChars)
	}
}

func TestCompactConcealmentReasonPriority(t *testing.T) {
	for _, c := range []struct {
		mask        htmlextract.ConcealmentReason
		name, value string
	}{
		{htmlextract.ReasonDisplayNone | htmlextract.ReasonColour, "display:none", ""},
		{htmlextract.ReasonVisibilityHidden | htmlextract.ReasonOpacity, "visibility:hidden", ""},
		{htmlextract.ReasonVisibilityCollapse | htmlextract.ReasonContentVisibility, "visibility:collapse", ""},
		{htmlextract.ReasonOpacity | htmlextract.ReasonFontSize, "opacity", "0.001"},
		{htmlextract.ReasonFontSize | htmlextract.ReasonColour, "font-size", "1px"},
		{htmlextract.ReasonColour | htmlextract.ReasonEmptyClip, "color-match", ""},
		{htmlextract.ReasonEmptyClip | htmlextract.ReasonContentVisibility, "empty-clip", ""},
		{htmlextract.ReasonContentVisibility, "content-visibility:hidden", ""},
	} {
		name, value := formatConcealmentReason(c.mask, .001, "1px")
		if name != c.name || value != c.value {
			t.Fatalf("mask %d: got (%s,%s), want (%s,%s)", c.mask, name, value, c.name, c.value)
		}
	}
}
