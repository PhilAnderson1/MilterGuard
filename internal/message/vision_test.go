package message

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

func TestVisionFallbackSelectsReferencedInlineImage(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
	if analysis.Images[0].MediaType != "image/png" {
		t.Fatalf("media type = %q, want image/png", analysis.Images[0].MediaType)
	}
	if !strings.Contains(analysis.Prompt, "INLINE EMAIL IMAGES: 1") {
		t.Fatalf("vision disclosure missing from prompt: %s", analysis.Prompt)
	}
}

func TestPercentEncodedCIDIsNormalizedOnceAndMatchesImage(t *testing.T) {
	m := multipartRelatedMessage("Fallback", `<img src="cid:image%252Did" alt="Notice">`, "<image%252Did>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
	if !strings.Contains(analysis.Prompt, `![Notice](cid:image%2did)`) {
		t.Fatalf("normalized CID evidence missing from prompt: %s", analysis.Prompt)
	}
}

func TestNormalizeContentIDRemovesOnlyOneAngleBracketPair(t *testing.T) {
	if got, want := normalizeContentID("<<Image-ID>>"), "<image-id>"; got != want {
		t.Fatalf("normalized content ID = %q, want %q", got, want)
	}
}

func TestVisionFallbackSelectsStandaloneImageAttachment(t *testing.T) {
	m := New(1 << 20)
	m.AddHeader("Content-Type", `multipart/mixed; boundary="outer"`)
	m.AddBody([]byte("--outer\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n\r\n" +
		"--outer\r\nContent-Type: image/png; name=order.png\r\n" +
		"Content-Disposition: attachment; filename=order.png\r\n" +
		"Content-ID: <gmail-attachment-id>\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + onePixelPNG + "\r\n" +
		"--outer--\r\n"))

	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 500, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
	if analysis.Images[0].MediaType != "image/png" {
		t.Fatalf("media type = %q, want image/png", analysis.Images[0].MediaType)
	}
	if !strings.Contains(analysis.Prompt, "[attachment: order.png; type=image/png]") {
		t.Fatalf("attachment evidence missing from prompt: %s", analysis.Prompt)
	}
	if !strings.Contains(analysis.Prompt, "INLINE EMAIL IMAGES: 1") {
		t.Fatalf("vision disclosure missing from prompt: %s", analysis.Prompt)
	}
}

func TestVisionPrefersReferencedImageOverStandaloneAttachment(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(onePixelPNG)
	if err != nil {
		t.Fatal(err)
	}
	content := extractedContent{
		ImageRefs: []string{"referenced"},
		Images: []extractedImage{
			{Data: decoded},
			{ContentID: "referenced", Data: append([]byte(nil), decoded...)},
		},
	}
	content.Images[1].Data[len(content.Images[1].Data)-1] ^= 1
	images := selectVisionImages(content, VisionOptions{
		Mode: "always", MaxImages: 1, MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(images) != 1 {
		t.Fatalf("selected images = %d, want 1", len(images))
	}
	if !bytes.Equal(images[0].Data, content.Images[1].Data) {
		t.Fatal("standalone attachment displaced referenced image")
	}
}

func TestVisionUnknownModeSelectsNoImages(t *testing.T) {
	decoded, err := base64.StdEncoding.DecodeString(onePixelPNG)
	if err != nil {
		t.Fatal(err)
	}
	images := selectVisionImages(extractedContent{Images: []extractedImage{{Data: decoded}}}, VisionOptions{
		Mode: "unknown", MaxImages: 1, MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(images) != 0 {
		t.Fatalf("unknown vision mode selected %d images", len(images))
	}
}

func TestVisionFallbackIgnoresGeneratedLinkAndImageEvidenceForTextThreshold(t *testing.T) {
	longDestination := "https://security.example/review?token=" + strings.Repeat("x", 400)
	m := multipartRelatedMessage("Fallback", `<a href="`+longDestination+`"><img alt="Long generated image description" src="cid:notice"></a>`, "<notice>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 2000, VisionOptions{
		Mode: "fallback", MinTextChars: 20, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if !strings.Contains(analysis.Prompt, longDestination) || !strings.Contains(analysis.Prompt, "![Long generated image description](cid:notice)") {
		t.Fatalf("link or image evidence missing from prompt: %s", analysis.Prompt)
	}
	if len(analysis.Images) != 1 {
		t.Fatalf("generated evidence inflated visible-text threshold; selected images = %d", len(analysis.Images))
	}
}

func TestVisionFallbackCountsVisibleAnchorLabel(t *testing.T) {
	visibleLabel := strings.Repeat("visible words ", 20)
	m := multipartRelatedMessage("Fallback", `<a href="https://example.test/review">`+visibleLabel+`</a><img src="cid:notice">`, "<notice>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 2000, VisionOptions{
		Mode: "fallback", MinTextChars: 20, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatalf("visible anchor label was excluded from text threshold: %#v", analysis.Images)
	}
}

func TestAlternativeSelectsRelatedHTMLWithLinkedCIDImage(t *testing.T) {
	m := New(1 << 20)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="alternative"`)
	m.AddBody([]byte("--alternative\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\nPlain fallback without the destination.\r\n" +
		"--alternative\r\nContent-Type: multipart/related; boundary=\"related\"\r\n\r\n" +
		"--related\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" +
		`<a href="https://security.example/review"><img src="cid:notice" alt="Review security notice"></a>` + "\r\n" +
		"--related\r\nContent-Type: image/png; name=notice.png\r\n" +
		"Content-ID: <notice>\r\nContent-Disposition: inline\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + onePixelPNG + "\r\n" +
		"--related--\r\n--alternative--\r\n"))

	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if strings.Contains(analysis.Prompt, "Plain fallback") {
		t.Fatalf("selected plain alternative instead of related HTML: %s", analysis.Prompt)
	}
	if !strings.Contains(analysis.Prompt, "https://security.example/review") {
		t.Fatalf("linked-image destination missing: %s", analysis.Prompt)
	}
	if !strings.Contains(analysis.Prompt, "![Review security notice](cid:notice)") {
		t.Fatalf("CID image reference missing: %s", analysis.Prompt)
	}
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
}

func TestAlternativeDoesNotTreatRelatedImageWithoutHTMLAsHTML(t *testing.T) {
	m := New(1 << 20)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="alternative"`)
	m.AddBody([]byte("--alternative\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n\r\nPreferred plain text.\r\n" +
		"--alternative\r\nContent-Type: multipart/related; boundary=\"related\"\r\n\r\n" +
		"--related\r\nContent-Type: image/png\r\nContent-ID: <notice>\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + onePixelPNG + "\r\n" +
		"--related--\r\n--alternative--\r\n"))

	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "always", MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if !strings.Contains(analysis.Prompt, "Preferred plain text.") {
		t.Fatalf("plain alternative missing: %s", analysis.Prompt)
	}
	if len(analysis.Images) != 0 {
		t.Fatalf("related image-only branch displaced plain alternative: %#v", analysis.Images)
	}
}

func TestVisionFallbackSelectsUnreferencedEmbeddedImage(t *testing.T) {
	m := imageOnlyMessage("cid:different-image", "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
}

func TestVisionOffAndRemoteImagesAreNeverSelected(t *testing.T) {
	inline := imageOnlyMessage("cid:scam-image", "<scam-image>")
	if images := inline.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "off", MinTextChars: 200, MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("vision mode off selected an inline image")
	}

	remote := New(10000)
	remote.AddHeader("Content-Type", "text/html")
	remote.AddBody([]byte(`<img src="https://tracker.example/image.png">`))
	if images := remote.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "always", MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("selected or fetched a remote image")
	}
}

func TestVisionFallbackSkipsImageWhenTextIsMeaningful(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	longText := strings.Repeat("This is meaningful body text. ", 20)
	m = multipartRelatedMessage(longText, `<p>`+longText+`</p><img src="cid:scam-image">`, "<scam-image>")
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatal("fallback mode selected an image despite sufficient visible text")
	}
}

func TestVisionImageLimitsAreEnforced(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	decoded, err := base64.StdEncoding.DecodeString(onePixelPNG)
	if err != nil {
		t.Fatal(err)
	}
	analysis := m.BuildAnalysis(AnalysisContext{}, 1000, VisionOptions{
		Mode: "always", MaxImages: 1, MaxBytes: int64(len(decoded) - 1), MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatal("selected an image exceeding the byte limit")
	}
}

func TestVisionRejectsSmallImageFileWithExcessiveDeclaredPixels(t *testing.T) {
	// This is a compact 1x1 GIF whose logical-screen dimensions are changed to
	// 65535x65535. DecodeConfig reads those dimensions without expanding the
	// image, allowing the pixel limit to reject a potential decompression bomb.
	data, err := base64.StdEncoding.DecodeString("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
	if err != nil {
		t.Fatal(err)
	}
	data[6], data[7], data[8], data[9] = 0xff, 0xff, 0xff, 0xff
	image, ok := visionImage(extractedImage{Data: data}, VisionOptions{
		MaxBytes: 1 << 20, MaxPixels: 12_000_000,
	})
	if ok || len(image.Data) != 0 {
		t.Fatalf("selected image with excessive declared dimensions: %#v", image)
	}
}

func imageOnlyMessage(src, contentID string) *Message {
	return multipartRelatedMessage("[7d4d-90d5-ef340]", `<img alt="7d4d-90d5-ef340" src="`+src+`">`, contentID)
}

func multipartRelatedMessage(plain, html, contentID string) *Message {
	m := New(1 << 20)
	m.AddHeader("Content-Type", `multipart/related; boundary="outer"`)
	body := "--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=\"inner\"\r\n\r\n" +
		"--inner\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + plain + "\r\n" +
		"--inner\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html><body>" + html + "</body></html>\r\n" +
		"--inner--\r\n" +
		"--outer\r\nContent-Type: image/png; name=notice.png\r\n" +
		"Content-ID: " + contentID + "\r\nContent-Disposition: inline\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + onePixelPNG + "\r\n" +
		"--outer--\r\n"
	m.AddBody([]byte(body))
	return m
}
