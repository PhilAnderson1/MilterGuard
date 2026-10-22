package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
)

func TestPromptDecodesMultipart(t *testing.T) {
	m := New(10000)
	m.AddHeader("Subject", "Test")
	m.AddHeader("Message-ID", "<test@example.invalid>")
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n"))
	p := m.Prompt(1000)
	if !strings.Contains(p, "hello") {
		t.Fatalf("decoded text missing: %s", p)
	}
	if strings.Contains(p, "Content-Type:") {
		t.Fatalf("MIME content type leaked into selected headers: %s", p)
	}
	if strings.Contains(p, "Message-Id:") {
		t.Fatalf("message ID leaked into selected headers: %s", p)
	}
}

func TestTransferDecodingRecoversMalformedInput(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		input    string
		want     string
	}{
		{"valid Base64", "base64", "aGVsbG8=", "hello"},
		{"unpadded Base64", "base64", "aGVsbG8", "hello"},
		{"Base64 valid prefix", "base64", "aGVsbG8=!!", "hello"},
		{"completely invalid Base64", "base64", "!!!!", "!!!!"},
		{"quoted-printable valid prefix", "quoted-printable", "hello\x00bad", "hello"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoded, _ := decodeTransferRecovering(test.encoding, []byte(test.input))
			if got := string(decoded); got != test.want {
				t.Fatalf("decodeTransferRecovering(%q, %q) = %q, want %q", test.encoding, test.input, got, test.want)
			}
		})
	}
}

func TestTransferDecodingReportsUnsupportedEncoding(t *testing.T) {
	for _, encoding := range []string{"", "7bit", "8bit", "binary"} {
		decoded, incomplete := decodeTransferRecovering(encoding, []byte("plain text"))
		if string(decoded) != "plain text" || incomplete {
			t.Errorf("standard identity encoding %q = %q, incomplete=%v", encoding, decoded, incomplete)
		}
	}
	for _, encoding := range []string{"base-64", "uuencode", "x-unknown"} {
		decoded, incomplete := decodeTransferRecovering(encoding, []byte("encoded data"))
		if string(decoded) != "encoded data" || !incomplete {
			t.Errorf("unsupported encoding %q = %q, incomplete=%v", encoding, decoded, incomplete)
		}
	}
	if decoded, incomplete := decodeTransferRecovering("x-unknown", nil); len(decoded) != 0 || incomplete {
		t.Errorf("empty unsupported encoding = %q, incomplete=%v", decoded, incomplete)
	}
}

func TestPromptReportsUnsupportedTransferEncoding(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/plain")
	m.AddHeader("Content-Transfer-Encoding", "base-64")
	m.AddBody([]byte("aGVsbG8="))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "A MIME part could not be fully transfer-decoded") || !strings.Contains(prompt, "aGVsbG8=") {
		t.Fatalf("unsupported transfer encoding was not retained and reported: %s", prompt)
	}
}

func TestPromptReportsIncompleteTransferDecoding(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/plain")
	m.AddHeader("Content-Transfer-Encoding", "base64")
	m.AddBody([]byte("aGVsbG8=!!"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "A MIME part could not be fully transfer-decoded") || !strings.Contains(prompt, "hello") {
		t.Fatalf("partial transfer decode was not reported: %s", prompt)
	}
}

func TestUnpaddedBase64DoesNotReportIncompleteTransfer(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/plain")
	m.AddHeader("Content-Transfer-Encoding", "base64")
	m.AddBody([]byte("aGVsbG8"))
	prompt := m.Prompt(1000)
	if strings.Contains(prompt, "ANALYSIS LIMITATIONS") || !strings.Contains(prompt, "hello") {
		t.Fatalf("recoverable unpadded Base64 was marked incomplete: %s", prompt)
	}
}

func TestAlternativePreservesIncompleteTransferNoticeFromUnselectedPart(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=!!\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>Visible HTML</p>\r\n--x--\r\n"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "A MIME part could not be fully transfer-decoded") || !strings.Contains(prompt, "Visible HTML") {
		t.Fatalf("alternative lost extraction limitation: %s", prompt)
	}
}

func TestPromptReportsIncompleteMultipartParsing(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/mixed; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\n\r\nFirst part\r\n--x\r\ninvalid header\r\n\r\nSecond part\r\n--x--\r\n"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "MIME content could not be fully parsed") || !strings.Contains(prompt, "First part") {
		t.Fatalf("partial multipart parse was not reported: %s", prompt)
	}
}

func TestPromptReportsMultipartWithoutBoundary(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "multipart/mixed")
	m.AddBody([]byte("unparseable multipart body"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "[multipart message has no boundary]") {
		t.Fatalf("missing-boundary marker was not included: %s", prompt)
	}
	if !strings.Contains(prompt, "MIME content could not be fully parsed") {
		t.Fatalf("missing-boundary limitation was not included: %s", prompt)
	}
}

func TestStructuralMIMEHeadersUseFirstOccurrence(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html; charset=UTF-8")
	m.AddHeader("Content-Type", "text/plain")
	m.AddHeader("Content-Transfer-Encoding", "quoted-printable")
	m.AddHeader("Content-Transfer-Encoding", "base64")
	m.AddBody([]byte(`<p>caf=C3=A9 <a href="https://example.invalid/">link</a></p>`))

	if got, want := m.Header("Content-Type"), "text/html; charset=UTF-8, text/plain"; got != want {
		t.Fatalf("joined Content-Type = %q, want %q", got, want)
	}
	if got, want := m.FirstHeader("Content-Type"), "text/html; charset=UTF-8"; got != want {
		t.Fatalf("first Content-Type = %q, want %q", got, want)
	}
	if got, want := m.ProcessedBody(1000), `café [link](https://example.invalid/)`; got != want {
		t.Fatalf("processed body = %q, want %q", got, want)
	}
}

func TestMIMEExtractionDecodesDeclaredBodyCharset(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        string
	}{
		{
			name:        "plain text",
			contentType: `text/plain; charset=iso-8859-1`,
			body:        "caf=E9",
			want:        "café",
		},
		{
			name:        "HTML",
			contentType: `text/html; charset=iso-8859-1`,
			body:        `<p>caf=E9 <a href="https://example.invalid/">link</a></p>`,
			want:        `café [link](https://example.invalid/)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := extractMIME(test.contentType, "quoted-printable", "", []byte(test.body), 0)
			if !strings.Contains(content.Text, test.want) {
				t.Fatalf("extracted text = %q, want it to contain %q", content.Text, test.want)
			}
		})
	}
}

func TestUTF8CharsetDecodingPreservesValidTextAndHandlesMalformedInput(t *testing.T) {
	valid := []byte("café")
	for _, label := range []string{"utf-8", "UTF8", "unicode-1-1-utf-8"} {
		got, complete := decodeCharset(label, valid, 100)
		if !complete || got != string(valid) {
			t.Errorf("decodeCharset(%q) = %q, want %q", label, got, valid)
		}
	}
	if got, complete := decodeCharset("utf-8", []byte{'a', 0xff, 'b'}, 100); !complete || got != "a�b" {
		t.Fatalf("malformed UTF-8 = %q, want replacement character", got)
	}
	if got := decodeHTMLCharset("utf-8", append([]byte("\xef\xbb\xbf"), valid...), 100); got != string(valid) {
		t.Fatalf("BOM-prefixed HTML UTF-8 = %q, want %q", got, valid)
	}
}

func TestPlainTextCharsetDecodingIsBoundedAfterExpansion(t *testing.T) {
	const limit = 8
	got, complete := decodeCharset("windows-1252", bytes.Repeat([]byte{0x92}, 100), limit)
	if complete {
		t.Fatal("oversized charset conversion reported complete")
	}
	if len(got) > limit || !utf8.ValidString(got) {
		t.Fatalf("bounded decoded text = %q (%d bytes)", got, len(got))
	}

	budget := newExtractionBudget()
	budget.setDecodedTextByteLimit(limit)
	content := extractMIMEWithBudget("text/plain; charset=windows-1252", "", "", bytes.Repeat([]byte{0x92}, 100), 0, budget)
	if !content.ExtractionIncomplete || len(content.Text) > limit {
		t.Fatalf("oversized plain text was not bounded: %+v", content)
	}
}

func TestHTMLCharsetDecodingIsBoundedAfterExpansion(t *testing.T) {
	const limit = 8
	got := decodeHTMLCharset("windows-1252", bytes.Repeat([]byte{0x92}, 100), limit)
	if len(got) != limit+1 {
		t.Fatalf("expanded HTML length = %d, want %d", len(got), limit+1)
	}

	budget := newExtractionBudget()
	budget.htmlBytesRemaining = limit
	content := extractMIMEWithBudget("text/html; charset=windows-1252", "", "", bytes.Repeat([]byte{0x92}, 100), 0, budget)
	if !content.ExtractionIncomplete || !content.HTMLFallbackUsed {
		t.Fatalf("oversized decoded HTML was not handled as incomplete fallback: %+v", content)
	}
}

func TestHTMLCharsetSniffingWithoutUsableMIMECharset(t *testing.T) {
	for _, contentType := range []string{"text/html", "text/html; charset=unknown-charset"} {
		t.Run(contentType, func(t *testing.T) {
			m := New(10000)
			m.AddHeader("Content-Type", contentType)
			m.AddBody([]byte("<meta charset=shift_jis><p>\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd</p>"))
			if got := m.ProcessedBody(1000); got != "こんにちは" {
				t.Fatalf("HTML with internal charset = %q, want こんにちは", got)
			}
		})
	}
}

func TestHTMLCharsetSniffingHonorsBOM(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte("\xff\xfe<\x00p\x00>\x00H\x00i\x00<\x00/\x00p\x00>\x00"))
	if got := m.ProcessedBody(1000); strings.TrimSpace(got) != "Hi" {
		t.Fatalf("BOM-encoded HTML = %q, want Hi", got)
	}
}

func TestValidMIMECharsetTakesPrecedenceOverHTMLMeta(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html; charset=iso-8859-1")
	m.AddBody([]byte("<meta charset=shift_jis><p>caf\xe9</p>"))
	if got := m.ProcessedBody(1000); got != "café" {
		t.Fatalf("MIME-declared HTML charset was overridden: %q", got)
	}
}

func TestPlainTextDoesNotSniffHTMLMetaCharset(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/plain")
	m.AddBody([]byte("<meta charset=windows-1252>caf\xe9"))
	if got := m.ProcessedBody(1000); got != "<meta charset=windows-1252>caf�" {
		t.Fatalf("plain text unexpectedly used HTML charset sniffing: %q", got)
	}
}

func TestMIMEExtractionRetainsBodyForUnknownCharset(t *testing.T) {
	body := []byte("body with an unsupported charset label")
	content := extractMIME(`text/plain; charset=x-not-a-real-charset`, "", "", body, 0)
	if content.Text != string(body) {
		t.Fatalf("extracted text = %q, want original body %q", content.Text, body)
	}
}

func TestMIMEExtractionReadsAttachedMessage(t *testing.T) {
	attached := "From: sender@example.net\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		`<p>Nested evidence <a href="https://evil.invalid/login">sign in</a></p>`
	content := extractMIME("message/rfc822", "", "", []byte(attached), 0)
	if want := `Nested evidence [sign in](https://evil.invalid/login)`; !strings.Contains(content.Text, want) {
		t.Fatalf("attached-message text = %q, want it to contain %q", content.Text, want)
	}
}

func TestMIMEAttachedMessageRecursionLimit(t *testing.T) {
	nestedMessage := func(levels int) []byte {
		message := "Content-Type: text/plain; charset=UTF-8\r\n\r\ndeep nested evidence"
		for level := 1; level < levels; level++ {
			message = "Content-Type: message/rfc822\r\n\r\n" + message
		}
		return []byte(message)
	}

	atLimit := extractMIME("message/rfc822", "", "", nestedMessage(8), 0)
	if atLimit.Text != "deep nested evidence" {
		t.Fatalf("content at MIME nesting limit = %q, want nested evidence", atLimit.Text)
	}

	beyondLimit := extractMIME("message/rfc822", "", "", nestedMessage(9), 0)
	if beyondLimit.Text != "[MIME nesting limit reached]" || !beyondLimit.MIMEIncomplete {
		t.Fatalf("content beyond MIME nesting limit = %#v, want incomplete limit marker", beyondLimit)
	}

	m := New(10000)
	m.AddHeader("Content-Type", "message/rfc822")
	m.AddBody(nestedMessage(9))
	prompt := m.Prompt(1000)
	for _, want := range []string{
		"[MIME nesting limit reached]",
		"MIME content could not be fully parsed; nested or later parts may be missing.",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("depth-limited prompt missing %q: %s", want, prompt)
		}
	}
}

func TestMultipartDigestDefaultsPartsToAttachedMessages(t *testing.T) {
	attached := "From: sender@example.net\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		`<p>Digest evidence <a href="https://evil.invalid/digest">open</a></p>`
	body := "--digest\r\n\r\n" + attached + "\r\n--digest--\r\n"
	content := extractMIME(`multipart/digest; boundary="digest"`, "", "", []byte(body), 0)
	if want := `Digest evidence [open](https://evil.invalid/digest)`; !strings.Contains(content.Text, want) {
		t.Fatalf("digest text = %q, want it to contain %q", content.Text, want)
	}
}

func TestMalformedAttachedMessageProducesMarker(t *testing.T) {
	content := extractMIME("message/rfc822", "", "", []byte("not a valid message"), 0)
	if content.Text != "[attached message could not be parsed]" {
		t.Fatalf("attached-message text = %q", content.Text)
	}
}

func TestMIMEExtractionRetainsContentBeyondTwoMiB(t *testing.T) {
	tail := "evidence-after-two-mib"
	largeText := strings.Repeat("a", 2<<20+1024) + tail

	t.Run("transfer decoded body", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte(largeText))
		content := extractMIME("text/plain", "base64", "", []byte(encoded), 0)
		if !strings.HasSuffix(content.Text, tail) {
			t.Fatal("transfer-decoded MIME content was truncated before its tail")
		}
	})

	t.Run("multipart body", func(t *testing.T) {
		body := "--x\r\nContent-Type: text/plain\r\n\r\n" + largeText + "\r\n--x--\r\n"
		content := extractMIME(`multipart/mixed; boundary="x"`, "", "", []byte(body), 0)
		if !strings.Contains(content.Text, tail) {
			t.Fatal("multipart MIME content was truncated before its tail")
		}
	})
}

func TestMIMEPartLimitAppliesAcrossMessage(t *testing.T) {
	var body strings.Builder
	for i := 0; i < maxMIMEParts; i++ {
		fmt.Fprintf(&body, "--x\r\nContent-Type: text/plain\r\n\r\npart-%d\r\n", i)
	}
	body.WriteString("--x\r\nContent-Type: text/plain\r\n\r\ntail-beyond-part-limit\r\n--x--\r\n")
	content := extractMIME(`multipart/mixed; boundary="x"`, "", "", []byte(body.String()), 0)
	if !content.MIMEIncomplete {
		t.Fatal("MIME part limit was not reported")
	}
	if strings.Contains(content.Text, "tail-beyond-part-limit") {
		t.Fatal("content beyond MIME part limit was processed")
	}
}

func TestHTMLPartLimitAppliesAcrossAlternatives(t *testing.T) {
	var body strings.Builder
	for i := 0; i <= maxHTMLParts; i++ {
		fmt.Fprintf(&body, "--x\r\nContent-Type: text/html\r\n\r\n<p>alternative-%d</p>\r\n", i)
	}
	body.WriteString("--x--\r\n")
	content := extractMIME(`multipart/alternative; boundary="x"`, "", "", []byte(body.String()), 0)
	if !content.ExtractionIncomplete || !content.HTMLFallbackUsed {
		t.Fatalf("HTML part limit was not reported: %+v", content)
	}
	if !strings.Contains(content.Text, fmt.Sprintf("alternative-%d", maxHTMLParts)) {
		t.Fatalf("selected bounded fallback missing: %q", content.Text)
	}
}

func TestHTMLByteBudgetIsSharedAcrossParts(t *testing.T) {
	budget := newExtractionBudget()
	firstSource := `<p>first</p>`
	budget.htmlBytesRemaining = len(firstSource)
	first := htmlToTextWithBudget(firstSource, budget)
	if first.HTMLFallbackUsed {
		t.Fatal("HTML at the byte limit unexpectedly used lexical fallback")
	}
	second := htmlToTextWithBudget(`<p>second</p>`, budget)
	if !second.HTMLFallbackUsed || !second.ExtractionIncomplete {
		t.Fatalf("cumulative HTML byte limit was not enforced: %+v", second)
	}
}

func TestHTMLCSSByteBudgetIsSharedAcrossParts(t *testing.T) {
	const cssText = `p{display:none}`
	budget := newExtractionBudget()
	budget.cssBytesRemaining = len(cssText)
	first := htmlToTextWithBudget(`<style>`+cssText+`</style><p>first</p>`, budget)
	if first.HTMLFallbackUsed || budget.cssBytesRemaining != 0 {
		t.Fatalf("first HTML part did not consume exact CSS budget: content=%+v remaining=%d", first, budget.cssBytesRemaining)
	}
	second := htmlToTextWithBudget(`<p>second</p>`, budget)
	if !second.HTMLFallbackUsed || !second.ExtractionIncomplete {
		t.Fatalf("exhausted cumulative CSS budget was not enforced: %+v", second)
	}
}

func TestMultipartAlternativePrefersHTML(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nplain-only wording\r\n" +
		"--x\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>HTML <a href=\"https://example.invalid/login\">sign in</a></p>\r\n" +
		"--x--\r\n"))
	prompt := m.Prompt(1000)
	if strings.Contains(prompt, "plain-only wording") {
		t.Fatalf("plain alternative must be ignored when HTML is available: %s", prompt)
	}
	if !strings.Contains(prompt, "HTML [sign in](https://example.invalid/login)") {
		t.Fatalf("HTML alternative or link destination missing: %s", prompt)
	}
}

func TestMultipartAlternativeFallsBackToPlainText(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nplain fallback\r\n--x--\r\n"))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "plain fallback") {
		t.Fatalf("plain-text fallback missing: %s", prompt)
	}
}

func TestMultipartAlternativeAppliesLimitAfterSelection(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + strings.Repeat("padding ", 500) + "\r\n" +
		"--x\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<p>short HTML body</p>\r\n" +
		"--x--\r\n"))
	prompt := m.Prompt(30)
	if !strings.Contains(prompt, "short HTML body") || strings.Contains(prompt, "[body truncated]") {
		t.Fatalf("limit was not applied after selecting the HTML alternative: %s", prompt)
	}
}

func TestHTMLMemoryBudgetIsSharedAcrossParts(t *testing.T) {
	budget := newExtractionBudget()
	initial := budget.remainingMemory()
	budget.consumeHTML(htmlextract.AnalysisUsage{ResourceUsage: htmlextract.ResourceUsage{MemoryBytes: initial / 3}})
	limits, ok := budget.htmlLimits(1)
	if !ok {
		t.Fatal("remaining shared memory budget rejected")
	}
	if limits.MemoryBytes != initial-initial/3 {
		t.Fatalf("remaining memory=%d want=%d", limits.MemoryBytes, initial-initial/3)
	}
	budget.consumeHTML(htmlextract.AnalysisUsage{ResourceUsage: htmlextract.ResourceUsage{MemoryBytes: limits.MemoryBytes}})
	expectTermination(t, termination.MemoryExceeded, func() { budget.htmlLimits(1) })
}

func TestMultipartJoinReservesOutputBeforeAllocation(t *testing.T) {
	budget := newExtractionBudget()
	initial := budget.remainingMemory()
	joined := joinExtractedText([]string{"only"}, "\n\n", budget)
	if joined != "only" || budget.remainingMemory() != initial {
		t.Fatalf("single-part join: joined=%q remaining=%d", joined, budget.remainingMemory())
	}

	budget = newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 5})
	expectTermination(t, termination.MemoryExceeded, func() { joinExtractedText([]string{"ab", "cd"}, "\n\n", budget) })
	if budget.remainingMemory() != 0 {
		t.Fatal("lost exhaustion")
	}

	budget = newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 6})
	joined = joinExtractedText([]string{"ab", "cd"}, "\n\n", budget)
	if joined != "ab\n\ncd" || budget.remainingMemory() != 0 {
		t.Fatalf("bounded join: joined=%q remaining=%d", joined, budget.remainingMemory())
	}
}

func TestMultipartJoinsCheckCPUBetweenCopies(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckPrimary: func() {
		calls++
		if calls >= 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})

	if joined := joinExtractedText([]string{"a", "b"}, "", budget); joined != "ab" {
		t.Fatalf("first join: joined=%q", joined)
	}

	expectTermination(t, termination.CPUExceeded, func() { joinExtractedText([]string{"c", "d"}, "", budget) })
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestUTF8NormalisationChecksCPUBetweenScans(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckPrimary: func() {
		calls++
		if calls >= 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})
	content := extractedContent{
		Text:         string([]byte{'a', 0xff}),
		VisibleText:  string([]byte{'b', 0xff}),
		StrippedText: string([]byte{'c', 0xff}),
	}
	expectTermination(t, termination.CPUExceeded, func() { normalizeExtractedUTF8(&content, budget) })
	if content.Text != "a�" || content.VisibleText != "b\xff" || content.StrippedText != "c\xff" {
		t.Fatalf("normalization continued: %+v", content)
	}
	discardInvalidUTF8(&content)
	if content.Text != "a�" || content.VisibleText != "" || content.StrippedText != "" {
		t.Fatalf("invalid fields retained: %+v", content)
	}
}

func TestHTMLProcessingReportsMemoryUsage(t *testing.T) {
	m := New(10_000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte("<p>reported memory</p>"))
	var used, limit int64
	analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 1_000, VisionOptions{Mode: "off"}, HTMLProcessingControl{
		MemoryBytes: 8 << 20,
		ObserveMemoryUsage: func(observedUsed, observedLimit int64) {
			used, limit = observedUsed, observedLimit
		},
	})
	if analysis.BodyExtractionIncomplete || used <= 0 || limit != 8<<20 || used >= limit {
		t.Fatalf("reported memory: used=%d limit=%d analysis=%+v", used, limit, analysis)
	}
}

func TestMultipartExtractionStopsAtContentCPULimit(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{BeginFallback: func() bool { return false }, CheckPrimary: func() {
		calls++
		if calls >= 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})
	body := []byte("--x\r\nContent-Type: text/plain\r\n\r\nfirst\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--x--\r\n")
	got := extractMIMEWithBudget(`multipart/mixed; boundary="x"`, "", "", body, 0, budget)
	if !got.ExtractionIncomplete || !got.HTMLCPULimitExceeded || !budget.cpuLimitExceeded {
		t.Fatalf("CPU-limited multipart extraction = %+v budget=%+v", got, budget)
	}
}

func TestMultipartStrippedTextIsJoinedOnceWithoutEmptySeparators(t *testing.T) {
	body := []byte("--x\r\nContent-Type: text/plain\r\n\r\nfirst\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\n\r\n" +
		"--x\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--x--\r\n")
	got := extractMIME(`multipart/mixed; boundary="x"`, "", "", body, 0)
	if got.StrippedText != "first\n\nsecond" {
		t.Fatalf("stripped text=%q, want %q", got.StrippedText, "first\\n\\nsecond")
	}
}

func TestMultipartPreservesCPUFallbackEvidence(t *testing.T) {
	source := `<p>RECOVERED EVIDENCE <a href="https://example.test/proof">link</a><img src="cid:logo"></p>`
	for _, outer := range []string{"", "multipart/alternative", "multipart/mixed", "multipart/related", "nested"} {
		for _, stopOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stop=%v", outer, stopOutput), func(t *testing.T) {
				ctype := "text/html"
				body := source
				primaryChecks := 1
				if outer != "" {
					ctype = outer + `; boundary="x"`
					body = "--x\r\nContent-Type: text/html\r\n\r\n" + body + "\r\n--x--\r\n"
					primaryChecks = 2
				}
				if outer == "nested" {
					ctype = `multipart/mixed; boundary="y"`
					body = "--y\r\nContent-Type: multipart/related; boundary=\"x\"\r\n\r\n" + body + "\r\n--y--\r\n"
					primaryChecks = 3
				}
				calls := 0
				budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckPrimary: func() {
					calls++
					if calls >= primaryChecks {
						termination.Fail(termination.Failure{Code: termination.CPUExceeded})
					}

					return
				}, CheckFallback: func() {
					if stopOutput {
						termination.Fail(termination.Failure{Code: termination.CPUExceeded})
					}

					return
				}})
				got := extractMIMEWithBudget(ctype, "", "", []byte(body), 0, budget)
				if !got.HTMLCPULimitExceeded {
					t.Fatal("missing CPU status")
				}
				if stopOutput {
					if strings.Contains(got.Text, "RECOVERED EVIDENCE") {
						t.Fatal("output continued after stop")
					}
					return
				}
				if !strings.Contains(got.Text, "RECOVERED EVIDENCE") || !got.HTMLFallbackUsed || len(got.Links) != 1 || len(got.ImageRefs) != 1 {
					t.Fatalf("lost fallback evidence: %+v", got)
				}
			})
		}
	}
}

func TestCompleteAlternativeAndFallbackAreNotMissingEvidence(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", `multipart/alternative; boundary="x"`)
	m.AddBody([]byte("--x\r\nContent-Type: text/plain\r\n\r\nplain\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>HTML</p>\r\n--x--\r\n"))
	a := m.BuildAnalysis(AnalysisContext{}, 10000, VisionOptions{})
	if a.BodyExtractionIncomplete || !strings.Contains(a.Prompt, "HTML") {
		t.Fatalf("analysis=%+v", a)
	}
	content := extractBoundedHTMLFallback("<p>complete evidence</p>", true, testFallbackResources(nil))
	if content.incomplete() || !content.HTMLFallbackUsed {
		t.Fatalf("fallback=%+v", content)
	}
}

func BenchmarkMultipartRepresentations(b *testing.B) {
	for _, depth := range []int{0, 2} {
		body := "--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("a", 1<<20) + "\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("b", 1<<20) + "\r\n--x--\r\n"
		ctype := `multipart/mixed; boundary="x"`
		for n := 0; n < depth; n++ {
			boundary := fmt.Sprintf("wrapper%d", n)
			body = "--" + boundary + "\r\nContent-Type: " + ctype + "\r\n\r\n" + body + "\r\n--" + boundary + "--\r\n"
			ctype = "multipart/mixed; boundary=" + boundary
		}
		data := []byte(body)
		b.Run(fmt.Sprintf("depth%d", depth), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				extractMIME(ctype, "", "", data, 0)
			}
		})
	}
}

func BenchmarkOpaqueAttachment(b *testing.B) {
	raw := bytes.Repeat([]byte("a"), 6<<20)
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))
	for _, tc := range []struct {
		name, encoding string
		data           []byte
	}{{"identity", "binary", raw}, {"base64", "base64", encoded}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				extractMIME("application/octet-stream", tc.encoding, "", tc.data, 0)
			}
		})
	}
}

func TestMultipartPlainTextReusesRepresentationsWithinBudget(t *testing.T) {
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 64 << 20})
	budget.setDecodedTextByteLimit(10 << 20)
	body := []byte("--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("a", 2<<20) + "\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("b", 2<<20) + "\r\n--x--\r\n")
	got := extractMIMEWithBudget(`multipart/mixed; boundary="x"`, "", "", body, 0, budget)
	if got.incomplete() || len(got.Text) != 4<<20+2 || got.VisibleText != got.Text || got.StrippedText != got.Text {
		t.Fatalf("text=%d visible=%d stripped=%d incomplete=%v", len(got.Text), len(got.VisibleText), len(got.StrippedText), got.incomplete())
	}
	// MIME body buffers are also charged. The three final representations
	// must still share the single admitted joined output.
	if !sameStringStorage(got.Text, got.VisibleText) || !sameStringStorage(got.Text, got.StrippedText) {
		t.Fatal("normalized representations duplicated storage")
	}
	if budget.remainingMemory() <= 0 || budget.primaryMemory.Exhausted() {
		t.Fatal("unexpected exhaustion")
	}
}

func TestOpaqueTransferValidationMatchesRecovery(t *testing.T) {
	for _, encoding := range []string{"base64", "quoted-printable", "binary", "7bit", "8bit", "", "unknown"} {
		for _, data := range []string{"", "aGVsbG8=", "aGVsbG8", "aGVsbG8=!!", "!!", "hello=20world", "hello=XY", strings.Repeat("YWFh", 20000)} {
			_, want := decodeTransferRecovering(encoding, []byte(data))
			got := validateOpaqueTransfer(encoding, []byte(data), nil)
			if got != want {
				t.Errorf("encoding=%q length=%d got=%v want=%v", encoding, len(data), got, want)
			}
		}
	}
	calls := 0
	got := extractMIMEWithBudget("application/octet-stream; name=test.bin", "base64", "", []byte(strings.Repeat("YWFh", 20000)), 0, newExtractionBudgetWithControl(HTMLProcessingControl{BeginFallback: func() bool { return false }, CheckPrimary: func() {
		calls++
		if calls >= 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}}))
	if !got.ExtractionIncomplete || !got.HTMLCPULimitExceeded {
		t.Fatalf("interrupted validation=%+v", got)
	}
}

func TestEmptyPartFailureSurvivesMIMEAssembly(t *testing.T) {
	for _, kind := range []string{"mixed", "related", "alternative"} {
		budget := newExtractionBudget()
		budget.setDecodedTextByteLimit(0)
		got := extractMIMEWithBudget("multipart/"+kind+"; boundary=x", "", "", []byte("--x\r\nContent-Type: text/plain\r\n\r\nlost text\r\n--x--\r\n"), 0, budget)
		if !got.incomplete() {
			t.Fatalf("%s lost empty-part failure: %+v", kind, got)
		}
	}
}

func TestUnselectedAlternativeFailureRemainsIncomplete(t *testing.T) {
	budget := newExtractionBudget()
	budget.setDecodedTextByteLimit(0)
	got := extractMIMEWithBudget("multipart/alternative; boundary=x", "", "", []byte("--x\r\nContent-Type: text/plain\r\n\r\nlost text\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>Selected HTML</p>\r\n--x--\r\n"), 0, budget)
	if !got.incomplete() || !strings.Contains(got.Text, "Selected HTML") {
		t.Fatalf("alternative=%+v", got)
	}
}

func TestMultipartDistinctRepresentationsRemainDistinct(t *testing.T) {
	url := "https://example.test/path?token=" + strings.Repeat("a", 200)
	body := "--x\r\nContent-Type: text/plain\r\n\r\n" + url + "\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>visible</p><div style=\"display:none\">concealed</div>\r\n--x--\r\n"
	got := extractMIME("multipart/mixed; boundary=x", "", "", []byte(body), 0)
	if got.incomplete() || !got.HasConcealedContent || !strings.Contains(got.Text, "concealed") || strings.Contains(got.StrippedText, "concealed") || strings.Contains(got.VisibleText, "concealed") || !strings.Contains(got.VisibleText, url) || strings.Contains(got.Text, url) {
		t.Fatalf("representations=%+v", got)
	}
}

func TestEmptyHTMLFallbackKeepsProvenance(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckPrimary: func() {
		calls++
		if calls >= 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}, CheckFallback: func() { return }})
	got := extractMIMEWithBudget("multipart/mixed; boundary=x", "", "", []byte("--x\r\nContent-Type: text/html\r\n\r\n<style>p{display:none}</style>\r\n--x--\r\n"), 0, budget)
	if !got.HTMLFallbackUsed || !got.HTML || !got.HTMLCPULimitExceeded {
		t.Fatalf("lost empty fallback provenance: %+v", got)
	}
}
