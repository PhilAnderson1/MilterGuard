package message

import (
	"encoding/base64"
	"strings"
	"testing"
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
	if !strings.Contains(prompt, "Multipart content could not be fully parsed") || !strings.Contains(prompt, "First part") {
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
	if !strings.Contains(prompt, "Multipart content could not be fully parsed") {
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
	if beyondLimit.Text != "[MIME nesting limit reached]" {
		t.Fatalf("content beyond MIME nesting limit = %q, want limit marker", beyondLimit.Text)
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
	largeText := strings.Repeat("a", (2<<20)+1024) + tail

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
