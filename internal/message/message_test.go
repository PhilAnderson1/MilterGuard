package message

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

func retainedBytes(m *Message) int64 { return m.archiveHeaderBytes + m.bodySize }

func setHeaderAuthentication(t *testing.T, m *Message, trusted []string) {
	t.Helper()
	visibleDomain := ""
	if m.FromHeaderCount() == 1 {
		visibleDomain = visibleFromDomain(m.Header("From"))
	}
	evidence, err := (mailauth.HeaderVerifier{}).Verify(t.Context(), mailauth.Transaction{
		AuthenticationResults: m.Headers["authentication-results"],
		ReceivedSPF:           m.Headers["received-spf"], TrustedAuthservIDs: trusted,
		VisibleFromDomain: visibleDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Authentication = evidence
}

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
			decoded, _ := decodeTransfer(test.encoding, []byte(test.input))
			if got := string(decoded); got != test.want {
				t.Fatalf("decodeTransfer(%q, %q) = %q, want %q", test.encoding, test.input, got, test.want)
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

func TestPromptDecodesHeaderWordsAndRetainsMailbox(t *testing.T) {
	m := New(1000)
	rawFrom := "=?UTF-8?B?TXVzY2xlIEdyb3d0aA==?= <noreply@musclegrowth.net>"
	rawSubject := "=?UTF-8?B?bmlrb2xhaSBoYXMgc2VudCB5b3UgYSBtZXNzYWdl?="
	m.AddHeader("From", rawFrom)
	m.AddHeader("Subject", rawSubject)
	if got := m.Header("From"); got != rawFrom {
		t.Fatalf("raw From = %q, want %q", got, rawFrom)
	}
	if got := m.Header("Subject"); got != rawSubject {
		t.Fatalf("raw Subject = %q, want %q", got, rawSubject)
	}
	if got, want := m.DecodedHeader("From"), "Muscle Growth <noreply@musclegrowth.net>"; got != want {
		t.Fatalf("decoded From = %q, want %q", got, want)
	}
	if got, want := m.DecodedHeader("Subject"), "nikolai has sent you a message"; got != want {
		t.Fatalf("decoded Subject = %q, want %q", got, want)
	}

	prompt := m.Prompt(100)
	for _, want := range []string{
		"From: Muscle Growth <noreply@musclegrowth.net>",
		"Subject: nikolai has sent you a message",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestPromptDecodesISO2022JPHeaderWordsAndRetainsMailbox(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "=?iso-2022-jp?b?GyRCJSslOSU/JV4hPCU1JV0hPCVIGyhC?= <Support@mkabbr.angelgarcia-abogados.com>")
	m.AddHeader("Subject", "=?iso-2022-jp?b?GyRCO1lKJyQkPGpCMyQtJE4kNDNORyckJCQ/JEAkLyRyJCo0aiQkJDckXiQ5GyhC?=")

	prompt := m.Prompt(100)
	for _, want := range []string{
		"From: カスタマーサポート <Support@mkabbr.angelgarcia-abogados.com>",
		"Subject: 支払い手続きのご確認いただくをお願いします",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestPromptPreservesMalformedEncodedHeader(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "=?UTF-8?Q?broken <sender@example.com>")
	if prompt := m.Prompt(100); !strings.Contains(prompt, "From: =?UTF-8?Q?broken <sender@example.com>") {
		t.Fatalf("malformed header evidence was not preserved:\n%s", prompt)
	}
}

func TestPromptOmitsRecipientHeader(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "sender@example.com")
	m.AddHeader("To", "Phil <junkmail@invades.net>")
	m.AddHeader("Subject", "test")
	prompt := m.Prompt(100)
	if strings.Contains(prompt, "To: Phil") || strings.Contains(prompt, "junkmail@invades.net") {
		t.Fatalf("recipient header included in AI input:\n%s", prompt)
	}
	if strings.Contains(prompt, "RECIPIENT INFORMATION:") {
		t.Fatalf("ordinary recipient header produced derived recipient evidence:\n%s", prompt)
	}
}

func TestPromptReportsMultipleFromHeadersWithoutCombiningThem(t *testing.T) {
	m := New(20000)
	m.AddHeader("From", "Alice <alice@example.com>")
	m.AddHeader("From", "Bob <bob@example.net>")
	prompt := m.Prompt(1000)
	for _, wanted := range []string{
		"Multiple From headers found: 2 (sender identity ambiguous)",
		"Visible From domain: ambiguous (multiple From headers)",
		"From: Alice <alice@example.com>\n",
		"From: Bob <bob@example.net>\n",
	} {
		if !strings.Contains(prompt, wanted) {
			t.Fatalf("missing %q from prompt: %s", wanted, prompt)
		}
	}
	if strings.Contains(prompt, "From: Alice <alice@example.com>, Bob <bob@example.net>") {
		t.Fatalf("separate From headers were combined: %s", prompt)
	}
}

func TestFromHeaderCountIncludesFieldsBeyondRetentionBudget(t *testing.T) {
	m := New(20000)
	for range 3 {
		m.AddHeader("From", strings.Repeat("x", maxHeaderValueBytes))
	}
	if got := m.FromHeaderCount(); got != 3 {
		t.Fatalf("From header count = %d, want 3", got)
	}
	if len(m.Headers["from"]) >= 3 {
		t.Fatal("test did not exceed the From retention budget")
	}
	if prompt := m.Prompt(1000); !strings.Contains(prompt, "Multiple From headers found: 3") {
		t.Fatalf("retention concealed sender ambiguity: %s", prompt)
	}
}

func TestPromptReportsMissingRecipientHeaderForInboundMail(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "sender@example.com")
	prompt := m.Prompt(100)
	for _, want := range []string{
		"RECIPIENT INFORMATION:\nVisible recipient addressing: no To header",
		"Possible significance: may indicate BCC delivery, but is not proof that the email is unwanted",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("missing To header evidence omitted %q:\n%s", want, prompt)
		}
	}
}

func TestPromptReportsEmptyRecipientGroupWithoutAddresses(t *testing.T) {
	for _, value := range []string{
		"undisclosed-recipients:;",
		"  Newsletter   subscribers : ;  ",
		`"Private recipients":;`,
	} {
		m := New(1000)
		m.AddHeader("To", value)
		prompt := m.Prompt(100)
		if !strings.Contains(prompt, "Visible recipient addressing: no addresses disclosed using an empty To group") {
			t.Errorf("empty group %q was not reported:\n%s", value, prompt)
		}
		groupIndex := strings.Index(prompt, "Visible recipient group:")
		if groupIndex < 0 {
			t.Errorf("empty group label %q was not reported:\n%s", value, prompt)
		}
		if strings.Contains(prompt, "Possible significance:") {
			t.Errorf("empty group %q produced interpretive significance text:\n%s", value, prompt)
		}
		if strings.Contains(prompt, "\nTo:") {
			t.Errorf("raw To header %q was included:\n%s", value, prompt)
		}
	}
}

func TestPromptDoesNotInferEmptyGroupFromAmbiguousRecipientHeaders(t *testing.T) {
	values := []string{
		"",
		"undisclosed-recipients:; alice@example.com",
		"Alice <alice@example.com>",
		"malformed:value",
	}
	for _, value := range values {
		m := New(1000)
		m.AddHeader("To", value)
		if prompt := m.Prompt(100); strings.Contains(prompt, "RECIPIENT INFORMATION:") {
			t.Errorf("ambiguous recipient header %q produced derived evidence:\n%s", value, prompt)
		}
	}

	m := New(1000)
	m.AddHeader("To", "First group:;")
	m.AddHeader("To", "Second group:;")
	if prompt := m.Prompt(100); strings.Contains(prompt, "RECIPIENT INFORMATION:") {
		t.Fatalf("multiple To fields produced derived recipient evidence:\n%s", prompt)
	}
}

func TestPromptDoesNotReportRecipientStructureForAuthenticatedSubmission(t *testing.T) {
	for _, to := range []string{"", "undisclosed-recipients:;"} {
		m := New(1000)
		m.AuthenticatedSubmission = true
		if to != "" {
			m.AddHeader("To", to)
		}
		if prompt := m.Prompt(100); strings.Contains(prompt, "RECIPIENT INFORMATION:") {
			t.Errorf("authenticated submission with To %q produced recipient evidence:\n%s", to, prompt)
		}
	}
}

func TestConnectionInformationPrecedesHeadersAndReportsDNSPrecisely(t *testing.T) {
	m := New(1000)
	m.Connection = ConnectionInfo{
		RemoteIP:            "92.205.185.174",
		MTAReportedHostname: "174.185.205.92.host.secureserver.net",
		HELOIdentity:        "mx.example.com",
		EnvelopeSender:      "bounce@example.net",
		ReverseDNSStatus:    ReverseDNSAvailable,
		ReverseDNS: []ReverseDNSName{
			{Hostname: "174.185.205.92.host.secureserver.net", Confirmation: ForwardConfirmed},
			{Hostname: "other.example", Confirmation: ForwardUnconfirmed},
			{Hostname: "unresolved.example", Confirmation: ForwardLookupFailed},
		},
	}
	m.AddHeader("Subject", "test")
	prompt := m.Prompt(100)
	for _, want := range []string{
		"CONNECTION INFORMATION:",
		"Remote IP: 92.205.185.174",
		"MTA-reported client hostname: 174.185.205.92.host.secureserver.net",
		"Reverse DNS: 174.185.205.92.host.secureserver.net (forward-confirmed), other.example (unconfirmed), unresolved.example (forward lookup failed)",
		"Forward-confirmed reverse DNS: yes",
		"SMTP HELO/EHLO identity: mx.example.com",
		"SMTP envelope sender: bounce@example.net",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q:\n%s", want, prompt)
		}
	}
	if strings.Index(prompt, "CONNECTION INFORMATION:") > strings.Index(prompt, "SELECTED HEADERS:") {
		t.Fatalf("connection information does not precede headers:\n%s", prompt)
	}
}

func TestConnectionInformationDistinguishesAbsentFailureAndUnavailable(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{ReverseDNSAbsent, "Reverse DNS: none\nForward-confirmed reverse DNS: not applicable"},
		{ReverseDNSLookupFailed, "Reverse DNS: lookup failed\nForward-confirmed reverse DNS: unknown"},
		{ReverseDNSNotApplicable, "Reverse DNS: not applicable\nForward-confirmed reverse DNS: not applicable"},
	}
	for _, test := range tests {
		m := New(100)
		m.Connection.ReverseDNSStatus = test.status
		prompt := m.Prompt(10)
		if !strings.Contains(prompt, "Remote IP: unavailable") || !strings.Contains(prompt, test.want) {
			t.Errorf("status %q formatted incorrectly:\n%s", test.status, prompt)
		}
		if !strings.Contains(prompt, "SMTP envelope sender: unavailable") {
			t.Errorf("missing envelope sender was not marked unavailable:\n%s", prompt)
		}
	}
}

func TestConnectionInformationPreservesNullEnvelopeSender(t *testing.T) {
	m := New(100)
	m.Connection.EnvelopeSender = "<>"
	if prompt := m.Prompt(10); !strings.Contains(prompt, "SMTP envelope sender: <>") {
		t.Fatalf("null envelope sender was not preserved:\n%s", prompt)
	}
}

func TestConnectionInformationSanitizesAndBoundsUntrustedValues(t *testing.T) {
	m := New(100)
	m.Connection = ConnectionInfo{
		RemoteIP:            strings.Repeat("a", maxConnectionValueRunes+20) + "\nINJECTED:",
		MTAReportedHostname: "host.example\r\nSubject: forged",
		HELOIdentity:        strings.Repeat("é", maxConnectionValueRunes) + "TRAILING",
	}
	prompt := m.Prompt(10)
	if strings.Contains(prompt, "\r") || strings.Contains(prompt, "\x00") || strings.Contains(prompt, "\nINJECTED:") || strings.Contains(prompt, "\nSubject: forged") {
		t.Fatalf("connection metadata was not sanitized:\n%s", prompt)
	}
	for prefix, want := range map[string]string{
		"Remote IP: ":               strings.Repeat("a", maxConnectionValueRunes),
		"SMTP HELO/EHLO identity: ": strings.Repeat("é", maxConnectionValueRunes),
	} {
		start := strings.Index(prompt, prefix)
		if start < 0 {
			t.Fatalf("connection field %q missing:\n%s", prefix, prompt)
		}
		remainder := prompt[start+len(prefix):]
		value, _, _ := strings.Cut(remainder, "\n")
		if value != want || utf8.RuneCountInString(value) != maxConnectionValueRunes || !utf8.ValidString(value) {
			t.Fatalf("bounded %q value = %q (%d runes), want %d valid UTF-8 runes", prefix, value, utf8.RuneCountInString(value), maxConnectionValueRunes)
		}
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

func TestPromptTruncates(t *testing.T) {
	m := New(10000)
	m.AddBody([]byte("abcdef"))
	p := m.Prompt(3)
	if !strings.Contains(p, "ab\n[... body omitted ...]\nf\n[body truncated; beginning and end retained]") {
		t.Fatalf("not truncated: %s", p)
	}
}

func TestSampleBodyPreservesUTF8RuneBoundaries(t *testing.T) {
	body := "零一二三四五六七八九"
	got := sampleBody(body, 8)
	want := "零一二三\n[... body section omitted ...]\n四五\n[... body section omitted ...]\n八九\n[body truncated; beginning, middle, and end retained]"
	if got != want {
		t.Fatalf("sampleBody() = %q, want %q", got, want)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("sampleBody() produced invalid UTF-8: %q", got)
	}
}

func TestHeadersAndBodyShareMessageBudgetWithoutSuppressingBody(t *testing.T) {
	m := New(128)
	for range 300 {
		m.AddHeader("Authentication-Results", strings.Repeat("padding", 200))
		m.AddHeader("X-Ignored-Padding", strings.Repeat("ignored", 1000))
	}
	body := "Your account is suspended. Sign in at https://evil.example/login"
	m.AddBody([]byte(body))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, body) {
		t.Fatalf("header padding suppressed the body: %s", prompt)
	}
	if got := retainedBytes(m); got > m.maxBytes {
		t.Fatalf("retained bytes = %d, want at most %d", got, m.maxBytes)
	}
}

func TestBodyIsTruncatedToRemainingCombinedMessageBudget(t *testing.T) {
	m := New(64)
	m.AddHeader("Subject", "test")
	headerBytes := m.archiveHeaderBytes
	m.AddBody([]byte(strings.Repeat("x", 64)))
	if got, want := int64(m.body.Len()), m.maxBytes-headerBytes; got != want {
		t.Fatalf("retained body bytes = %d, want %d", got, want)
	}
	if !m.BodyTruncated || !m.Truncated {
		t.Fatal("message exceeding the combined header and body budget was not marked truncated")
	}
	if got := retainedBytes(m); got != m.maxBytes {
		t.Fatalf("retained bytes = %d, want %d", got, m.maxBytes)
	}
	if prompt := m.Prompt(1000); !strings.Contains(prompt, "Message body exceeded the retained-byte limit") {
		t.Fatalf("body truncation was not reported to AI: %s", prompt)
	}
}

func TestPromptIncludesOnlyTrustedAuthenticationResults(t *testing.T) {
	m := New(1000)
	m.AddHeader("Authentication-Results", "nl.invades.net; dmarc=pass header.from=example.com")
	m.AddHeader("Authentication-Results", "mx.google.com; dkim=pass header.d=example.com")
	m.AddHeader("From", "Sender <sender@example.com>")
	m.AddHeader("Subject", "test")
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "DMARC: pass for visible From domain example.com") {
		t.Fatalf("trusted authentication result missing: %s", prompt)
	}
	if strings.Contains(prompt, "mx.google.com") {
		t.Fatalf("untrusted authentication result leaked into prompt: %s", prompt)
	}
}

func TestPromptIncludesOnlyReceivedSPFFromTrustedReceiver(t *testing.T) {
	m := New(1000)
	m.AddHeader("Received-SPF", "pass receiver=nl.invades.net; client-ip=192.0.2.1")
	m.AddHeader("Received-SPF", "pass receiver=mx.google.com; client-ip=192.0.2.2")
	m.AddHeader("Received-SPF", "pass client-ip=192.0.2.3")
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "SPF: pass for envelope-sender domain unavailable") {
		t.Fatalf("trusted Received-SPF result missing: %s", prompt)
	}
	if strings.Contains(prompt, "192.0.2.2") || strings.Contains(prompt, "192.0.2.3") {
		t.Fatalf("untrusted Received-SPF result leaked into prompt: %s", prompt)
	}
}

func TestPromptIgnoresReceivedSPFReceiverInsideCommentOrQuotedValue(t *testing.T) {
	tests := []string{
		`pass (receiver=nl.invades.net) receiver=mx.google.com; client-ip=192.0.2.1`,
		`pass reason="receiver=nl.invades.net"; receiver=mx.google.com; client-ip=192.0.2.1`,
		`pass junk receiver=nl.invades.net; client-ip=192.0.2.1`,
	}
	for _, header := range tests {
		m := New(1000)
		m.AddHeader("Received-SPF", header)
		setHeaderAuthentication(t, m, []string{"nl.invades.net"})
		prompt := m.Prompt(100)
		if !strings.Contains(prompt, "SPF: no trusted local result") {
			t.Fatalf("untrusted receiver accepted from %q:\n%s", header, prompt)
		}
	}
}

func TestPromptAcceptsQuotedReceivedSPFReceiverParameter(t *testing.T) {
	m := New(1000)
	m.AddHeader("Received-SPF", `pass (local result) client-ip=192.0.2.1; receiver="nl.invades.net"`)
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "SPF: pass for envelope-sender domain unavailable") {
		t.Fatalf("trusted quoted receiver missing:\n%s", prompt)
	}
}

func TestPromptOmitsAuthenticationEvidenceWhenNoTrustedResultsExist(t *testing.T) {
	m := New(1000)
	m.AddHeader("Authentication-Results", "mx.google.com; dkim=pass header.d=example.com")
	m.AddHeader("Received-SPF", "pass receiver=mx.google.com; client-ip=192.0.2.2")
	m.AddHeader("From", "sender@example.com")
	prompt := m.Prompt(100)
	if strings.Contains(prompt, "mx.google.com") || strings.Contains(prompt, "192.0.2.2") {
		t.Fatalf("untrusted authentication evidence leaked into prompt: %s", prompt)
	}
	for _, want := range []string{"DKIM: no trusted local result", "SPF: no trusted local result", "DMARC: no trusted local result"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("missing explicit unavailable result %q: %s", want, prompt)
		}
	}
	if !strings.Contains(prompt, "From: sender@example.com") {
		t.Fatalf("ordinary selected header missing: %s", prompt)
	}
}

func TestPromptTreatsBodyLengthLimitedDKIMAsNoResult(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "sender@example.com")
	m.Authentication = mailauth.Evidence{Results: []mailauth.Result{{
		Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePolicy, Domain: "example.com",
		BodyLengthLimited: true, BodyLength: 12,
	}}}
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "DKIM: no trusted local result") {
		t.Fatalf("body-length-limited DKIM was not treated as unavailable:\n%s", prompt)
	}
	if strings.Contains(prompt, "DKIM: policy") {
		t.Fatalf("body-length-limited DKIM policy result leaked into prompt:\n%s", prompt)
	}
}

func TestPromptOmitsBodyLengthLimitedDKIMAlongsideUsableResult(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "sender@example.com")
	m.Authentication = mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePolicy, Domain: "limited.example.com", BodyLengthLimited: true, BodyLength: 12},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "example.com"},
	}, "example.com")
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "DKIM: pass for signing domain example.com") {
		t.Fatalf("usable DKIM result missing from prompt:\n%s", prompt)
	}
	if strings.Contains(prompt, "limited.example.com") || strings.Contains(prompt, "DKIM: no trusted local result") {
		t.Fatalf("body-length-limited DKIM affected usable result rendering:\n%s", prompt)
	}
}

func TestPromptOmitsAlignmentLanguageFromNonPassResults(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "sender@example.com")
	m.Authentication = mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomeFail, Domain: "example.com"},
		{Method: mailauth.MethodSPF, Outcome: mailauth.OutcomeSoftfail, Domain: "example.com"},
		{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomeFail, Domain: "example.com"},
	}, "example.com")
	prompt := m.Prompt(100)
	for _, want := range []string{
		"DKIM: fail for signing domain example.com",
		"SPF: softfail for envelope-sender domain example.com",
		"DMARC: fail for visible From domain example.com",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("non-pass authentication result missing %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "aligned with visible From domain") || strings.Contains(prompt, "matches supplied visible From domain") {
		t.Fatalf("non-pass authentication result included misleading domain-match language:\n%s", prompt)
	}
}

func TestPromptDescribesAuthenticatedSubmissionWithoutInboundAuthenticationResults(t *testing.T) {
	m := New(1000)
	m.AuthenticatedSubmission = true
	m.AddHeader("From", "Philip Anderson <phil.anderson@invades.net>")
	m.AddHeader("Subject", "Meeting tomorrow")
	m.AddHeader("Authentication-Results", "nl.invades.net; dkim=pass header.d=invades.net")
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})
	prompt := m.Prompt(100)
	for _, want := range []string{
		"AUTHENTICATION INFORMATION:",
		"Authenticated SMTP submission: yes",
		"Subject: Meeting tomorrow",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("authenticated submission prompt missing %q:\n%s", want, prompt)
		}
	}
	for _, unwanted := range []string{
		"CONNECTION INFORMATION:",
		"Remote IP:",
		"Reverse DNS:",
		"SMTP HELO/EHLO identity:",
		"SMTP envelope sender:",
		"Visible From domain:",
		"DKIM:",
		"SPF:",
		"DMARC:",
		"From: Philip Anderson",
	} {
		if strings.Contains(prompt, unwanted) {
			t.Fatalf("authenticated submission prompt contains inbound evidence %q:\n%s", unwanted, prompt)
		}
	}
}

func TestPromptStartsWithCapturedAnalysisTime(t *testing.T) {
	m := New(1000)
	m.analysisTime = time.Date(2026, time.September, 16, 14, 32, 5, 0, time.FixedZone("test", 2*60*60))
	m.AddHeader("Subject", "test")

	const want = "ANALYSIS TIME:\nServer time: 2026-09-16 12:32:05 UTC\n\n"
	if prompt := m.Prompt(100); !strings.HasPrefix(prompt, want) {
		t.Fatalf("prompt does not start with captured analysis time:\n%s", prompt)
	}
}

func TestPromptNormalizesConflictingBrandAuthenticationEvidence(t *testing.T) {
	m := New(1000)
	m.AddHeader("From", "Aliexpress <Aliexpress@gernandz.click>")
	m.AddHeader("Authentication-Results", "nl.invades.net; dmarc=pass header.from=gernandz.click")
	m.AddHeader("Authentication-Results", "nl.invades.net; \tdkim=pass header.d=gernandz.click; \tdkim=fail reason=\"signature verification failed\" header.d=mail.aliexpress.com")
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})
	prompt := m.Prompt(100)
	for _, want := range []string{
		"Visible From domain: gernandz.click",
		"DKIM: pass for signing domain gernandz.click (aligned with visible From domain: yes)",
		"DKIM: fail for signing domain mail.aliexpress.com",
		"SPF: no trusted local result",
		"DMARC: pass for visible From domain gernandz.click",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("normalized authentication summary missing %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "Authentication-Results:") {
		t.Fatalf("raw authentication header leaked into prompt: %s", prompt)
	}
	if strings.Contains(prompt, "DKIM: fail for signing domain mail.aliexpress.com (aligned") {
		t.Fatalf("failed DKIM result included misleading alignment language: %s", prompt)
	}
}

func TestAuthenticationResultsSemicolonInsideQuotedReasonDoesNotSplitClause(t *testing.T) {
	m := New(2000)
	m.AddHeader("From", "Sender <sender@example.com>")
	m.AddHeader("Authentication-Results", `nl.invades.net; dkim=pass reason="signature; verified" header.d=example.com; spf=pass reason="accepted\"; still valid" smtp.mailfrom=sender@example.com; dmarc=pass header.from=example.com`)
	setHeaderAuthentication(t, m, []string{"nl.invades.net"})

	prompt := m.Prompt(100)
	for _, want := range []string{
		"DKIM: pass for signing domain example.com (aligned with visible From domain: yes)",
		"SPF: pass for envelope-sender domain example.com (aligned with visible From domain: yes)",
		"DMARC: pass for visible From domain example.com",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("quote-aware authentication result missing %q:\n%s", want, prompt)
		}
	}
}

func TestLongBodySamplesBeginningMiddleAndEnd(t *testing.T) {
	m := New(10000)
	body := "BEGIN-EVIDENCE " + strings.Repeat("a", 400) + " MIDDLE-EVIDENCE " + strings.Repeat("b", 400) + " END-EVIDENCE"
	m.AddBody([]byte(body))
	prompt := m.Prompt(120)
	for _, evidence := range []string{"BEGIN-EVIDENCE", "MIDDLE-EVIDENCE", "END-EVIDENCE"} {
		if !strings.Contains(prompt, evidence) {
			t.Errorf("sampled prompt omitted %s: %s", evidence, prompt)
		}
	}
}

func TestPromptIncludesDomainRegistrationEvidence(t *testing.T) {
	m := New(1000)
	m.DomainRegistration = DomainRegistrationInfo{
		Available: true, Domain: "example.com", RegisteredAt: time.Now().UTC().Add(-72 * time.Hour),
	}
	prompt := m.Prompt(1000)
	for _, wanted := range []string{
		"AUTHENTICATION INFORMATION:",
		"Authenticated visible From domain registration date:",
		"(3 days old)",
	} {
		if !strings.Contains(prompt, wanted) {
			t.Fatalf("domain registration evidence missing %q: %s", wanted, prompt)
		}
	}
	if strings.Contains(prompt, "DOMAIN REGISTRATION INFORMATION:") {
		t.Fatalf("domain registration evidence was written as a separate section: %s", prompt)
	}
}

func TestFormatDomainAgeUsesLargestWholeUnit(t *testing.T) {
	tests := []struct {
		name string
		age  time.Duration
		want string
	}{
		{name: "years", age: 3*365*24*time.Hour + 364*24*time.Hour, want: "3 years"},
		{name: "one year", age: 365 * 24 * time.Hour, want: "1 year"},
		{name: "months", age: 8*30*24*time.Hour + 29*24*time.Hour, want: "8 months"},
		{name: "one month", age: 30 * 24 * time.Hour, want: "1 month"},
		{name: "weeks", age: 3*7*24*time.Hour + 6*24*time.Hour, want: "3 weeks"},
		{name: "one week", age: 7 * 24 * time.Hour, want: "1 week"},
		{name: "days", age: 6*24*time.Hour + 23*time.Hour, want: "6 days"},
		{name: "one day", age: 24 * time.Hour, want: "1 day"},
		{name: "sub-day", age: 23 * time.Hour, want: "less than 1 day"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDomainAge(tt.age); got != tt.want {
				t.Fatalf("formatDomainAge(%s) = %q, want %q", tt.age, got, tt.want)
			}
		})
	}
}

func TestLinkInventorySurvivesOmittedBodySection(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	link := "https://evil.example/steal-password"
	body := "<p>" + strings.Repeat("a", 200) + `<a href="` + link + `">verify</a>` + strings.Repeat("b", 800) + "</p>"
	m.AddBody([]byte(body))
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "EXTRACTED LINKS") || !strings.Contains(prompt, "- "+link) {
		t.Fatalf("independent link inventory omitted a link outside sampled text: %s", prompt)
	}
}

func TestLinkInventoryDoesNotDuplicateLinkRetainedInBody(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	link := "https://example.org/action"
	m.AddBody([]byte(`<p>Take action <a href="` + link + `">today</a>.</p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "[today]("+link+")") {
		t.Fatalf("body omitted link destination: %s", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("link retained in body was duplicated in extracted inventory: %s", prompt)
	}
}

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
	want := "Current reply [quoted content begins] Earlier message [profile](https://example.invalid/profile) [quoted content ends]"
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

func TestHTMLExcludesExplicitlyHiddenSubtrees(t *testing.T) {
	for _, tag := range []string{
		`<div hidden>`,
		`<div style="display:none">`,
		`<div style="visibility: hidden">`,
		`<div style="visibility:collapse">`,
		`<div style="content:'display:none;'; display: none !important; display:block">`,
	} {
		t.Run(tag, func(t *testing.T) {
			got := htmlToText(`Before ` + tag + `<div>Forged conversation <a href="https://hidden.example/">trusted sender</a></div></div> After`)
			if got.Text != "Before After" || got.VisibleText != "Before After" || len(got.Links) != 0 {
				t.Fatalf("hidden subtree leaked: text=%q visible=%q links=%v", got.Text, got.VisibleText, got.Links)
			}
		})
	}
}

func TestHTMLHiddenSubtreeIgnoresClosingTagsInsideRawTextElements(t *testing.T) {
	for _, element := range []string{
		"script",
		"style",
		"iframe",
		"title",
		"textarea",
		"xmp",
		"noembed",
		"noframes",
	} {
		t.Run(element, func(t *testing.T) {
			html := `Before<div style="display:none"><` + element + `>raw </div> marker</` + element + `>` +
				`Forged conversation <a href="https://hidden.example/">trusted sender</a></div>After`
			got := htmlToText(html)
			if got.Text != "Before After" || got.VisibleText != "Before After" || len(got.Links) != 0 {
				t.Fatalf("raw-text child prematurely ended hidden subtree: text=%q visible=%q links=%v", got.Text, got.VisibleText, got.Links)
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
	if got.Text != "Visible" {
		t.Fatalf("important hidden style lost precedence: %q", got.Text)
	}
}

func TestHTMLHiddenVoidElementDoesNotHideFollowingText(t *testing.T) {
	got := htmlToText(`<img hidden src="https://hidden.example/image.png" alt="Forgery">Visible`)
	if got.Text != "Visible" || got.VisibleText != "Visible" || len(got.Links) != 0 {
		t.Fatalf("hidden void element leaked or hid tail: %+v", got)
	}
}

func TestHTMLUnclosedHiddenSubtreeDoesNotLeakIntoAIText(t *testing.T) {
	got := htmlToText(`Visible<div style="display:none">Forged correspondence`)
	if got.Text != "Visible" || got.VisibleText != "Visible" {
		t.Fatalf("unclosed hidden subtree leaked: %+v", got)
	}
}

func TestHiddenHTMLDoesNotSuppressFallbackImageAnalysis(t *testing.T) {
	m := multipartRelatedMessage("Fallback", `<p>Short notice</p><div style="display:none">`+strings.Repeat("forged history ", 30)+`</div><img src="cid:scam-image" alt="Notice">`, "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 || strings.Contains(analysis.Prompt, "forged history") {
		t.Fatalf("hidden text affected fallback image selection: images=%d prompt=%s", len(analysis.Images), analysis.Prompt)
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

func TestHTMLDoesNotSurfaceContentInsideUnclosedHiddenElement(t *testing.T) {
	for _, hidden := range []string{"style", "script"} {
		t.Run(hidden, func(t *testing.T) {
			m := New(4096)
			m.AddHeader("Content-Type", "text/html; charset=UTF-8")
			m.AddBody([]byte("Before<" + hidden + ">discard me<p>Visible after malformed hidden element</p>"))
			prompt := m.Prompt(4096)
			if !strings.Contains(prompt, "Before") {
				t.Fatalf("text before hidden element was discarded: %s", prompt)
			}
			if strings.Contains(prompt, "discard me") || strings.Contains(prompt, "Visible after malformed hidden element") {
				t.Fatalf("hidden content leaked into prompt: %s", prompt)
			}
		})
	}
}

func TestHTMLHiddenElementsRequireExactClosingTag(t *testing.T) {
	for _, source := range []string{
		`<style>body{color:red}</styleX><div>AI-only injection</div>`,
		`<script>ignore()</scripts><p>AI-only injection</p>`,
	} {
		got := htmlToText(source)
		if got.Text != "" {
			t.Fatalf("malformed hidden-element close surfaced text: %q", got.Text)
		}
	}
}

func TestHTMLHiddenElementsRequireExactOpeningTag(t *testing.T) {
	for _, source := range []string{
		`<style=invalid>human-visible</style>`,
		`<scriptlet>human-visible</scriptlet>`,
	} {
		got := htmlToText(source)
		if got.Text != "human-visible" {
			t.Fatalf("non-hidden element text = %q, want human-visible", got.Text)
		}
	}
}

func TestHTMLExcludesNonRenderedContainers(t *testing.T) {
	for _, element := range []string{"template", "iframe", "title"} {
		t.Run(element, func(t *testing.T) {
			got := htmlToText("Before<" + element + `><a href="https://hidden.example/">AI-only injection</a></` + element + ">After")
			if got.Text != "Before After" || len(got.Links) != 0 {
				t.Fatalf("non-rendered %s content leaked: text=%q links=%v", element, got.Text, got.Links)
			}
		})
	}
}

func TestHTMLPreservesVisibleRawTextContainers(t *testing.T) {
	for _, element := range []string{"textarea", "xmp", "noembed", "noframes"} {
		t.Run(element, func(t *testing.T) {
			got := htmlToText("Before<" + element + `><b>visible literal text</b></` + element + ">After")
			if got.Text != "Before<b>visible literal text</b>After" {
				t.Fatalf("visible raw %s text = %q", element, got.Text)
			}
		})
	}
}

func TestHTMLPreservesUnclosedVisibleRawTextContainers(t *testing.T) {
	tests := []struct {
		element string
		want    string
	}{
		{element: "textarea", want: `Beforeliteral & <b>tail`},
		{element: "xmp", want: `Beforeliteral &amp; <b>tail`},
		{element: "noembed", want: `Beforeliteral &amp; <b>tail`},
		{element: "noframes", want: `Beforeliteral &amp; <b>tail`},
	}
	for _, test := range tests {
		t.Run(test.element, func(t *testing.T) {
			got := htmlToText(`Before<` + test.element + `>literal &amp; <b>tail`)
			if got.Text != test.want {
				t.Fatalf("unclosed raw %s text = %q, want %q", test.element, got.Text, test.want)
			}
		})
	}
}

func TestHTMLPlaintextTreatsRemainderAsText(t *testing.T) {
	got := htmlToText(`Before<plaintext>literal<a href="https://evil.example/">evil</a></plaintext><p>After</p>`)
	want := `Beforeliteral<a href="https://evil.example/">evil</a></plaintext><p>After</p>`
	if got.Text != want {
		t.Fatalf("plaintext extraction = %q, want %q", got.Text, want)
	}
	if strings.Contains(got.Text, `[evil](https://evil.example/)`) {
		t.Fatalf("markup inside plaintext became a structured link: %q", got.Text)
	}
}

func TestHTMLTagEndHonorsQuotedAttributeValues(t *testing.T) {
	tests := []string{
		`<a title="a>b" href="https://example.test/path">click</a>`,
		`<a title='a>b' href='https://example.test/path'>click</a>`,
	}
	for _, source := range tests {
		got := htmlToText(source)
		if got.Text != `[click](https://example.test/path)` {
			t.Errorf("quoted tag extracted as %q", got.Text)
		}
	}
}

func TestHTMLQuotedAttributeWithMarkupAndValidClosingRemainsAttribute(t *testing.T) {
	got := htmlToText(`<div title="x><script>hidden text</script>">Visible</div>`)
	if got.Text != "Visible" {
		t.Fatalf("valid quoted attribute emitted markup as text: %q", got.Text)
	}
}

func TestHTMLTagEndDoesNotTreatQuotesInsideUnquotedValuesAsDelimiters(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{
			name:   "double quote",
			source: `<a href=http://evil.example/" x>Show me</a>URGENT WIRE TRANSFER https://phish.example/login`,
			want:   `[Show me](http://evil.example/")URGENT WIRE TRANSFER https://phish.example/login`,
		},
		{
			name:   "apostrophe",
			source: `<img alt=It's>Visible after image`,
			want:   "Visible after image",
		},
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

func TestHTMLDoesNotInterpretTagsInsideQuotedAttributes(t *testing.T) {
	got := htmlToText(`<div title="x><script>AI-only injection</script>">Visible</div>`)
	if got.Text != "Visible" {
		t.Fatalf("attribute markup affected visible text: %q", got.Text)
	}
}

func TestHTMLUnterminatedQuotedTagDoesNotBecomeVisibleText(t *testing.T) {
	for _, source := range []string{
		`Before<div title="x>AI-only injection<p>hidden</p>`,
		`Before<div title='x>AI-only injection<p>hidden</p>`,
	} {
		got := htmlToText(source)
		if got.Text != "Before" {
			t.Errorf("unterminated quoted tag extracted as %q", got.Text)
		}
	}
}

func TestHTMLUnterminatedMarkupTailDoesNotBecomeVisibleText(t *testing.T) {
	for _, source := range []string{
		`Before<div title=unfinished fake correspondence`,
		`Before<!DOCTYPE html fake correspondence`,
		`Before<?processing instruction fake correspondence`,
	} {
		if got := htmlToText(source); got.Text != "Before" {
			t.Errorf("unterminated markup tail extracted from %q as %q", source, got.Text)
		}
	}
	if got := htmlToText(`Before<`); got.Text != `Before<` {
		t.Fatalf("ordinary lone tag opener = %q, want %q", got.Text, `Before<`)
	}
}

func TestHTMLInvalidTagStartsRemainVisible(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "space", source: `< div>`, want: `< div>`},
		{name: "tab", source: "<\tdiv>", want: `< div>`},
		{name: "newline", source: "<\ndiv>", want: `< div>`},
		{name: "digit", source: `<1>`, want: `<1>`},
		{name: "invalid then valid", source: `< <script>hidden</script>visible`, want: `< visible`},
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

func TestHTMLHiddenClosingTagHonorsQuotedAttributes(t *testing.T) {
	got := htmlToText(`<style>hidden</style title="a>b"><p>Visible</p>`)
	if got.Text != "Visible" {
		t.Fatalf("hidden closing tag desynchronized extraction: %q", got.Text)
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

func TestHTMLTemplateScannerFindsMatchingOuterClose(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "closing text in attribute", source: `<template><div title="</template>">hidden</div></template><p>Visible</p>`},
		{name: "closing text in comment", source: `<template><!-- </template> --><p>hidden</p></template><p>Visible</p>`},
		{name: "nested template", source: `<template><template>hidden</template>also hidden</template><p>Visible</p>`},
		{name: "closing text in raw element", source: `<template><script>const value = "</template>";</script></template><p>Visible</p>`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := htmlToText(test.source)
			if got.Text != "Visible" || len(got.Links) != 0 {
				t.Fatalf("template extraction = text %q, links %v", got.Text, got.Links)
			}
		})
	}
}

func TestHTMLPlaintextInsideTemplateConsumesRemainder(t *testing.T) {
	got := htmlToText(`Before<template><plaintext></template><a href="https://hidden.example/">AI-only</a></template>After`)
	if got.Text != "Before" || len(got.Links) != 0 {
		t.Fatalf("template plaintext extraction = text %q, links %v", got.Text, got.Links)
	}
}

func TestHTMLPlaintextInsideHiddenElementConsumesRemainder(t *testing.T) {
	got := htmlToText(`Before<div hidden><plaintext></div><a href="https://hidden.example/">AI-only</a>After`)
	if got.Text != "Before" || len(got.Links) != 0 {
		t.Fatalf("hidden plaintext extraction = text %q, links %v", got.Text, got.Links)
	}
}

func TestHTMLTemplateScannerIgnoresOrdinaryLessThan(t *testing.T) {
	got := htmlToText(`<template>1 < 2 and hidden</template><p>Visible</p>`)
	if got.Text != "Visible" || len(got.Links) != 0 {
		t.Fatalf("template less-than extraction = text %q, links %v", got.Text, got.Links)
	}
}

func TestHTMLNestedAnchorImplicitlyClosesPreviousAnchor(t *testing.T) {
	got := htmlToText(`<a href="https://one.example/">one <a href="https://two.example/">two</a> tail</a>`)
	if got.Text != `[one](https://one.example/) [two](https://two.example/) tail` {
		t.Fatalf("nested anchors extracted as %q", got.Text)
	}
	if len(got.Links) != 2 || got.Links[0] != "https://one.example/" || got.Links[1] != "https://two.example/" {
		t.Fatalf("nested anchor links = %v", got.Links)
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

func TestHTMLInvalidFirstBaseDoesNotEnableLaterBase(t *testing.T) {
	for _, source := range []string{
		`<base href="javascript:alert(1)"><base href="https://later.example/"><a href="target">Open</a>`,
		`<base href><base href="https://later.example/"><a href="target">Open</a>`,
	} {
		got := htmlToText(source)
		if got.Text != "Open" || len(got.Links) != 0 {
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

func TestHTMLUnclosedAnchorEmitsUnescapedPlainLabel(t *testing.T) {
	got := htmlToText(`<a href="https://good.example/">plain [label]\`)
	if got.Text != `plain [label]\` {
		t.Fatalf("unclosed anchor text = %q", got.Text)
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

func TestHTMLUnclosedAnchorDoesNotWrapMessageTail(t *testing.T) {
	got := htmlToText(`<a href="https://one.example/">one lots of unrelated message text`)
	if got.Text != `one lots of unrelated message text` {
		t.Fatalf("unclosed anchor extracted as %q", got.Text)
	}
	if len(got.Links) != 1 || got.Links[0] != "https://one.example/" {
		t.Fatalf("unclosed anchor link evidence = %v", got.Links)
	}
}

func TestHTMLEmptyAndUnmatchedAnchors(t *testing.T) {
	got := htmlToText(`before</a><a href="https://example.test/"></a>after`)
	if got.Text != `before[link](https://example.test/)after` {
		t.Fatalf("empty or unmatched anchor extracted as %q", got.Text)
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

func TestHTMLMarkdownURLWithTrailingBackslashRemainsStructured(t *testing.T) {
	got := htmlToText(`<a href='https://example.test/path\'>label</a>`)
	if got.Text != `[label](https://example.test/path%5C)` {
		t.Fatalf("backslash URL extracted as %q", got.Text)
	}
	if len(got.Links) != 1 || got.Links[0] != `https://example.test/path\` {
		t.Fatalf("original link evidence = %v", got.Links)
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

func TestExtractedLinksStripInvisibleFormatting(t *testing.T) {
	const normalized = "https://paypal.example/account"
	obfuscated := "https://pay\u200bpal.example/acc\u2060ount"

	got := htmlToText(`<a href="` + obfuscated + `">Sign in</a>`)
	if got.Text != `[Sign in](`+normalized+`)` {
		t.Fatalf("normalized HTML link text = %q", got.Text)
	}
	if len(got.Links) != 1 || got.Links[0] != normalized {
		t.Fatalf("normalized HTML link evidence = %v", got.Links)
	}

	links := boundedLinks([]string{obfuscated, normalized})
	if len(links) != 1 || links[0] != normalized {
		t.Fatalf("normalized links were not deduplicated: %v", links)
	}
}

func TestPlainTextLinkNormalizationMatchesPromptBody(t *testing.T) {
	m := New(4096)
	m.AddHeader("Content-Type", "text/plain; charset=UTF-8")
	m.AddBody([]byte("Visit https://pay\u200bpal.example/acc\u2060ount"))
	prompt := m.Prompt(4096)
	if strings.ContainsRune(prompt, '\u200b') || strings.ContainsRune(prompt, '\u2060') {
		t.Fatalf("prompt retained invisible URL formatting: %q", prompt)
	}
	if !strings.Contains(prompt, "https://paypal.example/account") {
		t.Fatalf("normalized URL missing from prompt: %q", prompt)
	}
	if strings.Contains(prompt, "EXTRACTED LINKS") {
		t.Fatalf("normalized body URL was emitted redundantly: %q", prompt)
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

func TestHTMLExcludesStyleElementAfterQuotedPrintableDecoding(t *testing.T) {
	for _, encoding := range []string{"quoted-printable", "8bit"} {
		t.Run(encoding, func(t *testing.T) {
			m := New(10000)
			m.AddHeader("Content-Type", "text/html")
			m.AddHeader("Content-Transfer-Encoding", encoding)
			m.AddBody([]byte(`<h2>End of Summer Offers</h2><img src="tracker" style="display:none;><object><title><style=
 type=3D"text/css"> @media screen and (min-width: 480px) { .product { font-size: 18px !important; } } </style><p>Visible offer</p>`))
			prompt := m.Prompt(1000)
			for _, unwanted := range []string{"<style", "@media", ".product", "font-size", "!important"} {
				if strings.Contains(prompt, unwanted) {
					t.Fatalf("malformed style content leaked into prompt: %s", prompt)
				}
			}
			if !strings.Contains(prompt, "End of Summer Offers") {
				t.Fatalf("visible HTML text before malformed markup is missing: %s", prompt)
			}
		})
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
		"value= next line",
		`[link](https://example.test/?q=3D)`,
		`![code=3Dvalue](https://example.test/image.png)`,
	} {
		if !strings.Contains(prompt, wanted) {
			t.Errorf("literal 8bit HTML missing %q: %s", wanted, prompt)
		}
	}
}

func TestPromptStripsInvisibleFormattingAndPreheaderPadding(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<p>v&#x200c;e&#xad;r&#x034f;ify&#x202b; account` + strings.Repeat(` &#x200c; &#xad; &#x034f;`, 20) + `</p>`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "verify account") {
		t.Fatalf("invisible formatting was not removed from meaningful text: %q", prompt)
	}
	for _, unwanted := range []rune{'\u00ad', '\u034f', '\u200c', '\u202b'} {
		if strings.ContainsRune(prompt, unwanted) {
			t.Fatalf("prompt retained invisible formatting U+%04X: %q", unwanted, prompt)
		}
	}
	if strings.Contains(prompt, strings.Repeat(" ", 2)) {
		t.Fatalf("prompt retained repeated preheader padding spaces: %q", prompt)
	}
}

func TestMalformedHTMLStillPreservesLink(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(`<a href="https://example.invalid">Click <b>here`))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, "BODY:\nClick here") || !strings.Contains(prompt, "- https://example.invalid") {
		t.Fatalf("malformed HTML text or independent link evidence missing: %s", prompt)
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

func TestVisionFallbackSelectsReferencedInlineImage(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
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
	analysis := m.BuildAnalysis(1000, VisionOptions{
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

	analysis := m.BuildAnalysis(1000, VisionOptions{
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
	analysis := m.BuildAnalysis(2000, VisionOptions{
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
	analysis := m.BuildAnalysis(2000, VisionOptions{
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

	analysis := m.BuildAnalysis(1000, VisionOptions{
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

	analysis := m.BuildAnalysis(1000, VisionOptions{
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
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 1 {
		t.Fatalf("selected images = %d, want 1; prompt=%s", len(analysis.Images), analysis.Prompt)
	}
}

func TestVisionOffAndRemoteImagesAreNeverSelected(t *testing.T) {
	inline := imageOnlyMessage("cid:scam-image", "<scam-image>")
	if images := inline.BuildAnalysis(1000, VisionOptions{
		Mode: "off", MinTextChars: 200, MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("vision mode off selected an inline image")
	}

	remote := New(10000)
	remote.AddHeader("Content-Type", "text/html")
	remote.AddBody([]byte(`<img src="https://tracker.example/image.png">`))
	if images := remote.BuildAnalysis(1000, VisionOptions{
		Mode: "always", MaxImages: 2, MaxBytes: 1 << 20, MaxPixels: 100,
	}).Images; len(images) != 0 {
		t.Fatal("selected or fetched a remote image")
	}
}

func TestVisionFallbackSkipsImageWhenTextIsMeaningful(t *testing.T) {
	m := imageOnlyMessage("cid:scam-image", "<scam-image>")
	longText := strings.Repeat("This is meaningful body text. ", 20)
	m = multipartRelatedMessage(longText, `<p>`+longText+`</p><img src="cid:scam-image">`, "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
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
	analysis := m.BuildAnalysis(1000, VisionOptions{
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

func TestArchiveBytesRetainsAllHeadersAndBody(t *testing.T) {
	m := New(1024)
	m.AddHeader("X-Unselected", "preserved")
	m.AddHeader("Subject", "test")
	m.AddBody([]byte("message body"))
	got := string(m.ArchiveBytes())
	for _, want := range []string{"X-Unselected: preserved\r\n", "Subject: test\r\n", "\r\nmessage body"} {
		if !strings.Contains(got, want) {
			t.Fatalf("archive missing %q: %q", want, got)
		}
	}
}

func TestArchiveBytesFoldsEmbeddedHeaderLineBreaks(t *testing.T) {
	m := New(4096)
	m.AddHeader("Subject", "original\r\nX-Forged: yes\nContent-Type: text/html\rAnother: value")
	m.AddBody([]byte("message body"))

	archive := m.ArchiveBytes()
	for _, want := range []string{
		"Subject: original\r\n X-Forged: yes\r\n Content-Type: text/html\r\n Another: value\r\n",
		"\r\n\r\nmessage body",
	} {
		if !bytes.Contains(archive, []byte(want)) {
			t.Fatalf("archive missing folded value %q: %q", want, archive)
		}
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("archive is not syntactically valid: %v\n%q", err, archive)
	}
	for _, name := range []string{"X-Forged", "Content-Type", "Another"} {
		if value := parsed.Header.Get(name); value != "" {
			t.Errorf("embedded line created %s header %q", name, value)
		}
	}
	if subject := parsed.Header.Get("Subject"); !strings.Contains(subject, "X-Forged: yes") || !strings.Contains(subject, "Another: value") {
		t.Fatalf("folded subject lost original value: %q", subject)
	}
}

func TestArchiveBytesRejectsInvalidHeaderNames(t *testing.T) {
	for _, name := range []string{"", "Bad:Name", "Bad\r\nX-Forged", "Bad\x00Name", "Bad Name", "Bäd"} {
		t.Run(strconv.Quote(name), func(t *testing.T) {
			m := New(4096)
			m.AddHeader("Subject", "safe")
			m.AddHeader(name, "attacker value")
			m.AddBody([]byte("body"))

			archive := m.ArchiveBytes()
			want := "Subject: safe\r\n" + archiveTruncationHeader + "\r\nbody"
			if string(archive) != want {
				t.Fatalf("archive retained invalid header name:\n got %q\nwant %q", archive, want)
			}
			parsed, err := mail.ReadMessage(bytes.NewReader(archive))
			if err != nil {
				t.Fatalf("archive is not syntactically valid: %v", err)
			}
			if len(parsed.Header) != 2 || parsed.Header.Get("Subject") != "safe" || parsed.Header.Get("X-MilterGuard-Archive-Truncated") != "yes" {
				t.Fatalf("parsed headers = %#v", parsed.Header)
			}
		})
	}
}

func TestHeaderFamiliesCannotSuppressSecurityHeaders(t *testing.T) {
	m := New(1 << 20)
	for range 3 {
		m.AddHeader("To", strings.Repeat("x", maxHeaderValueBytes))
	}
	for _, name := range []string{
		"X-MilterGuard-Classification",
		"X-MilterGuard-Score",
		"X-MilterGuard-Confidence",
		"X-MilterGuard-Action",
		"X-MilterGuard-Internal",
	} {
		m.AddHeader(name, "forged")
		m.AddHeader(strings.ToLower(name), "second")
		if got := m.HeaderOccurrences(name); got != 2 {
			t.Errorf("%s occurrences = %d, want 2", name, got)
		}
		if values := m.Headers[strings.ToLower(name)]; len(values) != 2 {
			t.Errorf("%s retained values = %q, want both occurrences", name, values)
		}
	}
}

func TestTruncatedArchiveReservesCompleteMarkerAndRemainsParseable(t *testing.T) {
	limit := int64(len(archiveTruncationHeader) + 2)
	m := New(limit)
	m.AddHeader("X", "value")
	m.AddHeader("Long", strings.Repeat("x", 100))
	m.AddBody([]byte("body"))

	archive := m.ArchiveBytes()
	if int64(len(archive)) > limit {
		t.Fatalf("archive is %d bytes, limit is %d", len(archive), limit)
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("truncated archive is not syntactically valid: %v\n%q", err, archive)
	}
	if got := parsed.Header.Get("X-MilterGuard-Archive-Truncated"); got != "yes" {
		t.Fatalf("archive truncation marker = %q, want yes", got)
	}
}

func TestTruncatedArchiveOmitsEntireFoldedHeaderField(t *testing.T) {
	// The retained archive headers exactly fill half this message budget. Once
	// space is reserved for the truncation marker, the cutoff lands inside the
	// folded field and the complete field must therefore be omitted.
	m := New(78)
	m.AddHeader("X", "ok")
	m.AddHeader("F", "one\n"+strings.Repeat("x", 21))
	if m.archiveHeaderBytes != m.maxBytes/2 {
		t.Fatalf("test archive headers = %d bytes, want %d", m.archiveHeaderBytes, m.maxBytes/2)
	}
	m.AddHeader("Invalid Header", "force archive truncation")
	m.AddBody([]byte("body"))

	archive := m.ArchiveBytes()
	parsed, err := mail.ReadMessage(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("archive split a folded header field: %v\n%q", err, archive)
	}
	if got := parsed.Header.Get("X"); got != "ok" {
		t.Fatalf("complete preceding header = %q, want ok", got)
	}
	if got := parsed.Header.Get("F"); got != "" {
		t.Fatalf("partially retained folded header = %q, want omitted", got)
	}
	if got := parsed.Header.Get("X-MilterGuard-Archive-Truncated"); got != "yes" {
		t.Fatalf("archive truncation marker = %q, want yes", got)
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body" {
		t.Fatalf("archive body = %q, want body", body)
	}
}

func TestSmallTruncatedArchiveOmitsMarkerRatherThanCuttingHeader(t *testing.T) {
	m := New(8)
	m.AddHeader("Invalid Header", "value")
	m.AddBody([]byte("body"))

	archive := m.ArchiveBytes()
	if len(archive) > 8 {
		t.Fatalf("archive is %d bytes, limit is 8", len(archive))
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("small truncated archive is not syntactically valid: %v\n%q", err, archive)
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body" {
		t.Fatalf("archive body = %q, want body", body)
	}
}

func TestRetainedHeaderTruncationPreservesUTF8(t *testing.T) {
	m := New(1 << 20)
	value := strings.Repeat("a", maxHeaderValueBytes-1) + "€"
	m.AddHeader("Subject", value)

	got := m.Header("Subject")
	if !utf8.ValidString(got) {
		t.Fatalf("truncated header is invalid UTF-8: %q", got)
	}
	if len(got) > maxHeaderValueBytes {
		t.Fatalf("truncated header is %d bytes, limit is %d", len(got), maxHeaderValueBytes)
	}
	if got != strings.Repeat("a", maxHeaderValueBytes-1) {
		t.Fatalf("truncated header ended at the wrong rune boundary: %q", got[len(got)-8:])
	}
	if !m.Truncated {
		t.Fatal("message was not marked truncated")
	}
}

func TestStructuralMIMEHeaderUsesLargerRetentionLimit(t *testing.T) {
	m := New(1 << 20)
	value := `multipart/mixed; note="` + strings.Repeat("x", maxHeaderValueBytes) + `"; boundary="parts"`
	m.AddHeader("Content-Type", value)
	if got := m.FirstHeader("Content-Type"); got != value {
		t.Fatalf("Content-Type was truncated: got %d bytes, want %d", len(got), len(value))
	}
	if m.MIMEHeadersTruncated {
		t.Fatal("ordinary structural MIME header was marked truncated")
	}
}

func TestOversizedStructuralMIMEHeaderIsMarkedUnsafe(t *testing.T) {
	m := New(1 << 20)
	m.AddHeader("Content-Type", strings.Repeat("x", maxMIMEHeaderValueBytes+1))
	if !m.MIMEHeadersTruncated {
		t.Fatal("oversized structural MIME header was not marked truncated")
	}
}

func TestHeaderFamiliesCannotSuppressIdentityMIMEOrAuthentication(t *testing.T) {
	m := New(1 << 20)
	for range 10 {
		m.AddHeader("To", strings.Repeat("x", maxHeaderValueBytes))
	}
	m.AddHeader("From", "Sender <sender@example.com>")
	m.AddHeader("Subject", "Important message")
	m.AddHeader("Content-Type", `multipart/mixed; boundary="parts"`)
	m.AddHeader("Content-Transfer-Encoding", "7bit")
	m.AddHeader("Authentication-Results", "mx.example; dkim=pass header.d=example.com")

	for name, want := range map[string]string{
		"From":                      "Sender <sender@example.com>",
		"Subject":                   "Important message",
		"Content-Type":              `multipart/mixed; boundary="parts"`,
		"Content-Transfer-Encoding": "7bit",
		"Authentication-Results":    "mx.example; dkim=pass header.d=example.com",
	} {
		if got := m.Header(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestHTMLUnicodeBeforeLoneTagOpenerDoesNotPanic(t *testing.T) {
	got := htmlToText("ẞẞ<")
	if got.Text != "ẞẞ<" {
		t.Fatalf("unexpected extracted text: %q", got.Text)
	}
}

func TestHTMLCommentEndingsMatchRenderedContent(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "normal", source: `<!-- benign --><p>visible</p>`, want: "visible"},
		{name: "bang ending", source: `<!-- benign --!><p>visible</p>`, want: "visible"},
		{name: "abrupt empty", source: `<p>Hello</p><!--><p>visible</p><!-- -->`, want: "Hello visible"},
		{name: "abrupt empty dash", source: `<!---><p>visible</p>`, want: "visible"},
		{name: "unterminated", source: `before<!-- <p>hidden</p>`, want: "before"},
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
