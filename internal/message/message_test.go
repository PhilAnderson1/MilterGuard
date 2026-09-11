package message

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const onePixelPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="

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

func TestMailboxAddressFallsBackToUnambiguousAngleAddress(t *testing.T) {
	if got, ok := MailboxAddress(`Malformed [display <Sender@Example.com>`); !ok || got != "Sender@Example.com" {
		t.Fatalf("fallback mailbox = %q, %v", got, ok)
	}
	for _, value := range []string{
		`Malformed <first@example.com> <second@example.com>`,
		`Malformed <not-an-address>`,
		`Malformed <Name <sender@example.com>`,
	} {
		if got, ok := MailboxAddress(value); ok {
			t.Errorf("ambiguous or invalid mailbox %q accepted as %q", value, got)
		}
	}
}

func TestConnectionInformationPrecedesHeadersAndReportsDNSPrecisely(t *testing.T) {
	m := New(1000)
	m.Connection = ConnectionInfo{
		RemoteIP:            "92.205.185.174",
		MTAReportedHostname: "174.185.205.92.host.secureserver.net",
		HELOIdentity:        "mx.example.com",
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
	}
}

func TestConnectionInformationSanitizesAndBoundsUntrustedValues(t *testing.T) {
	m := New(100)
	m.Connection = ConnectionInfo{
		RemoteIP:            strings.Repeat("a", maxConnectionValueRunes+20) + "\nINJECTED:",
		MTAReportedHostname: "host.example\r\nSubject: forged",
		HELOIdentity:        "helo.example\x00bad",
	}
	prompt := m.Prompt(10)
	if strings.Contains(prompt, "\r") || strings.Contains(prompt, "\x00") || strings.Contains(prompt, "\nINJECTED:") || strings.Contains(prompt, "\nSubject: forged") {
		t.Fatalf("connection metadata was not sanitized:\n%s", prompt)
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

func TestStripInvisibleFormattingDoesNotAllocateForCleanText(t *testing.T) {
	const clean = "Already clean UTF-8 text ✓"
	if allocations := testing.AllocsPerRun(100, func() {
		if got := stripInvisibleFormatting(clean); got != clean {
			t.Fatalf("stripInvisibleFormatting() = %q, want %q", got, clean)
		}
	}); allocations != 0 {
		t.Fatalf("clean formatting pass allocated %.1f times, want 0", allocations)
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
	if got := m.RetainedBytes(); got > m.MaxBytes {
		t.Fatalf("retained bytes = %d, want at most %d", got, m.MaxBytes)
	}
}

func TestBodyIsTruncatedToRemainingCombinedMessageBudget(t *testing.T) {
	m := New(64)
	m.AddHeader("Subject", "test")
	headerBytes := m.archiveHeaderBytes
	m.AddBody([]byte(strings.Repeat("x", 64)))
	if got, want := int64(m.Body.Len()), m.MaxBytes-headerBytes; got != want {
		t.Fatalf("retained body bytes = %d, want %d", got, want)
	}
	if !m.BodyTruncated || !m.Truncated {
		t.Fatal("message exceeding the combined header and body budget was not marked truncated")
	}
	if got := m.RetainedBytes(); got != m.MaxBytes {
		t.Fatalf("retained bytes = %d, want %d", got, m.MaxBytes)
	}
}

func TestPromptIncludesOnlyTrustedAuthenticationResults(t *testing.T) {
	m := New(1000)
	m.TrustedAuthservIDs = []string{"nl.invades.net"}
	m.AddHeader("Authentication-Results", "nl.invades.net; dmarc=pass header.from=example.com")
	m.AddHeader("Authentication-Results", "mx.google.com; dkim=pass header.d=example.com")
	m.AddHeader("From", "Sender <sender@example.com>")
	m.AddHeader("Subject", "test")
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "DMARC: pass for visible From domain example.com (matches supplied visible From domain: yes)") {
		t.Fatalf("trusted authentication result missing: %s", prompt)
	}
	if strings.Contains(prompt, "mx.google.com") {
		t.Fatalf("untrusted authentication result leaked into prompt: %s", prompt)
	}
}

func TestPromptIncludesOnlyReceivedSPFFromTrustedReceiver(t *testing.T) {
	m := New(1000)
	m.TrustedAuthservIDs = []string{"nl.invades.net"}
	m.AddHeader("Received-SPF", "pass receiver=nl.invades.net; client-ip=192.0.2.1")
	m.AddHeader("Received-SPF", "pass receiver=mx.google.com; client-ip=192.0.2.2")
	m.AddHeader("Received-SPF", "pass client-ip=192.0.2.3")
	prompt := m.Prompt(100)
	if !strings.Contains(prompt, "SPF: pass for envelope-sender domain unavailable") {
		t.Fatalf("trusted Received-SPF result missing: %s", prompt)
	}
	if strings.Contains(prompt, "192.0.2.2") || strings.Contains(prompt, "192.0.2.3") {
		t.Fatalf("untrusted Received-SPF result leaked into prompt: %s", prompt)
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

func TestPromptNormalizesConflictingBrandAuthenticationEvidence(t *testing.T) {
	m := New(1000)
	m.TrustedAuthservIDs = []string{"nl.invades.net"}
	m.AddHeader("From", "Aliexpress <Aliexpress@gernandz.click>")
	m.AddHeader("Authentication-Results", "nl.invades.net; dmarc=pass header.from=gernandz.click")
	m.AddHeader("Authentication-Results", "nl.invades.net; \tdkim=pass header.d=gernandz.click; \tdkim=fail reason=\"signature verification failed\" header.d=mail.aliexpress.com")
	prompt := m.Prompt(100)
	for _, want := range []string{
		"Visible From domain: gernandz.click",
		"DKIM: pass for signing domain gernandz.click (aligned with visible From domain: yes)",
		"DKIM: fail for signing domain mail.aliexpress.com (aligned with visible From domain: no)",
		"SPF: no trusted local result",
		"DMARC: pass for visible From domain gernandz.click (matches supplied visible From domain: yes)",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("normalized authentication summary missing %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "Authentication-Results:") {
		t.Fatalf("raw authentication header leaked into prompt: %s", prompt)
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
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddHeader("Content-Transfer-Encoding", "quoted-printable")
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

func TestVisionFallbackIgnoresUnreferencedImage(t *testing.T) {
	m := imageOnlyMessage("cid:different-image", "<scam-image>")
	analysis := m.BuildAnalysis(1000, VisionOptions{
		Mode: "fallback", MinTextChars: 200, MaxImages: 2,
		MaxBytes: 1 << 20, MaxPixels: 100,
	})
	if len(analysis.Images) != 0 {
		t.Fatalf("selected unreferenced image: %#v", analysis.Images)
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
