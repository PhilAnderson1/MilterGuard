package message

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
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
	m.AddHeader("From", "=?UTF-8?B?TXVzY2xlIEdyb3d0aA==?= <noreply@musclegrowth.net>")
	m.AddHeader("Subject", "=?UTF-8?B?bmlrb2xhaSBoYXMgc2VudCB5b3UgYSBtZXNzYWdl?=")

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

func TestHeaderPaddingCannotConsumeBodyBudget(t *testing.T) {
	m := New(128)
	for range 300 {
		m.AddHeader("Authentication-Results", strings.Repeat("padding", 200))
		m.AddHeader("X-Ignored-Padding", strings.Repeat("ignored", 1000))
	}
	body := "Your account is suspended. Sign in at https://evil.example/login"
	m.AddBody([]byte(body))
	prompt := m.Prompt(1000)
	if !strings.Contains(prompt, body) {
		t.Fatalf("header padding consumed body allowance: %s", prompt)
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

func TestHTMLRecoversAfterUnclosedHiddenElement(t *testing.T) {
	for _, hidden := range []string{"style", "script", "noscript"} {
		t.Run(hidden, func(t *testing.T) {
			m := New(4096)
			m.AddHeader("Content-Type", "text/html; charset=UTF-8")
			m.AddBody([]byte("Before<" + hidden + ">discard me<p>Visible after malformed hidden element</p>"))
			prompt := m.Prompt(4096)
			if !strings.Contains(prompt, "Before Visible after malformed hidden element") {
				t.Fatalf("visible tail was discarded: %s", prompt)
			}
			if strings.Contains(prompt, "discard me") {
				t.Fatalf("hidden content leaked into prompt: %s", prompt)
			}
		})
	}
}

func TestHTMLExcludesMalformedStyleElementFromMixedEncodingSpam(t *testing.T) {
	m := New(10000)
	m.AddHeader("Content-Type", "text/html")
	m.AddHeader("Content-Transfer-Encoding", "8bit")
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
	if !strings.Contains(prompt, "[Click here](https://example.invalid)") {
		t.Fatalf("malformed HTML link missing: %s", prompt)
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
