package message

import (
	"bytes"
	"io"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func retainedBytes(m *Message) int64 { return m.archiveHeaderBytes + m.bodySize }

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
		if values := m.headers[strings.ToLower(name)]; len(values) != 2 {
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
