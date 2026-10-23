package message

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestMultipartLongPreambleLineDoesNotHideParts(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		body := strings.Repeat("p", 139<<10) + newline +
			"--boundary" + newline +
			"Content-Type: text/html" + newline + newline +
			"<p>retained evidence</p>" + newline +
			"--boundary--" + newline
		got := extractMIME("multipart/mixed; boundary=boundary", "", "", []byte(body), 0)
		if got.incomplete() || !got.HTML || !strings.Contains(got.Text, "retained evidence") {
			t.Fatalf("newline=%q content=%+v", newline, got)
		}
	}
}

func TestMultipartPreambleIgnoresEmbeddedAndPrefixMatches(t *testing.T) {
	body := strings.Repeat("p", 8<<10) + "--boundary\r\n" +
		"--boundary-suffix\r\n" +
		"--boundary\r\nContent-Type: text/plain\r\n\r\nretained evidence\r\n--boundary--\r\n"
	got := extractMIME("multipart/mixed; boundary=boundary", "", "", []byte(body), 0)
	if got.incomplete() || !strings.Contains(got.Text, "retained evidence") {
		t.Fatalf("content=%+v", got)
	}
}

func TestMultipartPreambleScanChecksResources(t *testing.T) {
	checks := 0
	source := []byte(strings.Repeat("p", 4*resourceguard.WorkChunk) + "\r\n--boundary\r\n")
	got := multipartBodyFromFirstBoundary(source, "boundary", func() { checks++ })
	if !strings.HasPrefix(string(got), "--boundary\r\n") {
		t.Fatalf("body starts %q", got[:min(len(got), 32)])
	}
	if checks < 4 {
		t.Fatalf("resource checks=%d, want at least 4", checks)
	}
}
