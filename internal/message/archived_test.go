package message

import (
	"strings"
	"testing"
)

func TestParseArchivedUsesExistingHTMLProcessing(t *testing.T) {
	raw := []byte("From: =?UTF-8?Q?Example_Sender?= <sender@example.net>\r\n" +
		"Subject: =?UTF-8?Q?Example_=E2=9C=93?=\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n\r\n" +
		"<style>.hidden { color:red }</style><p>Hello <a href=\"https://example.net/path\">account</a></p>" +
		"<img src=\"https://images.example.net/logo.png\" alt=\"Example logo\">")
	msg, err := ParseArchived(raw, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if msg.DecodedHeader("Subject") != "Example ✓" {
		t.Fatalf("decoded subject = %q", msg.DecodedHeader("Subject"))
	}
	body := msg.ProcessedBody(4096)
	for _, want := range []string{"[account](https://example.net/path)", "![Example logo](https://images.example.net/logo.png)"} {
		if !strings.Contains(body, want) {
			t.Errorf("processed body missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, ".hidden") || strings.Contains(body, "<style>") {
		t.Fatalf("processed body retained HTML/CSS: %s", body)
	}
}

func TestParseArchivedRejectsMalformedOuterMessageAndBoundsBody(t *testing.T) {
	if _, err := ParseArchived([]byte("Bad Header\r\n\r\nbody"), 1024); err == nil {
		t.Fatal("malformed RFC 5322 message was accepted")
	}
	msg, err := ParseArchived([]byte("Content-Type: text/plain\r\n\r\nabcdefghij"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if body := msg.ProcessedBody(4); !strings.Contains(body, "body truncated") {
		t.Fatalf("bounded processed body = %q", body)
	}
}
