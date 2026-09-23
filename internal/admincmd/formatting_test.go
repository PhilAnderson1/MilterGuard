package admincmd

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAppendBoundedResponseAppendsTextThatFits(t *testing.T) {
	var body strings.Builder
	if complete := AppendBoundedResponse(&body, "first response"); !complete {
		t.Fatal("short response was reported as truncated")
	}
	if got := body.String(); got != "first response" {
		t.Fatalf("response = %q, want unchanged text", got)
	}
}

func TestAppendBoundedResponseCapsOversizedText(t *testing.T) {
	var body strings.Builder
	if complete := AppendBoundedResponse(&body, strings.Repeat("x", MaxResponseBytes+100)); complete {
		t.Fatal("oversized response was reported as complete")
	}
	got := body.String()
	if len(got) != MaxResponseBytes {
		t.Fatalf("response length = %d, want %d", len(got), MaxResponseBytes)
	}
	if !strings.HasSuffix(got, responseTruncatedNotice) {
		t.Fatal("oversized response lacks truncation notice")
	}
	if !utf8.ValidString(got) {
		t.Fatal("oversized response is not valid UTF-8")
	}
}

func TestAppendBoundedResponseDoesNotSplitMultibyteText(t *testing.T) {
	var body strings.Builder
	contentLimit := MaxResponseBytes - len(responseTruncatedNotice)
	body.WriteString(strings.Repeat("x", contentLimit-1))
	if complete := AppendBoundedResponse(&body, "€"+strings.Repeat("y", len(responseTruncatedNotice))); complete {
		t.Fatal("multibyte response was reported as complete")
	}
	got := body.String()
	if len(got) > MaxResponseBytes {
		t.Fatalf("response length = %d, exceeds %d", len(got), MaxResponseBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("response ends partway through a UTF-8 character")
	}
	if !strings.HasSuffix(got, responseTruncatedNotice) {
		t.Fatal("response lacks truncation notice")
	}
}

func TestAppendBoundedResponseSafelyTrimsExistingContent(t *testing.T) {
	var body strings.Builder
	contentLimit := MaxResponseBytes - len(responseTruncatedNotice)
	body.WriteString(strings.Repeat("x", contentLimit-1))
	body.WriteString("€")
	if complete := AppendBoundedResponse(&body, strings.Repeat("y", len(responseTruncatedNotice))); complete {
		t.Fatal("overfilled response was reported as complete")
	}
	got := body.String()
	if len(got) > MaxResponseBytes {
		t.Fatalf("response length = %d, exceeds %d", len(got), MaxResponseBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("trimming existing content produced invalid UTF-8")
	}
	if !strings.HasSuffix(got, responseTruncatedNotice) {
		t.Fatal("trimmed response lacks truncation notice")
	}
}
