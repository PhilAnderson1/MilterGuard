package admincmd

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func TestRejectionFormattingDescribesEmptySubjectAndReason(t *testing.T) {
	entry := stores.Rejection{
		ID: 1, Sender: "sender@example.net", Recipients: []string{"owner@example.com"},
		RejectedAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
	}
	for name, formatted := range map[string]string{
		"history": formatRejectionHistory([]stores.Rejection{entry}, false),
		"detail":  formatRejectionDetail(entry, "body"),
	} {
		if !strings.Contains(formatted, "Subject: (no subject)\n") || !strings.Contains(formatted, "Unavailable") {
			t.Errorf("%s formatting did not describe empty values: %q", name, formatted)
		}
		if strings.Contains(formatted, "predates") {
			t.Errorf("%s formatting invented legacy record provenance: %q", name, formatted)
		}
	}
}

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
