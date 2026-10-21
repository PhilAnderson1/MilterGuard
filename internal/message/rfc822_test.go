package message

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestAttachedMessageParserRetainsOnlyStructuralHeaders(t *testing.T) {
	data := []byte("Subject: ignored\r\n" +
		"cOnTeNt-TyPe: text/html;\r\n\tcharset=UTF-8\r\n" +
		"Content-Transfer-Encoding: quoted-printable\r\n" +
		"Content-ID: <first>\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-ID: <second>\r\n\r\n<p>body</p>")
	budget := newExtractionBudget()

	got, ok := parseAttachedMessage(data, budget)
	if !ok {
		t.Fatal("valid attached message was rejected")
	}
	if got.contentType != "text/html; charset=UTF-8" || got.transferEncoding != "quoted-printable" || got.contentID != "<first>" || string(got.body) != "<p>body</p>" {
		t.Fatalf("parsed attached message = %+v", got)
	}
	if used := budget.primaryMemory.Used(); used == 0 || used >= int64(len(data)) {
		t.Fatalf("retained-header charge = %d, want only selected values", used)
	}
}

func TestAttachedMessageParserHeaderLimit(t *testing.T) {
	within := []byte("X:" + strings.Repeat("a", maxAttachedMessageHeaderBytes-4) + "\n\nbody")
	if got, ok := parseAttachedMessage(within, newExtractionBudget()); !ok || string(got.body) != "body" {
		t.Fatalf("header at limit rejected: ok=%v body=%q", ok, got.body)
	}

	over := []byte("X:" + strings.Repeat("a", maxAttachedMessageHeaderBytes-3) + "\n\nbody")
	if _, ok := parseAttachedMessage(over, newExtractionBudget()); ok {
		t.Fatal("header above limit was accepted")
	}
}

func TestAttachedMessageParserRejectsMalformedHeaders(t *testing.T) {
	for _, data := range []string{
		"",
		"not a header",
		" continuation without a field\r\n\r\nbody",
		"Valid: field\r\nmalformed\r\n\r\nbody",
	} {
		if _, ok := parseAttachedMessage([]byte(data), newExtractionBudget()); ok {
			t.Fatalf("malformed attached message accepted: %q", data)
		}
	}
	if got, ok := parseAttachedMessage([]byte("Content-Type: text/plain"), newExtractionBudget()); !ok || len(got.body) != 0 {
		t.Fatalf("valid header ending at EOF rejected: ok=%v body=%q", ok, got.body)
	}
}

func TestAttachedMessageParserUsesMemoryBudget(t *testing.T) {
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 128})
	data := []byte("Content-ID: " + strings.Repeat("x", 4096) + "\r\n\r\nbody")
	expectTermination(t, termination.MemoryExceeded, func() { parseAttachedMessage(data, budget) })
	if !budget.primaryMemory.Exhausted() {
		t.Fatal("retained attached header bypassed memory ledger")
	}
}

func TestAttachedMessageParserChecksCPUWhileScanning(t *testing.T) {
	calls := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckPrimary: func() {
		calls++
		if calls == 2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}})
	data := []byte("X:" + strings.Repeat("a", resourceguard.WorkChunk*2) + "\r\n\r\nbody")
	expectTermination(t, termination.CPUExceeded, func() { parseAttachedMessage(data, budget) })
	if calls != 2 {
		t.Fatalf("CPU checks = %d, want 2", calls)
	}
}
