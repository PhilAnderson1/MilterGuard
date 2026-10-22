package message

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestChildMemoryExhaustionTransfersOnlyAdmittedCharges(t *testing.T) {
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 100})
	child := resourceguard.NewMemory(100)
	child.Reserve(7)
	var failure termination.Failure
	func() {
		defer termination.Recover(&failure)
		child.Reserve(100)
	}()
	if failure.Code != termination.MemoryExceeded {
		t.Fatalf("failure=%+v", failure)
	}
	b.consumeMemory(child)
	if got := b.primaryMemory.Charged(); got != 7 || !b.memoryLimitExceeded {
		t.Fatalf("transferred=%d memoryLimitExceeded=%v", got, b.memoryLimitExceeded)
	}
}

func TestPrimaryMIMEBodyAllocationsAreGuarded(t *testing.T) {
	body := strings.Repeat("a", 16<<10)
	for _, tc := range []struct{ name, kind, encoding, body string }{
		{"text copy", "text/plain", "", body},
		{"transfer decode", "text/plain", "base64", base64.StdEncoding.EncodeToString([]byte(body))},
		{"quoted printable", "text/plain", "quoted-printable", strings.Repeat(strings.Repeat("=61", 20)+"=\r\n", 1024)},
		{"charset decode", "text/plain; charset=windows-1252", "", strings.Repeat("\x92", 16<<10)},
		{"multipart read", "multipart/mixed; boundary=x", "", "--x\r\nContent-Type: application/octet-stream\r\n\r\n" + body + "\r\n--x--\r\n"},
		{"attached message header", "message/rfc822", "", "Content-ID: " + body + "\r\nContent-Type: application/octet-stream\r\n\r\nbody"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const limit = 8 << 10
			notified := 0
			b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: limit, StopOnMemoryLimit: true, MemoryLimitExceeded: func() { notified++ }, BeginFallback: func() bool { t.Fatal("memory rejection admitted fallback"); return true }})
			got := extractMIMEWithBudget(tc.kind, tc.encoding, "", []byte(tc.body), 0, b)
			if !got.incomplete() || b.terminal.Code != termination.MemoryExceeded || b.cpuLimitExceeded || notified != 1 || b.primaryMemory.Used() != limit || b.fallback != nil {
				t.Fatalf("text length=%d incomplete=%v terminal=%+v used=%d notified=%d", len(got.Text), got.incomplete(), b.terminal, b.primaryMemory.Used(), notified)
			}
		})
	}
}

func TestNestedMIMESharesPrimaryMemoryAllowance(t *testing.T) {
	body := strings.Repeat("a", 64<<10)
	kind := "application/octet-stream"
	for _, boundary := range []string{"inner", "outer"} {
		body = "--" + boundary + "\r\nContent-Type: " + kind + "\r\n\r\n" + body + "\r\n--" + boundary + "--\r\n"
		kind = "multipart/mixed; boundary=" + boundary
	}
	const limit = 192 << 10
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: limit, StopOnMemoryLimit: true})
	got := extractMIMEWithBudget(kind, "", "", []byte(body), 0, b)
	if !got.incomplete() || !b.memoryLimitExceeded || b.primaryMemory.Used() != limit || b.terminal.Code != termination.MemoryExceeded {
		t.Fatalf("nested decoding escaped shared allowance: terminal=%+v used=%d incomplete=%v", b.terminal, b.primaryMemory.Used(), got.incomplete())
	}
}

func TestPrimaryMIMEFailureUsesIndependentFallbackLedger(t *testing.T) {
	const limit = 32 << 10
	admissions := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: limit, BeginFallback: func() bool { admissions++; return true }})
	first := extractMIMEWithBudget("text/plain", "", "", []byte(strings.Repeat("a", 16<<10)), 0, b)
	if first.incomplete() || b.primaryMemory.Used() < 16<<10 || b.fallback != nil {
		t.Fatal("first part was not charged to primary")
	}
	second := extractMIMEWithBudget("text/plain", "", "", []byte(strings.Repeat("b", 24<<10)), 0, b)
	if second.incomplete() || len(second.Text) != 24<<10 || !b.memoryLimitExceeded || b.fallback == nil || admissions != 1 || b.primaryMemory.Used() != limit || b.fallback.memory.Used() < 24<<10 || b.fallback.memory.Used() >= limit {
		t.Fatalf("second length=%d incomplete=%v admissions=%d terminal=%+v", len(second.Text), second.incomplete(), admissions, b.terminal)
	}
	third := extractMIMEWithBudget("text/plain", "", "", []byte(strings.Repeat("c", 16<<10)), 0, b)
	if !third.incomplete() || admissions != 1 || !b.fallbackMemoryExceeded || b.terminal.Code != termination.MemoryExceeded {
		t.Fatalf("fallback reset: admissions=%d terminal=%+v", admissions, b.terminal)
	}
}

func TestCompletedPartRetentionCanSwitchMemoryStage(t *testing.T) {
	admissions := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 4096, BeginFallback: func() bool { admissions++; return true }})

	if _, ok := runExtraction(b, func() int { return 1 }); !ok {
		t.Fatal("initial admission failed")
	}

	b.primaryMemory.Reserve(b.remainingMemory() - 1)
	content := extractedContent{Text: "already completed"}
	parts, ok := appendMIMEPart(b, nil, content)
	if !ok || len(parts) != 1 || parts[0].Text != content.Text || admissions != 1 || b.primaryMemory.Used() != 4096 || b.fallback.memory.Used() == 0 {
		t.Fatalf("parts=%+v admissions=%d ok=%v", parts, admissions, ok)
	}
}

func TestMIMEAndHTMLShareOneReportedAllowance(t *testing.T) {
	source := []byte("<p>Visible text</p>")
	unlimited := newExtractionBudgetWithControl(HTMLProcessingControl{})
	got := extractMIMEWithBudget("text/html", "", "", source, 0, unlimited)
	if got.incomplete() || unlimited.primaryMemory.Used() <= int64(len(source)) {
		t.Fatal("HTML work was not included in the primary ledger")
	}
	limit := unlimited.primaryMemory.Used() - 1
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: limit, StopOnMemoryLimit: true})
	got = extractMIMEWithBudget("text/html", "", "", source, 0, b)
	if !got.incomplete() || !b.memoryLimitExceeded || b.primaryMemory.Charged() <= 0 || b.primaryMemory.Charged() > limit || b.cpuLimitExceeded {
		t.Fatalf("shared allowance bypassed: limit=%d used=%d incomplete=%v", limit, b.primaryMemory.Used(), got.incomplete())
	}
}
