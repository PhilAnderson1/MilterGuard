package message

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestMIMEPartRestartUsesFallbackOnce(t *testing.T) {
	second := strings.Repeat("second part data ", 10000)
	source := []byte("--x\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + second + "\r\n--x\r\nContent-Type: text/plain\r\n\r\nthird\r\n--x--\r\n")
	calls, admissions, fallbackCalls := 0, 0, 0
	interrupt := false
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		CheckPrimary: func() {
			if interrupt {
				calls++
				if calls == 7 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}
			}
		},
		CheckFallback: func() { fallbackCalls++ },
		BeginFallback: func() bool { admissions++; return true },
	})
	reader := multipart.NewReader(newDecodeReader(bytes.NewReader(source), b.checkStage), "x")
	first, ok := readRestartableMIMEPart(&reader, source, "x", 0, b)
	if !ok || first.err != nil || string(first.body) != "first" {
		t.Fatalf("first=%+v ok=%v", first, ok)
	}
	interrupt = true
	got, ok := readRestartableMIMEPart(&reader, source, "x", 1, b)
	if !ok || got.err != nil || string(got.body) != second || admissions != 1 || fallbackCalls == 0 || calls != 7 {
		t.Fatalf("restart ok=%v err=%v len=%d admissions=%d primary=%d fallback=%d", ok, got.err, len(got.body), admissions, calls, fallbackCalls)
	}
	third, ok := readRestartableMIMEPart(&reader, source, "x", 2, b)
	if !ok || third.err != nil || string(third.body) != "third" || admissions != 1 {
		t.Fatalf("third=%+v ok=%v admissions=%d", third, ok, admissions)
	}
	if string(first.body) != "first" {
		t.Fatal("completed part changed")
	}
}

func TestMIMEFallbackExhaustionNeverRetries(t *testing.T) {
	admissions, primary, fallback := 0, 0, 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		CheckPrimary:  func() { primary++; termination.Fail(termination.Failure{Code: termination.CPUExceeded}) },
		CheckFallback: func() { fallback++; termination.Fail(termination.Failure{Code: termination.CPUExceeded}) },
		BeginFallback: func() bool { admissions++; return true },
	})
	data := []byte("--x\r\n\r\ndata\r\n--x--\r\n")
	reader := multipart.NewReader(bytes.NewReader(data), "x")
	for range 2 {
		_, ok := readRestartableMIMEPart(&reader, data, "x", 0, b)
		if ok {
			t.Fatal("exhausted stage completed")
		}
	}
	if primary != 1 || fallback != 1 || admissions != 1 || b.terminal.Code != termination.CPUExceeded {
		t.Fatalf("primary=%d fallback=%d admissions=%d terminal=%+v", primary, fallback, admissions, b.terminal)
	}
}

func TestCancellationDoesNotAdmitFallback(t *testing.T) {
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		CheckPrimary:  func() { termination.Fail(termination.Failure{Code: termination.Cancelled}) },
		BeginFallback: func() bool { t.Fatal("cancelled stage admitted fallback"); return true },
	})
	got := extractMIMEWithBudget("text/plain", "", "", []byte("text"), 0, b)
	if !got.incomplete() || b.cpuLimitExceeded || b.terminal.Code != termination.Cancelled {
		t.Fatalf("result=%+v terminal=%+v", got, b.terminal)
	}
}

func TestControlledMultipartRetainsCompletedPartsOnPrimaryRestart(t *testing.T) {
	raw := []byte("--x\r\nContent-Type: text/plain\r\n\r\nfirst unique\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("second text ", 8000) + "\r\n--x--\r\n")
	baselineBudget := newExtractionBudgetWithControl(HTMLProcessingControl{})
	baseline := extractMIMEWithBudget("multipart/mixed; boundary=x", "", "", raw, 0, baselineBudget)
	for _, at := range []int{1, 5, 10, 20, 35, 60} {
		calls, admissions := 0, 0
		b := newExtractionBudgetWithControl(HTMLProcessingControl{
			CheckPrimary: func() {
				calls++
				if calls == at {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}
			},
			BeginFallback: func() bool { admissions++; return true },
		})
		got := extractMIMEWithBudget("multipart/mixed; boundary=x", "", "", raw, 0, b)
		if got.Text != baseline.Text || got.VisibleText != baseline.VisibleText || admissions > 1 {
			t.Fatalf("at=%d text lengths=%d/%d admissions=%d incomplete=%v", at, len(got.Text), len(baseline.Text), admissions, got.incomplete())
		}
	}
}

func expectTermination(t *testing.T, code termination.Code, work func()) termination.Failure {
	t.Helper()
	var failure termination.Failure
	func() { defer termination.Recover(&failure); work(); t.Fatal("resource failure returned normally") }()
	if failure.Code != code {
		t.Fatalf("failure=%+v want %v", failure, code)
	}
	return failure
}

func TestCPUOutcomePrecedesFallbackAdmission(t *testing.T) {
	var stages []bool
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		CheckPrimary:     func() { termination.Fail(termination.Failure{Code: termination.CPUExceeded}) },
		CheckFallback:    func() { termination.Fail(termination.Failure{Code: termination.CPUExceeded}) },
		CPULimitExceeded: func(fallback bool) { stages = append(stages, fallback) },
		BeginFallback: func() bool {
			if len(stages) != 1 || stages[0] {
				t.Fatal("primary outcome missing before fallback")
			}
			return true
		},
	})
	_, complete := runExtraction(b, func() bool { b.checkStage(); return true })
	if complete || len(stages) != 2 || !stages[1] || b.terminal.Code != termination.CPUExceeded {
		t.Fatalf("complete=%v stages=%v terminal=%+v", complete, stages, b.terminal)
	}
}

func TestFallbackCPUOutcomeAcrossMIMEParts(t *testing.T) {
	calls, admissions, outcomes := 0, 0, 0
	stopAt := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		CheckFallback: func() {
			calls++
			if stopAt != 0 && calls >= stopAt {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}
		},
		CPULimitExceeded: func(fallback bool) {
			if !fallback {
				t.Fatal("wrong stage")
			}
			outcomes++
		},
		BeginFallback: func() bool { admissions++; return true },
	})
	if !b.beginFallback() {
		t.Fatal("fallback refused")
	}
	first := extractMIMEWithBudget("text/plain", "", "", []byte("first completed part"), 0, b)
	if first.incomplete() || calls == 0 {
		t.Fatal("first part did not complete with CPU checks")
	}
	stopAt = calls + 1
	second := extractMIMEWithBudget("text/plain", "", "", []byte("second part"), 0, b)
	stoppedCalls := calls
	extractMIMEWithBudget("text/plain", "", "", []byte("third part"), 0, b)
	if !second.incomplete() || calls != stoppedCalls || admissions != 1 || outcomes != 1 || b.terminal.Code != termination.CPUExceeded {
		t.Fatalf("calls=%d/%d admissions=%d outcomes=%d terminal=%+v", calls, stoppedCalls, admissions, outcomes, b.terminal)
	}
}
