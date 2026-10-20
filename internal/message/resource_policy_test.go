package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
)

func TestMemoryPolicyStopsBeforeLexicalFallback(t *testing.T) {
	for _, stop := range []bool{false, true} {
		fallbackCalls, memoryCalls := 0, 0
		msg := New(4096)
		msg.AddHeader("Content-Type", "text/html")
		msg.AddBody([]byte("<p>retained evidence</p>"))
		got := msg.BuildAnalysisWithHTMLControl(AnalysisContext{}, 4096, VisionOptions{Mode: "off"}, HTMLProcessingControl{
			MemoryBytes: 8192, StopOnMemoryLimit: stop,
			MemoryLimitExceeded: func() { memoryCalls++ },
			CheckFallback:       func() { fallbackCalls++; return },
		})
		if !got.HTMLMemoryLimitExceeded || got.HTMLCPULimitExceeded || memoryCalls != 1 {
			t.Fatalf("stop=%v memory callbacks=%d analysis=%+v", stop, memoryCalls, got)
		}
		if stop {
			if fallbackCalls != 0 || strings.Contains(got.Prompt, "retained evidence") {
				t.Fatalf("memory rejection ran fallback: calls=%d", fallbackCalls)
			}
		} else {
			if fallbackCalls == 0 || !strings.Contains(got.Prompt, "retained evidence") {
				t.Fatal("memory fallback lost evidence")
			}
		}
	}
}

func TestMemoryLimitFlagRequiresFailedAllocation(t *testing.T) {
	calls := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 256, StopOnMemoryLimit: true, MemoryLimitExceeded: func() { calls++ }})
	runExtraction(b, func() struct{} { return struct{}{} })
	b.consumeHTML(htmlextract.ResourceUsage{MemoryBytes: b.remainingMemory()})
	if b.memoryLimitExceeded || calls != 0 {
		t.Fatal("exact use is not a violation")
	}
	_, complete := runExtraction(b, func() struct{} { b.reserveOutputMemory(1); return struct{}{} })
	if complete || !b.memoryLimitExceeded || calls != 1 {
		t.Fatal("failed reservation did not report exhaustion")
	}
	_, complete = runExtraction(b, func() struct{} { t.Fatal("terminal operation resumed"); return struct{}{} })
	if complete || calls != 1 {
		t.Fatal("memory notification repeated")
	}
}

func TestMultipartOutputMemoryExhaustionIsReported(t *testing.T) {
	m := New(4096)
	m.AddHeader("Content-Type", `multipart/mixed; boundary="small"`)
	m.AddBody([]byte("--small\r\nContent-Type: text/plain\r\n\r\nfirst\r\n--small\r\nContent-Type: text/plain\r\n\r\nsecond\r\n--small--\r\n"))
	a := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 4096, VisionOptions{Mode: "off"}, HTMLProcessingControl{MemoryBytes: 1, StopOnMemoryLimit: true})
	if !a.HTMLMemoryLimitExceeded || a.HTMLCPULimitExceeded || !a.BodyExtractionIncomplete {
		t.Fatalf("analysis=%+v", a)
	}
}

func TestUncontrolledFallbackPreservesLaterMIMEParts(t *testing.T) {
	m := New(32 << 10)
	m.AddHeader("Content-Type", `multipart/mixed; boundary="continue"`)
	m.AddBody([]byte("--continue\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("<div>", 700) + "first evidence\r\n--continue\r\nContent-Type: text/plain\r\n\r\nsecond evidence\r\n--continue\r\nContent-Type: text/html\r\n\r\n<p>third evidence</p>\r\n--continue--\r\n"))
	a := m.BuildAnalysis(AnalysisContext{}, 4096, VisionOptions{Mode: "off"})
	for _, want := range []string{"first evidence", "second evidence", "third evidence"} {
		if !strings.Contains(a.Prompt, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if a.HTMLCPULimitExceeded || a.HTMLMemoryLimitExceeded {
		t.Fatal("structural failure reported as budget exhaustion")
	}
}

func TestTerminalFallbackIsNotRestarted(t *testing.T) {
	calls := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{CheckFallback: func() { calls++; termination.Fail(termination.Failure{Code: termination.CPUExceeded}) }})
	if !b.beginFallback() {
		t.Fatal("fallback admission")
	}
	_, complete := runExtraction(b, func() struct{} { b.checkStage(); return struct{}{} })
	if complete || calls != 1 {
		t.Fatal("fallback stop not reported")
	}
	_, complete = runExtraction(b, func() struct{} { t.Fatal("terminal fallback resumed"); return struct{}{} })
	if complete || calls != 1 {
		t.Fatal("fallback restarted")
	}
}

func TestCSSExpansionMemoryExhaustionStopsRecovery(t *testing.T) {
	var source strings.Builder
	source.WriteString(`<div style="--a0:x;`)
	for i := 1; i < 30; i++ {
		fmt.Fprintf(&source, "--a%d:var(--a%d) var(--a%d);", i, i-1, i-1)
	}
	source.WriteString(`display:none">evidence</div>`)
	m := New(4096)
	m.AddHeader("Content-Type", "text/html")
	m.AddBody([]byte(source.String()))
	fallbackCalls := 0
	a := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 4096, VisionOptions{Mode: "off"}, HTMLProcessingControl{MemoryBytes: 8 << 20, StopOnMemoryLimit: true, CheckFallback: func() { fallbackCalls++; return }})
	if !a.HTMLMemoryLimitExceeded || a.HTMLCPULimitExceeded || fallbackCalls != 0 {
		t.Fatalf("analysis=%+v fallback calls=%d", a, fallbackCalls)
	}
}
