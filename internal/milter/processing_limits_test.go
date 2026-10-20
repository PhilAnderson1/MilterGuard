package milter

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/threadcpu"
)

// Real CPU tests use a large input and a small allowance; they do not assert
// exact clock values or a particular number of parser operations.
func requireThreadCPU(t *testing.T) {
	t.Helper()
	if _, ok := threadcpu.Now(); !ok {
		t.Skip("thread CPU clock unavailable")
	}
}

func cpuHeavyHTML() string {
	return strings.Repeat(`<p style="color:#123456">ordinary message</p>`, 60000)
}

func processingTestService(action string, analyzer Analyzer) *analysisService {
	return &analysisService{
		analyzer: analyzer,
		ai:       config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 4096, MaxHTMLParseCPUMilliseconds: 250, HTMLResourceLimitAction: action, VisionMode: "off"},
		slots:    make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestNonCPUFailureGetsFreshFallbackAllowance(t *testing.T) {
	for _, action := range []string{"dos-reject", "reject", "fallback", ""} {
		t.Run(action, func(t *testing.T) {
			analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
			service := processingTestService(action, analyzer)
			// 700 open elements exceed the tree nesting limit. Fallback continues
			// into a second HTML part and a plain part under the same allowance.
			msg := message.New(32 << 10)
			msg.AddHeader("Content-Type", `multipart/mixed; boundary="stages"`)
			msg.AddBody([]byte("--stages\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("<div>", 700) + "first evidence\r\n--stages\r\nContent-Type: text/html\r\n\r\n<p>second evidence</p>\r\n--stages\r\nContent-Type: text/plain\r\n\r\nthird evidence\r\n--stages--\r\n"))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if result.selected != actionAccept || result.htmlCPUExceeded || result.htmlMemoryExceeded {
				t.Fatalf("result=%+v", result)
			}
			select {
			case input := <-analyzer.inputs:
				for _, want := range []string{"first evidence", "second evidence", "third evidence"} {
					if !strings.Contains(input.Text, want) {
						t.Fatalf("missing %q from %q", want, input.Text)
					}
				}
			default:
				t.Fatal("AI was not called")
			}
		})
	}
}

func TestCPUExhaustionPolicyWithRealClock(t *testing.T) {
	requireThreadCPU(t)
	for _, action := range []string{"dos-reject", "reject", "fallback", ""} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			service.ai.MaxHTMLParseCPUMilliseconds = 1
			msg := message.New(4 << 20)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte(cpuHeavyHTML()))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if !result.htmlPrimaryCPUExceeded || result.htmlMemoryExceeded {
				t.Fatalf("wrong exhaustion: %+v", result)
			}
			if action == "fallback" {
				if result.selected != actionAccept || analyzer.calls.Load() != 1 {
					t.Fatalf("fallback policy: %+v", result)
				}
			} else if result.selected != actionReject || analyzer.calls.Load() != 0 {
				t.Fatalf("reject policy: %+v", result)
			}
		})
	}
}

func TestMemoryExhaustionUsesResourceLimitAction(t *testing.T) {
	for _, action := range []string{"dos-reject", "reject", "fallback", ""} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			service.ai.MaxHTMLParseMemoryBytes = 1
			service.ai.HTMLResourceRejectMessage = "custom resource limit message"
			msg := message.New(4096)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte("<p>evidence</p>"))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if !result.htmlMemoryExceeded || result.htmlCPUExceeded {
				t.Fatalf("result=%+v", result)
			}
			if action == "fallback" {
				if result.selected != actionAccept || analyzer.calls.Load() != 1 {
					t.Fatalf("result=%+v", result)
				}
			} else if result.selected != actionReject || result.rejectMessage != "custom resource limit message" || analyzer.calls.Load() != 0 || !strings.Contains(strings.Join(result.reasons, " "), "memory limit") {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestCompletedAnalysisRemainsAccepted(t *testing.T) {
	for _, action := range []string{"dos-reject", "fallback"} {
		analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
		service := processingTestService(action, analyzer)
		msg := message.New(4096)
		msg.AddHeader("Content-Type", "text/html")
		msg.AddBody([]byte("<p>complete evidence</p>"))
		result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
		if result.selected != actionAccept || result.htmlCPUExceeded || analyzer.calls.Load() != 1 {
			t.Fatalf("result=%+v", result)
		}
	}
}

// Shared fallback CPU checks across MIME parts are tested with deterministic
// termination injection in message.TestFallbackCPUOutcomeAcrossMIMEParts.

func TestFallbackMemoryExhaustionPolicy(t *testing.T) {
	for _, action := range []string{"reject", "dos-reject", "fallback"} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			// A small deeply nested part starts fallback without exhausting primary
			// memory. The following large part then exhausts fallback memory.
			service.ai.MaxHTMLParseMemoryBytes = 256 << 10
			msg := message.New(256 << 10)
			msg.AddHeader("Content-Type", "multipart/mixed; boundary=x")
			msg.AddBody([]byte("--x\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("<div>", 700) + "evidence\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + strings.Repeat("x", 128<<10) + "\r\n--x--\r\n"))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if result.htmlPrimaryMemoryExceeded || !result.htmlFallbackMemoryExceeded || !result.htmlMemoryExceeded || result.htmlCPUExceeded || result.htmlFallbackMemoryBytes != 256<<10 {
				t.Fatalf("result=%+v", result)
			}
			if action == "fallback" {
				if result.selected != actionAccept || analyzer.calls.Load() != 1 {
					t.Fatalf("result=%+v calls=%d", result, analyzer.calls.Load())
				}
			} else if result.selected != actionReject || analyzer.calls.Load() != 0 {
				t.Fatalf("result=%+v calls=%d", result, analyzer.calls.Load())
			}
		})
	}
}
