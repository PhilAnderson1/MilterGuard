package milter

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

// Advance the injected clock only when actual lexical fallback begins. This
// exercises the production wiring without depending on a fixed parser poll count.
func fallbackClock(step time.Duration) func() (time.Duration, bool) {
	calls, fallbackPolls := 0, 0
	elapsed := 240 * time.Millisecond
	return func() (time.Duration, bool) {
		calls++
		if calls == 1 {
			return time.Second, true
		}
		var pcs [64]uintptr
		frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs[:])])
		for {
			frame, more := frames.Next()
			if strings.HasSuffix(frame.Function, ".extractBoundedHTMLFallback") {
				if fallbackPolls > 0 {
					elapsed += step
				}
				fallbackPolls++
				break
			}
			if !more {
				break
			}
		}
		return time.Second + elapsed, true
	}
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
			service.threadCPUTime = fallbackClock(30 * time.Microsecond)
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if result.selected != actionAccept || result.htmlCPUExceeded || result.htmlMemoryExceeded || result.htmlPrimaryCPUTime != 240*time.Millisecond || result.htmlFallbackCPUTime <= 10*time.Millisecond {
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

func TestFallbackAllowanceExhaustionPolicy(t *testing.T) {
	for _, action := range []string{"dos-reject", "reject", "fallback", ""} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			service.threadCPUTime = fallbackClock(10 * time.Millisecond)
			msg := message.New(256 << 10)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte(strings.Repeat("<div>", 20000)))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if result.htmlPrimaryCPUExceeded || !result.htmlFallbackCPUExceeded || result.htmlPrimaryCPUTime != 240*time.Millisecond || result.htmlFallbackCPUTime != 260*time.Millisecond {
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

func TestMemoryExhaustionUsesResourceLimitAction(t *testing.T) {
	for _, action := range []string{"dos-reject", "reject", "fallback", ""} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			service.ai.MaxHTMLParseMemoryBytes = 1
			service.ai.HTMLResourceRejectMessage = "custom resource limit message"
			service.threadCPUTime = func() (time.Duration, bool) { return time.Second, true }
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

func TestCompletedAnalysisDoesNotSampleClockAgain(t *testing.T) {
	for _, action := range []string{"dos-reject", "fallback"} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			directCalls := 0
			service.threadCPUTime = func() (time.Duration, bool) {
				pc, _, _, _ := runtime.Caller(1)
				if strings.HasSuffix(runtime.FuncForPC(pc).Name(), ".buildAnalysis") {
					directCalls++
					if directCalls > 1 {
						return 2 * time.Second, true
					}
				}
				return time.Second, true
			}
			msg := message.New(4096)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte("<p>complete evidence</p>"))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if directCalls != 1 || result.selected != actionAccept || result.htmlCPUExceeded || analyzer.calls.Load() != 1 {
				t.Fatalf("direct clock calls=%d result=%+v", directCalls, result)
			}
		})
	}
}

func TestFallbackCPUAllowanceIsSharedAcrossMIMEParts(t *testing.T) {
	for _, parts := range []int{1, 16} {
		analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
		service := processingTestService("dos-reject", analyzer)
		service.threadCPUTime = fallbackClock(30 * time.Microsecond)
		var body strings.Builder
		for range parts {
			body.WriteString("--shared\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("<div>", 700) + "evidence\r\n")
		}
		body.WriteString("--shared--\r\n")
		msg := message.New(128 << 10)
		msg.AddHeader("Content-Type", `multipart/mixed; boundary="shared"`)
		msg.AddBody([]byte(body.String()))
		result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
		if result.htmlPrimaryCPUExceeded || result.htmlFallbackCPUExceeded != (parts > 1) {
			t.Fatalf("parts=%d result=%+v", parts, result)
		}
		if parts > 1 && (result.selected != actionReject || analyzer.calls.Load() != 0) {
			t.Fatalf("parts=%d result=%+v", parts, result)
		}
	}
}

func TestFallbackMemoryExhaustionPolicy(t *testing.T) {
	for _, action := range []string{"reject", "dos-reject", "fallback"} {
		t.Run(action, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := processingTestService(action, analyzer)
			service.ai.MaxHTMLParseMemoryBytes = 96 << 10
			service.threadCPUTime = func() (time.Duration, bool) { return time.Second, true }
			msg := message.New(256 << 10)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte(strings.Repeat("<div>", 700) + strings.Repeat("x", 128<<10)))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
			if result.htmlPrimaryMemoryExceeded || !result.htmlFallbackMemoryExceeded || !result.htmlMemoryExceeded || result.htmlCPUExceeded || result.htmlFallbackMemoryBytes != 96<<10 {
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
