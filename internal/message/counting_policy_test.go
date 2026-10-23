package message

import (
	"runtime"
	"strings"
	"testing"
)

func TestConfidentCountingOnlyForFallbackVision(t *testing.T) {
	for _, mediaType := range []string{"text/plain", "text/html"} {
		for _, caller := range []string{"off", "always", "fallback", "visible", "command"} {
			t.Run(mediaType+"/"+caller, func(t *testing.T) {
				m := New(1 << 20)
				m.AddHeader("Content-Type", mediaType)
				// Long enough to exercise the sampled checkpoint inside counting.
				body := strings.Repeat("Visible text ", 10000)
				if mediaType == "text/html" {
					body = "<p>" + body + "</p>"
				}
				m.AddBody([]byte(body))
				counted := false
				control := HTMLProcessingControl{CheckPrimary: func() {
					var pcs [32]uintptr
					frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs[:])])
					for {
						frame, more := frames.Next()
						if strings.HasSuffix(frame.Function, ".confidentPreparedTextCharacters") {
							counted = true
						}
						if !more {
							break
						}
					}
				}}
				var output string
				switch caller {
				case "visible":
					output = m.VisibleBodyWithHTMLControl(1000, control)
				case "command":
					var complete bool
					output, complete = m.CommandTextResult(-1, control)
					if !complete {
						t.Fatal("command extraction incomplete")
					}
				default:
					analysis := m.BuildAnalysisWithHTMLControl(AnalysisContext{}, 1000, VisionOptions{Mode: caller}, control)
					if analysis.BodyExtractionIncomplete {
						t.Fatal("analysis extraction incomplete")
					}
					output = analysis.Prompt
				}
				if !strings.Contains(output, "Visible text") {
					t.Fatal("text evidence lost")
				}
				if counted != (caller == "fallback") {
					t.Fatalf("confident counting ran=%t, want %t", counted, caller == "fallback")
				}
			})
		}
	}
}
