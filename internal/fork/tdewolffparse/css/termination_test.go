package css

import (
	"testing"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestStageTerminationPassesThroughCSSRecovery(t *testing.T) {
	for _, code := range []termination.Code{termination.CPUExceeded, termination.MemoryExceeded, termination.Cancelled} {
		var failure termination.Failure
		func() {
			defer termination.Recover(&failure)
			m := resourceguard.NewMemory(1 << 20)
			p := NewParserWithLimits(parse.NewInputString("p { color: red }"), false, ResourceLimits{Memory: m})
			// Install the failure after construction so it occurs under Next's
			// local recovery, not merely at initial setup.
			p.guard.limits.ShouldStop = func() {
				if code == termination.MemoryExceeded {
					m.Reserve(1 << 20)
				} else {
					termination.Fail(termination.Failure{Code: code})
				}
				return
			}
			p.guard.sampler = resourceguard.NewStopSampler(256, p.guard.limits.ShouldStop)
			p.Next()
			t.Fatal("CSS recovery swallowed stage termination")
		}()
		if failure.Code != code {
			t.Fatalf("failure=%+v want %v", failure, code)
		}
	}
}

func expectTermination(t *testing.T, code termination.Code, work func()) {
	t.Helper()
	var failure termination.Failure
	func() { defer termination.Recover(&failure); work(); t.Fatal("resource failure returned normally") }()
	if failure.Code != code {
		t.Fatalf("failure=%+v want %v", failure, code)
	}
}
