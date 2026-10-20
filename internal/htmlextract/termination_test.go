package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"testing"
)

func TestControlledAnalysisUnwindsAndPublishesUsage(t *testing.T) {
	for _, code := range []termination.Code{termination.MemoryExceeded, termination.CPUExceeded, termination.Cancelled} {
		var failure termination.Failure
		var usage ResourceUsage
		limits := DefaultLimits()
		if code == termination.MemoryExceeded {
			limits.MemoryBytes = 1
		}
		checks := 0
		func() {
			defer termination.Recover(&failure)
			AnalyzeControlled([]byte(`<style>p {color:red}</style><p>text</p>`), limits, func() {
				checks++
				if checks == 3 {
					termination.Fail(termination.Failure{Code: code})
				}
				return
			}, &usage)
			t.Fatal("controlled analysis returned after termination")
		}()
		if failure.Code != code || usage.MemoryBytes == 0 {
			t.Fatalf("code=%v failure=%+v usage=%+v", code, failure, usage)
		}
		if (code == termination.MemoryExceeded) != usage.MemoryLimitExceeded {
			t.Fatalf("incorrect memory classification: %+v", usage)
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

func captureAnalysis(input []byte, limits Limits) (document Document, usage ResourceUsage, err error, failure termination.Failure) {
	defer termination.Recover(&failure)
	document, err = AnalyzeControlled(input, limits, nil, &usage)
	return
}

func TestAnalysisEntryPointsRequireCallerBoundary(t *testing.T) {
	limits := DefaultLimits()
	limits.MemoryBytes = 1
	for name, work := range map[string]func(){
		"Analyze":         func() { Analyze([]byte("<p>text</p>"), limits) },
		"AnalyzeWithStop": func() { AnalyzeWithStop([]byte("<p>text</p>"), limits, nil) },
	} {
		t.Run(name, func(t *testing.T) { expectTermination(t, termination.MemoryExceeded, work) })
	}
}
