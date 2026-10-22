package message

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestPlainURLScansTerminateWithinLongTokens(t *testing.T) {
	long := strings.Repeat("h", 4*resourceguard.WorkChunk)
	for _, tc := range []struct {
		name string
		scan func(func())
	}{
		{"prefix", func(stop func()) { nextHTTPPrefix(long, 0, stop) }},
		{"delimiter", func(stop func()) {
			walkPlainHTTPURLs("https://"+long, -1, stop, func(string, int, int) bool { t.Fatal("visited before interrupt"); return true })
		}},
		{"punctuation", func(stop func()) { trimPlainURLPunctuation(long, stop) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var failure termination.Failure
			continued := false
			func() {
				defer termination.Recover(&failure)
				tc.scan(func() { termination.Fail(termination.Failure{Code: termination.CPUExceeded}) })
				continued = true
			}()
			if continued || failure.Code != termination.CPUExceeded {
				t.Fatalf("continued=%v failure=%+v", continued, failure)
			}
		})
	}
	// Permit the forward scan; interrupt only during the backwards trim.
	value := strings.Repeat(".", 4*resourceguard.WorkChunk)
	checks := 0
	var failure termination.Failure
	func() {
		defer termination.Recover(&failure)
		trimPlainURLPunctuation(value, func() {
			checks++
			if checks == 4 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}
		})
	}()
	if checks != 4 || failure.Code != termination.CPUExceeded {
		t.Fatalf("backwards trim: checks=%d failure=%+v", checks, failure)
	}
}

func TestDeferredUsagePreservesTermination(t *testing.T) {
	for _, code := range []termination.Code{termination.CPUExceeded, termination.Cancelled, termination.MemoryExceeded} {
		for _, html := range []bool{false, true} {
			b := newExtractionBudget()
			b.primaryMemory = resourceguard.NewMemory(10)
			child := resourceguard.NewMemory(10)
			child.Reserve(10)
			// Simulate an intervening parent charge that violates the child-limit
			// invariant. Cleanup must still preserve the original failure.
			b.primaryMemory.Reserve(1)
			want := termination.Failure{Code: code, Limit: 123}
			var got termination.Failure
			func() {
				defer termination.Recover(&got)
				if html {
					defer b.consumeHTML(htmlextract.AnalysisUsage{ResourceUsage: htmlextract.ResourceUsage{MemoryBytes: 10}})
				} else {
					defer b.consumeMemory(child)
				}
				termination.Fail(want)
			}()
			if got != want || !b.primaryMemory.Exhausted() || b.primaryMemory.Used() != 10 {
				t.Fatalf("html=%v got=%+v want=%+v used=%d", html, got, want, b.primaryMemory.Used())
			}
		}
	}
}
