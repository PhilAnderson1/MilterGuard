package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"strings"
	"testing"
)

func TestStylesheetRelationScan(t *testing.T) {
	for _, rel := range []string{
		"", "stylesheet", "STYLESHEET", " stylesheet \t", "alternate stylesheet",
		"stylesheet ALTERNATE", "alternate-stylesheet", "x stylesheet y",
		"stylesheet\u00a0alternate", "\u2003StyleSheet\u0085", "\xff stylesheet",
		"styleſheet", "stylesheet\x00alternate",
	} {
		stylesheet, alternate := false, false
		for _, word := range strings.Fields(asciiLower(rel)) {
			stylesheet = stylesheet || word == "stylesheet"
			alternate = alternate || word == "alternate"
		}
		s := sheet{}
		if got := s.hasStylesheetRelation(rel); got != (stylesheet && !alternate) {
			t.Errorf("rel=%q got=%v want=%v", rel, got, stylesheet && !alternate)
		}
	}
}

func TestStylesheetRelationScanDoesNotAllocate(t *testing.T) {
	rel := "STYLESHEET " + strings.Repeat("X ", 1<<19)
	s := sheet{}
	if allocations := testing.AllocsPerRun(3, func() {
		if !s.hasStylesheetRelation(rel) {
			t.Fatal("stylesheet not recognized")
		}
	}); allocations != 0 {
		t.Fatalf("allocated %v times", allocations)
	}
}

func TestStylesheetRelationScanCancellation(t *testing.T) {
	for _, suffix := range []string{strings.Repeat("x", 1<<20), strings.Repeat("\u2003", 1<<18), strings.Repeat("x ", 1<<19)} {
		calls := 0
		budget := testCPUGuard(cpuGuard{shouldStop: func() {
			calls++
			if calls == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		}})
		s := sheet{cpu: budget}
		expectTermination(t, termination.CPUExceeded, func() { s.hasStylesheetRelation("stylesheet " + suffix) })
		if calls != 2 {
			t.Fatalf("calls=%d", calls)
		}
	}
}
