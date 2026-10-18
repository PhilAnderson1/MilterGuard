package htmlextract

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
		budget := &cpuGuard{shouldStop: func() bool { calls++; return calls == 2 }}
		s := sheet{cpu: budget}
		if s.hasStylesheetRelation("stylesheet "+suffix) || !s.stopped || !budget.stopped || calls != 2 {
			t.Fatalf("stopped=%v budget stopped=%v calls=%d", s.stopped, budget.stopped, calls)
		}
	}
}
