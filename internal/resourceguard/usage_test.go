package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"testing"
)

func TestRecordUsageDoesNotRaiseOrRefund(t *testing.T) {
	m := NewMemory(10)
	m.Reserve(2)
	m.RecordUsage(5)
	m.RecordUsage(-1)
	if m.Used() != 7 || m.Exhausted() {
		t.Fatalf("used=%d exhausted=%v", m.Used(), m.Exhausted())
	}
	m.RecordUsage(3)
	if m.Used() != 10 || m.Exhausted() {
		t.Fatal("exact fit should succeed")
	}
	m.RecordUsage(1)
	m.RecordUsage(1<<63 - 1)
	m.RecordUsage(0)
	if m.Used() != 10 || !m.Exhausted() {
		t.Fatal("overflow must exhaust ledger")
	}
	expectTermination(t, termination.MemoryExceeded, func() { m.Reserve(1) })
}

func TestUnescapePathPrescan(t *testing.T) {
	for _, text := range []string{"plain/path", "escaped%20path", "%zz"} {
		checks := 0
		got, err := UnescapePathBytes(NewMemory(1024), text, func() { checks++ })
		if checks != 0 {
			t.Fatalf("%q: short input made %d checkpoints", text, checks)
		}
		if text == "%zz" {
			if err == nil {
				t.Fatal("missing escape error")
			}
			continue
		}
		want := strings.ReplaceAll(text, "%20", " ")
		if err != nil || string(got) != want {
			t.Fatalf("got=%q err=%v want=%q", got, err, want)
		}
	}
	expectTermination(t, termination.CPUExceeded, func() {
		UnescapePathBytes(NewMemory(100000), strings.Repeat("a", 2*WorkChunk), func() { termination.Fail(termination.Failure{Code: termination.CPUExceeded}) })
	})
}
