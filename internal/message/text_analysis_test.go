package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"runtime"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestPaddingInvalidUTF8ExpansionIsGuarded(t *testing.T) {
	input := strings.Repeat("\xff", 4096) + strings.Repeat("\u200b", 32)
	tight := resourceguard.NewMemory(int64(len(input) * 2))
	expectTermination(t, termination.MemoryExceeded, func() { compactFormattingPaddingWithResources(input, tight, nil) })
	memory := resourceguard.NewMemory(1 << 20)
	value := compactFormattingPaddingWithResources(input, memory, nil)
	want := strings.Repeat("�", 4096) + strings.Repeat("\u200b", 8)
	if value != want || memory.Used() < int64(len(value)) {
		t.Fatalf("expanded output was lost or undercharged: length=%d charged=%d", len(value), memory.Used())
	}
}

func TestPaddingCancellationDuringUnchangedRunCopy(t *testing.T) {
	input := strings.Repeat("\u200b", 32) + "x" + strings.Repeat(" ", 64<<10) + "y"
	writeChecks := 0
	stop := func() {
		var pcs [16]uintptr
		frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs[:])])
		for {
			frame, more := frames.Next()
			if frame.Function == "github.com/PhilAnderson1/MilterGuard/internal/resourceguard.WriteString" {
				writeChecks++
				// The first check admits the copy; the second interrupts it
				// after its first WorkChunk has been written.
				if writeChecks == 2 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			}
			if !more {
				return
			}
		}
	}
	expectTermination(t, termination.CPUExceeded, func() { compactFormattingPaddingWithResources(input, nil, stop) })
	if writeChecks != 2 {
		t.Fatalf("copy checks=%d", writeChecks)
	}
}

func TestConfidentCharactersPreserveNormalization(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
	}{
		{"  a\t b\n\n\nc \n", 6},
		{"<invisible>hello</invisible>", 5},
		{"a<normal>b", 10},
		{"é😀", 2},
		{"a\xff\xffb", 3},
		{strings.Repeat("\u200b", 40), 0},
		{"a" + strings.Repeat("\u200b", 40) + "b", 10},
	} {
		memory := resourceguard.NewMemory(1 << 20)
		got := confidentTextCharactersWithResources(tc.input, memory, nil)
		if got != tc.want {
			t.Errorf("%q: count=%d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestTextAnalysisCancellation(t *testing.T) {
	for _, input := range []string{
		strings.Repeat("a", 100000),
		"<visibility-uncertain " + strings.Repeat("a", 100000),
		strings.Repeat("a", 100000) + strings.Repeat("\u200b", 40),
		strings.Repeat("\xff", 100000),
	} {
		calls := 0
		stop := func() {
			calls++
			if calls >= 10 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		}
		expectTermination(t, termination.CPUExceeded, func() { confidentTextCharactersWithResources(input, nil, stop) })
		if calls != 10 {
			t.Fatalf("checks=%d", calls)
		}
	}
}

func TestTextAnalysisMemoryAdmission(t *testing.T) {
	for _, input := range []string{
		"a" + strings.Repeat("\u200b", 10000),
		"<invisible>" + strings.Repeat("a", 10000) + "</invisible>",
	} {
		memory := resourceguard.NewMemory(2048)
		expectTermination(t, termination.MemoryExceeded, func() { confidentTextCharactersWithResources(input, memory, nil) })
	}
}

func TestPlainCountingNeedsNoCopy(t *testing.T) {
	input := strings.Repeat("a", 1<<20)
	memory := resourceguard.NewMemory(1)
	count := confidentTextCharactersWithResources(input, memory, nil)
	if count != len(input) || memory.Used() != 0 {
		t.Fatalf("ordinary counting allocated: count=%d used=%d", count, memory.Used())
	}
}

func TestStoppedPlainTextSkipsCharacterCounting(t *testing.T) {
	input := []byte(strings.Repeat("a", 1<<20))
	checks := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{CheckFallback: func() {
		checks++
		if checks >= 258 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}})
	if !budget.beginFallback() {
		t.Fatal("fallback admission")
	}
	content := extractMIMEWithBudget("text/plain", "", "", input, 0, budget)
	if !content.ExtractionIncomplete || !content.HTMLCPULimitExceeded || content.ConfidentVisibleChars != 0 {
		t.Fatalf("stopped text counted: %+v", content)
	}
}
func TestCountingUsesFallbackMemory(t *testing.T) {
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 2048})
	if !budget.beginFallback() {
		t.Fatal("fallback admission")
	}
	remaining := budget.remainingMemory()
	_, complete := runExtraction(budget, func() int { return budget.confidentCharacters("a" + strings.Repeat("\u200b", 10000)) })
	if complete || !budget.fallbackMemoryExceeded || budget.remainingMemory() != remaining {
		t.Fatal("counting did not use fallback ledger")
	}
}
func TestHTMLTextStopCallbackIsSharedAndCurrent(t *testing.T) {
	stopClock := false
	clockChecks := 0
	memory := resourceguard.NewMemory(4096)
	e := htmlExtraction{memory: memory, shouldStop: func() {
		clockChecks++
		if stopClock {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}}
	stop := e.textStopCallback()
	stop()
	used := memory.Used()
	if used == 0 {
		t.Fatal("callback unaccounted")
	}
	for range 1000 {
		shared := e.textStopCallback()
		shared()
		if memory.Used() != used {
			t.Fatal("callback allocation repeated")
		}
	}
	if clockChecks != 101 {
		t.Fatalf("1001 text checks read clock %d times", clockChecks)
	}
	stopClock = true
	expectTermination(t, termination.CPUExceeded, func() { e.textClockCheck(); t.Fatal("continued into sampled text work") })
}
func TestPlainCountingCallbackIsSharedAcrossStages(t *testing.T) {
	stopClock := false
	fallbackChecks := 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 4096, CheckFallback: func() {
		fallbackChecks++
		if stopClock {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}})
	if b.confidentCharacters("text") != 4 {
		t.Fatal("initial count")
	}
	remaining := b.remainingMemory()
	if remaining == 4096 || b.countingStop == nil {
		t.Fatal("callback unaccounted")
	}
	for range 10 {
		if b.confidentCharacters("text") != 4 || b.remainingMemory() != remaining {
			t.Fatal("callback allocated again")
		}
	}
	if !b.beginFallback() {
		t.Fatal("fallback admission")
	}
	for range 10 {
		if b.confidentCharacters("text") != 4 || b.remainingMemory() != remaining || b.fallback.memory.Used() != 0 {
			t.Fatal("shared callback allocated again")
		}
	}
	if fallbackChecks == 0 {
		t.Fatal("callback did not follow active stage")
	}
	stopClock = true
	expectTermination(t, termination.CPUExceeded, func() { b.confidentCharacters("text") })
}
func TestSharedCallbackAdmissionFailure(t *testing.T) {
	e := htmlExtraction{memory: resourceguard.NewMemory(1)}
	expectTermination(t, termination.MemoryExceeded, func() { e.textStopCallback() })
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 1})
	expectTermination(t, termination.MemoryExceeded, func() { b.confidentCharacters("text") })
	if !e.memory.Exhausted() || !b.primaryMemory.Exhausted() {
		t.Fatal("lost exhaustion")
	}
}
func TestFallbackTokenizerStopUnwindsBeforeTextWork(t *testing.T) {
	clockChecks := 0
	stopClock := false
	r := testFallbackResources(func() {
		clockChecks++
		if stopClock {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	})
	stop := r.textStopCallback()
	for range 10 {
		stop()
	}
	if clockChecks != 1 {
		t.Fatalf("clock sampled %d times", clockChecks)
	}
	stopClock = true
	expectTermination(t, termination.CPUExceeded, func() { r.checkpoint(); stop(); t.Fatal("text work resumed after tokenizer stop") })
	if clockChecks != 2 {
		t.Fatalf("clock checks=%d", clockChecks)
	}
}
