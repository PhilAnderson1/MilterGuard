package message

import (
	"runtime"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestPaddingInvalidUTF8ExpansionIsGuarded(t *testing.T) {
	input := strings.Repeat("\xff", 4096) + strings.Repeat("\u200b", 32)
	tight := resourceguard.NewMemory(int64(len(input) * 2))
	if value, ok := compactFormattingPaddingWithResources(input, tight, nil); ok || value != "" || !tight.Exhausted() {
		t.Fatal("UTF-8 expansion allocated beyond the admitted output capacity")
	}
	memory := resourceguard.NewMemory(1 << 20)
	value, ok := compactFormattingPaddingWithResources(input, memory, nil)
	want := strings.Repeat("�", 4096) + strings.Repeat("\u200b", 8)
	if !ok || value != want || memory.Used() < int64(len(value)) {
		t.Fatalf("expanded output was lost or undercharged: complete=%v length=%d charged=%d", ok, len(value), memory.Used())
	}
}

func TestPaddingCancellationDuringUnchangedRunCopy(t *testing.T) {
	input := strings.Repeat("\u200b", 32) + "x" + strings.Repeat(" ", 64<<10) + "y"
	writeChecks := 0
	stop := func() bool {
		var pcs [16]uintptr
		frames := runtime.CallersFrames(pcs[:runtime.Callers(1, pcs[:])])
		for {
			frame, more := frames.Next()
			if frame.Function == "github.com/PhilAnderson1/MilterGuard/internal/resourceguard.WriteString" {
				writeChecks++
				// The first check admits the copy; the second interrupts it
				// after its first WorkChunk has been written.
				return writeChecks == 2
			}
			if !more {
				return false
			}
		}
	}
	value, ok := compactFormattingPaddingWithResources(input, nil, stop)
	if ok || value != "" || writeChecks != 2 {
		t.Fatalf("long whitespace copy ignored cancellation: complete=%v checks=%d", ok, writeChecks)
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
		got, ok := confidentTextCharactersWithResources(tc.input, memory, nil)
		if !ok || got != tc.want {
			t.Errorf("%q: count=%d complete=%v, want %d", tc.input, got, ok, tc.want)
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
		stop := func() bool { calls++; return calls >= 10 }
		if count, ok := confidentTextCharactersWithResources(input, nil, stop); ok || count != 0 || calls != 10 {
			t.Fatalf("cancelled counting: count=%d complete=%v checks=%d", count, ok, calls)
		}
	}
}

func TestTextAnalysisMemoryAdmission(t *testing.T) {
	for _, input := range []string{
		"a" + strings.Repeat("\u200b", 10000),
		"<invisible>" + strings.Repeat("a", 10000) + "</invisible>",
	} {
		memory := resourceguard.NewMemory(2048)
		if count, ok := confidentTextCharactersWithResources(input, memory, nil); ok || count != 0 || !memory.Exhausted() {
			t.Fatalf("memory rejection ignored: count=%d complete=%v used=%d", count, ok, memory.Used())
		}
	}
}

func TestPlainCountingNeedsNoCopy(t *testing.T) {
	input := strings.Repeat("a", 1<<20)
	memory := resourceguard.NewMemory(1)
	count, ok := confidentTextCharactersWithResources(input, memory, nil)
	if !ok || count != len(input) || memory.Used() != 0 {
		t.Fatalf("ordinary counting allocated: count=%d complete=%v used=%d", count, ok, memory.Used())
	}
}

func TestStoppedPlainTextSkipsCharacterCounting(t *testing.T) {
	input := []byte(strings.Repeat("a", 1<<20))
	checks := 0
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{
		ShouldFallback:     func() bool { return true },
		FallbackShouldStop: func() bool { checks++; return checks >= 258 },
	})
	if !budget.beginFallback() {
		t.Fatal("fallback admission")
	}
	content := extractMIMEWithBudget("text/plain", "", "", input, 0, budget)
	if !content.ExtractionIncomplete || !content.HTMLCPULimitExceeded || content.ConfidentVisibleChars != 0 || len(content.Text) != len(input) {
		t.Fatalf("stopped text was counted or lost: text=%d count=%d incomplete=%v", len(content.Text), content.ConfidentVisibleChars, content.ExtractionIncomplete)
	}
}

func TestCountingUsesFallbackMemory(t *testing.T) {
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 2048})
	if !budget.beginFallback() {
		t.Fatal("fallback admission")
	}
	remaining := budget.memoryBytesRemaining
	count, ok := budget.confidentCharacters("a" + strings.Repeat("\u200b", 10000))
	if ok || count != 0 || !budget.fallbackMemoryExceeded || budget.memoryBytesRemaining != remaining {
		t.Fatal("counting did not use and report the fallback ledger")
	}
}
