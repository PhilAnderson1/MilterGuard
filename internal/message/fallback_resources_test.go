package message

import (
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
)

func testFallbackResources(stop func() bool) *fallbackResources {
	return &fallbackResources{memory: resourceguard.NewMemory(64 << 20), shouldStop: stop}
}

// The primary ledger is deliberately exhausted before admitting recovery.
func TestFallbackMemoryIsFreshAndIndependent(t *testing.T) {
	const limit = 64 << 10
	primaryCalls, fallbackCalls, admissions := 0, 0, 0
	b := newExtractionBudgetWithControl(HTMLProcessingControl{
		MemoryBytes:                 limit,
		BeginFallback:               func() bool { admissions++; return true },
		MemoryLimitExceeded:         func() { primaryCalls++ },
		FallbackMemoryLimitExceeded: func() { fallbackCalls++ },
	})
	b.reserveOutputMemory(limit + 1)
	first := b.extractFallback("<p>first evidence</p>")
	if first.Text != "first evidence" || first.HTMLMemoryLimitExceeded || b.fallback.memory.Limit() != limit {
		t.Fatalf("first=%+v", first)
	}
	used := b.fallback.memory.Used()
	second := b.extractFallback("<p>second evidence</p>")
	if second.Text != "second evidence" || b.fallback.memory.Used() <= used || admissions != 1 || primaryCalls != 1 || fallbackCalls != 0 || b.memoryBytesRemaining != 0 {
		t.Fatalf("second=%+v budget=%+v", second, b)
	}
	if b.reserveOutputMemory(limit) {
		t.Fatal("fallback allowance unexpectedly reset")
	}
	b.observeFallback()
	b.observeFallback()
	if !b.fallbackMemoryExceeded || fallbackCalls != 1 || primaryCalls != 1 {
		t.Fatalf("callbacks primary=%d fallback=%d", primaryCalls, fallbackCalls)
	}
}

func TestFallbackMemoryFailuresAreNotCPUFailures(t *testing.T) {
	for _, source := range []string{
		strings.Repeat("x", 128<<10),
		`<p>prefix</p><a href="` + strings.Repeat("x", 128<<10) + `">link</a>`,
		strings.Repeat(`<a href="https://example.test/path">link</a><img src="cid:logo">`, 100),
	} {
		r := &fallbackResources{memory: resourceguard.NewMemory(8192)}
		got := extractBoundedHTMLFallback(source, true, r)
		if !got.HTMLMemoryLimitExceeded || !got.ExtractionIncomplete || got.HTMLCPULimitExceeded || r.memory.Used() > r.memory.Limit() {
			t.Fatalf("content=%+v used=%d", got, r.memory.Used())
		}
	}
}

func TestFallbackRetainsSafePrefixAtMemoryLimit(t *testing.T) {
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 8192})
	got := b.extractFallback("<p>safe prefix</p><a href=\"" + strings.Repeat("x", 128<<10) + "\">end</a>")
	normalizeExtractedUTF8(&got, b)
	if !strings.Contains(got.Text, "safe prefix") || !got.HTMLMemoryLimitExceeded || got.HTMLCPULimitExceeded {
		t.Fatalf("content=%+v", got)
	}
}

func TestFallbackDecodingUsesOwnLedger(t *testing.T) {
	b := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 64 << 10})
	if !b.beginFallback() {
		t.Fatal("admission failed")
	}
	primary := b.memoryBytesRemaining
	text, complete := decodeCharsetWithResources("", []byte("decoded text"), 100, b.decodingShouldStop, b.fallbackMemory)
	if !complete || text != "decoded text" || b.fallback.memory.Used() == 0 || b.memoryBytesRemaining != primary {
		t.Fatalf("text=%q complete=%v budget=%+v", text, complete, b)
	}
}
