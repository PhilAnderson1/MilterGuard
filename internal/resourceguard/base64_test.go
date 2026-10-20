package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"testing"
)

func TestBase64AdmitsSourceAndOutput(t *testing.T) {
	// Three output bytes alone fit, but the four-byte source conversion must
	// also be covered even when the compiler happens to eliminate that copy.
	expectTermination(t, termination.MemoryExceeded, func() { DecodeBase64(NewMemory(3), "YWJj") })
	memory := NewMemory(7)
	got, err := DecodeBase64(memory, "YWJj")
	if err != nil || string(got) != "abc" || memory.Used() != 7 {
		t.Fatalf("output=%q err=%v charged=%d", got, err, memory.Used())
	}
	if _, err := DecodeBase64(NewMemory(64), "!!!!"); err == nil {
		t.Fatal("invalid base64 no longer returns an ordinary error")
	}
}
