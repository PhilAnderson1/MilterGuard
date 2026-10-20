package parse

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"testing"
)

func TestProgressCountsRereads(t *testing.T) {
	for _, rewind := range []struct {
		name string
		run  func(*Input)
	}{
		{"rewind", func(z *Input) { z.Rewind(0) }},
		{"negative move", func(z *Input) { z.Move(-z.Offset()) }},
		{"reset", func(z *Input) { z.Reset() }},
	} {
		t.Run(rewind.name, func(t *testing.T) {
			z := NewInputString(strings.Repeat("a", 2048))
			var failure termination.Failure
			calls := 0
			z.SetProgressCheck(func() { calls++; termination.Fail(termination.Failure{Code: termination.Cancelled}) })
			// Repeated short speculative scans never reach position 1024.
			for i := 0; i < 3; i++ {
				z.Move(256)
				rewind.run(z)
			}
			z.Move(255)
			if calls != 0 {
				t.Fatalf("premature checkpoint: %d calls", calls)
			}
			func() {
				defer termination.Recover(&failure)
				z.Move(1)
				t.Fatal("checkpoint returned after cancellation")
			}()
			if calls != 1 || failure.Code != termination.Cancelled {
				t.Fatalf("calls=%d failure=%+v", calls, failure)
			}
		})
	}
}

func TestProgressCountsRuneBytes(t *testing.T) {
	for _, runeText := range []string{"a", "æ", "†", "𐀀"} {
		t.Run(runeText, func(t *testing.T) {
			z := NewInputString(strings.Repeat(runeText, 2048))
			calls := 0
			z.SetProgressCheck(func() { calls++ })
			for z.Offset()+len(runeText) < 1024 {
				z.MoveRune()
			}
			if calls != 0 {
				t.Fatal("premature checkpoint")
			}
			z.MoveRune()
			if calls != 1 {
				t.Fatalf("got %d checkpoints at byte %d", calls, z.Offset())
			}
		})
	}
}
