package parse

import (
	"errors"
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
			stopped := errors.New("stopped")
			calls := 0
			z.SetProgressCheck(func() error { calls++; return stopped })
			// Repeated short speculative scans never reach position 1024.
			for i := 0; i < 3; i++ {
				z.Move(256)
				rewind.run(z)
			}
			z.Move(255)
			if calls != 0 {
				t.Fatalf("premature checkpoint: %d calls", calls)
			}
			z.Move(1)
			if calls != 1 || z.Err() != stopped || z.Peek(0) != 0 {
				t.Fatalf("calls=%d err=%v", calls, z.Err())
			}
			z.SetProgressCheck(func() error { t.Fatal("called after stop"); return nil })
			z.Move(1024)
			if z.Err() != stopped {
				t.Fatalf("lost stop error: %v", z.Err())
			}
		})
	}
}

func TestProgressCountsRuneBytes(t *testing.T) {
	for _, runeText := range []string{"a", "æ", "†", "𐀀"} {
		t.Run(runeText, func(t *testing.T) {
			z := NewInputString(strings.Repeat(runeText, 2048))
			calls := 0
			z.SetProgressCheck(func() error { calls++; return nil })
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
