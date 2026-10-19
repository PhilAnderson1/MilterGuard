package cascadia

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestLanguageLowercaseAccounting(t *testing.T) {
	for _, source := range []string{"", "en-us", "EN-US", "ȺİK", "\ufffd", "\xff", strings.Repeat("\xff", 4096)} {
		t.Run(source[:min(len(source), 12)], func(t *testing.T) {
			want := strings.ToLower(source)
			memory := resourceguard.NewMemory(int64(len(want)) + 4096)
			p := parser{memory: memory}
			if got := p.lowerUnicode(source); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
			charged := int64(0)
			if source != want {
				var b strings.Builder
				b.Grow(len(want))
				charged = int64(b.Cap())
			}
			if memory.Used() != charged || memory.Exhausted() {
				t.Fatalf("charged=%d want=%d exhausted=%v", memory.Used(), charged, memory.Exhausted())
			}
			// With accounting disabled the only allocation is the output buffer.
			p.memory = nil
			allocs := testing.AllocsPerRun(10, func() { _ = p.lowerUnicode(source) })
			maxAllocs := float64(0)
			if source != want {
				maxAllocs = 1
			}
			if allocs > maxAllocs {
				t.Fatalf("got %v allocations, want at most %v", allocs, maxAllocs)
			}
			if charged > 0 {
				p.memory = resourceguard.NewMemory(charged - 1)
				defer func() {
					if _, ok := recover().(allocationAbort); !ok || !p.memory.Exhausted() {
						t.Fatal("missing allocation admission failure")
					}
				}()
				p.lowerUnicode(source)
			}
		})
	}
}

func TestLanguageSelectorAdmitsLowercaseCopy(t *testing.T) {
	memory := resourceguard.NewMemory(1 << 20)
	if _, err := ParseGroupWithMemory(":lang(en-us)", memory); err != nil {
		t.Fatal(err)
	}
	baseline := memory.Used()
	if _, err := ParseGroupWithMemory(":lang(EN-US)", resourceguard.NewMemory(baseline)); err != errSelectorMemory {
		t.Fatalf("missing lowercase admission: %v", err)
	}
	memory = resourceguard.NewMemory(baseline + 8)
	group, err := ParseGroupWithMemory(":lang(EN-US)", memory)
	if err != nil || len(group) != 1 || group[0].String() != ":lang(en-us)" || memory.Used() != baseline+8 {
		t.Fatalf("compiled=%v err=%v charged=%d", group, err, memory.Used())
	}
}
