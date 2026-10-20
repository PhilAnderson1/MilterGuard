package htmlextract

import (
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"math"
	"runtime"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestBudgetedFormatting(t *testing.T) {
	for _, v := range []float64{0, math.Copysign(0, -1), 1, .1, math.MaxFloat64, math.SmallestNonzeroFloat64, math.Inf(1)} {
		for _, unit := range []string{"", "px"} {
			got := numberStringWithBudget(v, unit, nil)

			if want := fmt.Sprintf("%g%s", v, unit); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}

		}
	}
	for _, c := range []RGBA{{0, 0, 0, 1}, {1, .5, .1, 0}, {math.SmallestNonzeroFloat64, .123456789, .987654321, .2}} {

		if got, want := colourStringWithBudget(c, nil), fmt.Sprintf("rgba(%g,%g,%g,%g)", c.R*255, c.G*255, c.B*255, c.A); got != want {
			t.Fatalf("got %q, want %q", got, want)
		}

	}
	for _, format := range []func(*cpuGuard) string{
		func(b *cpuGuard) string { return numberStringWithBudget(10, "px", b) },
		func(b *cpuGuard) string { return colourStringWithBudget(RGBA{0, 0, 0, 1}, b) },
	} {
		budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(1)})
		expectTermination(t, termination.MemoryExceeded, func() { format(budget) })
	}
}

func TestColourParsingDoesNotAllocateScratch(t *testing.T) {
	for _, text := range []string{"#abc", "#abcd", "#aabbccdd", "#ggg", "#１２３", "rgb(0,0,0)", "rgb(0 0 0 / 0)", "hsl(0 0% 0%)", "hwb(0 0% 0%)", "rgb(0,0,0,0,0)"} {
		if allocations := testing.AllocsPerRun(100, func() { readColourWithBudget(text, nil) }); allocations != 0 {
			t.Fatalf("%q: %g scratch allocations", text, allocations)
		}
	}
}

func TestRepeatedStyleAllocationBudget(t *testing.T) {
	for _, tc := range []struct {
		name, css string
		limit     uint64
	}{
		{"memo", "p{display:block}", 24 << 20},
		{"colour", ":root{--x:#000}p{color:var(--x);background-color:var(--x)}", 64 << 20},
		{"overflow", ":root{--x:hidden}p{overflow:var(--x)}", 40 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			css := tc.css
			for i := 1; i < 20; i++ {
				css += fmt.Sprintf("@media(min-width:%dpx){body{opacity:0.9}}", i*100)
			}
			input := []byte("<style>" + css + "</style>" + strings.Repeat("<p>x</p>", 40000))
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			doc, err := Analyze(input, DefaultLimits())
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Text) != 40000 {
				t.Fatalf("got %d text nodes", len(doc.Text))
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > tc.limit {
				t.Fatalf("allocated %d, charged %d", allocated, doc.Usage.MemoryBytes)
			}
		})
	}
}
