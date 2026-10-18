package htmlextract

import (
	"runtime"
	"strings"
	"testing"
)

func TestGrowingMapsStayWithinAllocationBudget(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		limit       int64
	}{
		{"element metadata", strings.Repeat(strings.Repeat("<div>", 15)+"<p>x</p>"+strings.Repeat("</div>", 15), 15000), 64 << 20},
		{"selector caches", "<style>.x .y .z{color:red}@media(min-width:500px){body{opacity:.9}}</style>" + strings.Repeat("<div class=x><div class=y><p class=z>x</p></div></div>", 20000), 32 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)
			limits := DefaultLimits()
			limits.MemoryBytes = tc.limit
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			doc, err := Analyze(input, limits)
			runtime.ReadMemStats(&after)
			if err == nil || doc.Usage.MemoryBytes != tc.limit {
				t.Fatalf("expected memory cutoff: charged=%d err=%v", doc.Usage.MemoryBytes, err)
			}
			// Allow unrelated runtime bookkeeping; the budget remains an estimate.
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(tc.limit)+(2<<20) {
				t.Fatalf("allocated=%d budget=%d", allocated, tc.limit)
			}
		})
	}
}
