package htmlextract

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestGrowingStorageStaysWithinAllocationBudget(t *testing.T) {
	type allocationCase struct {
		name, input string
		limit       int64
	}
	cases := []allocationCase{
		{"element metadata", strings.Repeat(strings.Repeat("<div>", 15)+"<p>x</p>"+strings.Repeat("</div>", 15), 15000), 64 << 20},
		{"selector caches", "<style>.x .y .z{color:red}@media(min-width:500px){body{opacity:.9}}</style>" + strings.Repeat("<div class=x><div class=y><p class=z>x</p></div></div>", 20000), 32 << 20},
		{"selector plans", "<style>" + strings.Repeat("p,", 4095) + "p{color:red}</style><p>x</p>", 4 << 20},
	}
	// Ignored end tags separate tokenizer text tokens that merge into the same
	// DOM text node. Exercise ordinary and foster-parented table text.
	for _, prefix := range []string{"<p>", "<table>"} {
		input := prefix + strings.Repeat("x", 32769) + strings.Repeat("</unknown>x", 10000)
		cases = append(cases, allocationCase{"text merges/" + prefix, input, 64 << 20})
	}
	for _, tc := range []struct {
		name, part string
		limit      int64
	}{
		{"token copies", "</" + strings.Repeat("x", 32769) + ">", 4 << 20},
		{"NUL attribute keys", "<p a" + strings.Repeat("\x00", 10923) + "='x'>x</p>", 64 << 20},
		{"NUL comments", "<!--" + strings.Repeat("\x00", 10923) + "-->", 32 << 20},
		{"NUL foreign text", "<svg>" + strings.Repeat("\x00", 10923) + "</svg>", 32 << 20},
	} {
		input := strings.Repeat(tc.part, DefaultLimits().InputBytes/len(tc.part))
		cases = append(cases, allocationCase{tc.name, input, tc.limit})
	}
	for _, count := range []int{16, 29, 64} {
		var css strings.Builder
		css.WriteString("<style>p{")
		for i := 0; i < count; i++ {
			// Independent cycles populate all four maps; counts span small-map and
			// capacity transitions that expose cumulative growth undercounting.
			fmt.Fprintf(&css, "--v%d:var(--v%d);", i, i)
		}
		css.WriteString("}</style>")
		cases = append(cases, allocationCase{fmt.Sprintf("variable graph/%d", count), css.String() + strings.Repeat("<p>x</p>", 10000), 64 << 20})
	}

	// Literal scopes bypass the dependency graph. Exercise larger map capacity
	// boundaries without colour dependencies supplying an additional allowance.
	for _, count := range []int{449, 897} {
		var css strings.Builder
		css.WriteString("<style>p{")
		for i := 0; i < count; i++ {
			fmt.Fprintf(&css, "--v%d:0;", i)
		}
		css.WriteString("}</style>")
		cases = append(cases, allocationCase{fmt.Sprintf("literal variables/%d", count), css.String() + strings.Repeat("<p>x</p>", 2000), 64 << 20})
	}

	for _, count := range []int{15, 57} {
		var light, dark strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&light, "--v%d:0;", i)
			fmt.Fprintf(&dark, "--v%d:1;", i)
		}
		input := "<style>p{" + light.String() + "}@media(prefers-color-scheme:dark){p{" + dark.String() + "}}</style>" + strings.Repeat("<p>x</p>", 20000)
		cases = append(cases, allocationCase{fmt.Sprintf("colour variables/%d", count), input, 64 << 20})
	}
	for _, count := range []int{256, 4096} {
		var css strings.Builder
		css.WriteString("<style>")
		for i := 0; i < count; i++ {
			fmt.Fprintf(&css, "@media(min-width:%dpx){p{color:red}}", i)
		}
		css.WriteString("</style><p>x</p>")
		limit := int64(64 << 20)
		if count == 256 {
			limit = 1 << 20
		}
		cases = append(cases, allocationCase{fmt.Sprintf("media states/%d", count), css.String(), limit})
	}
	for _, tc := range cases {
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
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(tc.limit)+uint64(min(tc.limit/8, 2<<20)) {
				t.Fatalf("allocated=%d budget=%d", allocated, tc.limit)
			}
		})
	}
}
