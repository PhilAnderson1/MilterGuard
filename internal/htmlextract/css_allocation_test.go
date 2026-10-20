package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Exercise cumulative allocation, including tiny scopes and parser sessions
// whose fixed costs can dominate their input and entry counts.
func TestCSSFixedAllocationBudget(t *testing.T) {
	responsiveCSS := "p{--a:var(--missing,0)}@media(prefers-color-scheme:dark){p{--a:1}}"
	for i := 1; i <= 20; i++ {
		responsiveCSS += fmt.Sprintf("@media(min-width:%dpx){body{opacity:.9}}", i*50)
	}
	for _, tc := range []struct {
		name, input   string
		limit         int64
		allowComplete bool
	}{
		{"responsive variable scopes", "<style>" + responsiveCSS + "</style>" + strings.Repeat("<p>x</p>", 4000), 64 << 20, false},
		{"literal scopes", "<style>p{--x:0}</style>" + strings.Repeat("<p>x</p>", 100000), 64 << 20, false},
		{"colour dependent scopes", "<style>p{--x:0}@media(prefers-color-scheme:dark){p{--x:1}}</style>" + strings.Repeat("<p>x</p>", 100000), 64 << 20, false},
		{"value lexers", "<style>:root{--x:rect(0,0,0,0)}p{clip:var(--x)}</style>" + strings.Repeat("<p>x</p>", 80000), 64 << 20, false},
		{"relative line heights", "<style>p{font-size:17px;line-height:163%}</style>" + strings.Repeat("<p>x</p>", 100000), 32 << 20, true},
		{"conditional margin alternatives", "<style>p{margin:.8ex}</style><!--[if mso]><style>p{margin:0!important}</style><![endif]-->" + strings.Repeat("<p>x</p>", 100000), 32 << 20, true},
		{"gradient clipping", strings.Repeat("<div style='background:linear-gradient(red,blue)'><p style='background:white'>x</p></div>", 30000), 32 << 20, false},
		{"inline parsers", strings.Repeat("<p style=' '>x</p>", 60000), 32 << 20, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)
			limits := DefaultLimits()
			limits.MemoryBytes = tc.limit
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, usage, err, failure := captureAnalysis(input, limits)
			runtime.ReadMemStats(&after)
			if err != nil || failure.Code == termination.None && !tc.allowComplete || failure.Code != termination.None && (failure.Code != termination.MemoryExceeded || usage.MemoryBytes != tc.limit) {
				t.Fatalf("expected memory cutoff: charged=%d err=%v", usage.MemoryBytes, err)
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			// Allow unrelated runtime bookkeeping; this is a regression bound, not an
			// assertion that the estimated budget is an exact process heap limit.
			if allocated > uint64(tc.limit)+2<<20 {
				t.Fatalf("allocated=%d, budget=%d", allocated, tc.limit)
			}
			t.Logf("allocated=%d, charged=%d", allocated, usage.MemoryBytes)
		})
	}
}

func TestClipCommaSyntaxDoesNotAllocateScratch(t *testing.T) {
	allocations := func(text string) float64 {
		return testing.AllocsPerRun(100, func() {
			value, status := resolveClip(clip, text, nil)
			if status != valueResolved || !value.Known || value.Number != 1 {
				t.Fatalf("unexpected clip result: %+v, %v", value, status)
			}
		})
	}
	// Both spellings have the same token count and input length. Only the comma
	// spelling needs to collect non-separator arguments into scratch storage.
	if comma, whitespace := allocations("rect(0,0,0,0)"), allocations("rect(0 0 0 0)"); comma != whitespace {
		t.Fatalf("comma syntax allocated %g times; whitespace syntax %g", comma, whitespace)
	}
}

func TestStaticCSSValueRejectsFailedCopy(t *testing.T) {
	tokens := []css.Token{
		{TokenType: css.WhitespaceToken, Data: []byte(" ")},
		{TokenType: css.IdentToken, Data: []byte("red")},
	}
	for _, reason := range []string{"memory", "cancellation"} {
		t.Run(reason, func(t *testing.T) {
			budget := testCPUGuard(cpuGuard{})
			if reason == "memory" {
				budget.memory = resourceguard.NewMemory(1)
			} else {
				{
					{
						budget.shouldStop = func() {
							{
								termination.Fail(termination.Failure{Code: termination.CPUExceeded})
							}

							return
						}
					}
				}
			}
			code := termination.CPUExceeded
			if reason == "memory" {
				code = termination.MemoryExceeded
			}
			expectTermination(t, code, func() {
				text := rawTokenStringWithBudget(tokens, budget)
				parseUnretainedCSSTokensWithBudget(tokens, text, budget)
			})
		})
	}
}

func TestInlineCSSMemoryBoundaryUnwinds(t *testing.T) {
	input := []byte("<p style='color:red'>x</p>")
	// Sweep the small-document allocation boundaries rather than depending on
	// one Go version's object sizes to exhaust memory during the value copy.
	for limit := int64(4096); limit < 40000; limit++ {
		limits := DefaultLimits()
		limits.MemoryBytes = limit
		_, usage, err, failure := captureAnalysis(input, limits)
		if err != nil || failure.Code != termination.None && (failure.Code != termination.MemoryExceeded || usage.MemoryBytes != limit) {
			t.Fatalf("limit=%d charged=%d err=%v", limit, usage.MemoryBytes, err)
		}
	}
}
