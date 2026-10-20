package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"runtime"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestEscapeDecodingAdmissionAndSemantics(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{`plain`, `plain`}, {`\72 ed`, `red`}, {`\0`, "\ufffd"},
		{`\110000`, "\ufffd"}, {`\1f600`, "😀"}, {"a\\\r\nb", "ab"},
		{`a\`, `a\`}, {`\g`, `g`},
	} {
		budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(1024)})

		if got := cssUnescapeWithBudget(tc.input, budget); got != tc.want {
			t.Fatalf("decode %q = %q; want %q", tc.input, got, tc.want)
		}

	}
	budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(1)})
	expectTermination(t, termination.MemoryExceeded, func() { cssUnescapeWithBudget(`\72 ed`, budget) })
}

func TestResourceHelpersObserveCancellation(t *testing.T) {
	for _, operation := range []string{"escaped", "plain", "comment", "reverse"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			budget := testCPUGuard(cpuGuard{shouldStop: func() {
				calls++
				if calls == 2 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			}})
			expectTermination(t, termination.CPUExceeded, func() {
				switch operation {
				case "escaped":
					cssUnescapeWithBudget(strings.Repeat(`\78`, 20000), budget)
				case "plain":
					cssUnescapeWithBudget(strings.Repeat("x", 60000), budget)
				case "comment":
					containsASCIIFoldWithBudget(strings.Repeat("x", 60000), "<style", budget)
				case "reverse":
					lastASCIIFoldIndexWithBudget(strings.Repeat("x", 60000), "<![endif]", budget)
				}
			})
			if calls != 2 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestResourceHelperAllocationAmplification(t *testing.T) {
	name := "--" + strings.Repeat(`\78`, 20000)
	cases := []struct {
		name  string
		input []byte
	}{
		{"escaped_variable", []byte("<style>:root{" + name + ":red}p{color:var(" + name + ")}</style>" + strings.Repeat("<p>x</p>", 1500))},
		{"media_clauses", []byte(strings.Repeat(`<link rel="stylesheet" href="x" media="`+strings.Repeat("x and ", 650)+`">`, 1200))},
		{"display_variable", []byte("<style>:root{--x:" + strings.Repeat("a", 1000) + "}p{display:var(--x)}</style>" + strings.Repeat("<p>x</p>", 40000))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			doc, err := Analyze(tc.input, DefaultLimits())
			runtime.ReadMemStats(&after)
			if err != nil {
				t.Fatal(err)
			}
			// These inputs used to allocate tens of MB or more, largely uncharged.
			// Leave room for runtime noise while catching renewed amplification.
			limit := uint64(16 << 20)
			if tc.name == "display_variable" {
				// The 40,000 elements need about 55 MB; the old copying check
				// added another 41 MB without charging it.
				limit = 64 << 20
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > limit {
				t.Fatalf("allocated %d; charged %d", allocated, doc.Usage.MemoryBytes)
			}
			if tc.name == "escaped_variable" && (len(doc.Text) != 1500 || doc.Text[0].Label != "visible") {
				t.Fatal("variable semantics changed")
			}
		})
	}
}

func TestMediaApplicabilityChargesTemporaryWork(t *testing.T) {
	memory := resourceguard.NewMemory(4096)
	s := sheet{memory: memory, cpu: testCPUGuard(cpuGuard{memory: memory})}
	expectTermination(t, termination.MemoryExceeded, func() {
		for i := 0; i < 100; i++ {
			s.mediaCanApply("screen and (min-width:1px)")
		}
	})
}
