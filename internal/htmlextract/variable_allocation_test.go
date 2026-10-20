package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestVariableBuilderChargesReplacementStorage(t *testing.T) {
	memory := resourceguard.NewMemory(10000)
	budget := testCPUGuard(cpuGuard{memory: memory})
	var out strings.Builder
	writeBudgetedString(&out, strings.Repeat("x", 64), budget)
	before := memory.Used()
	writeBudgetedString(&out, strings.Repeat("y", 128), budget)
	replacement := int64(out.Cap())
	if memory.Used()-before != replacement || out.String() != strings.Repeat("x", 64)+strings.Repeat("y", 128) {
		t.Fatalf("charged=%d want=%d length=%d", memory.Used()-before, replacement, out.Len())
	}
	limited := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(63)})
	var rejected strings.Builder
	expectTermination(t, termination.MemoryExceeded, func() { writeBudgetedString(&rejected, strings.Repeat("x", 64), limited) })
	if rejected.Cap() != 0 {
		t.Fatal("allocated output before admission")
	}
}

func TestBudgetedKeywordNormalization(t *testing.T) {
	for _, input := range []string{"", " \t\r\n\f", " Red ", "\u00a0RED\u00a0", "\xffA\x00", strings.Repeat("A", 10000), strings.Repeat(" ", 10000) + "X" + strings.Repeat(" ", 10000)} {
		memory := resourceguard.NewMemory(1 << 20)
		got := normalizeCSSKeywordWithBudget(input, testCPUGuard(cpuGuard{memory: memory}))
		want := normalizeCSSKeyword(input)
		if got != want {
			t.Fatalf("normalization mismatch for %d bytes", len(input))
		}
		wantCharge := int64(0)
		if want != trimCSSWhitespace(input) {
			var storage strings.Builder
			storage.Grow(len(want))
			wantCharge = int64(storage.Cap())
		}
		if memory.Used() != wantCharge {
			t.Fatalf("charged=%d want=%d", memory.Used(), wantCharge)
		}
	}
	memory := resourceguard.NewMemory(2)
	expectTermination(t, termination.MemoryExceeded, func() { normalizeCSSKeywordWithBudget("RED", testCPUGuard(cpuGuard{memory: memory})) })
}

func TestExpandedStringWorkChecksCancellation(t *testing.T) {
	for _, operation := range []string{"copy", "trim", "lower", "unchanged"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			budget := testCPUGuard(cpuGuard{shouldStop: func() {
				calls++
				if calls == 4 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			}})
			expectTermination(t, termination.CPUExceeded, func() {
				switch operation {
				case "copy":
					var out strings.Builder
					writeBudgetedString(&out, strings.Repeat("x", 64<<10), budget)
				case "trim":
					trimCSSWhitespaceWithBudget(strings.Repeat(" ", 64<<10), budget)
				case "lower":
					normalizeCSSKeywordWithBudget(strings.Repeat("X", 64<<10), budget)
				case "unchanged":
					normalizeCSSKeywordWithBudget(strings.Repeat("x", 64<<10), budget)
				}
			})
			if calls != 4 {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

func TestRepeatedVariableExpansionExhaustsMemory(t *testing.T) {
	input := []byte("<style>p{--x:" + strings.Repeat("a", 1000) + ";--y:" + strings.Repeat("var(--x)", 10000) + ";display:var(--y)}</style><p>hello</p>")
	limits := DefaultLimits()
	limits.MemoryBytes = 32 << 20
	var usage ResourceUsage
	expectTermination(t, termination.MemoryExceeded, func() { AnalyzeControlled(input, limits, nil, &usage) })
	if usage.MemoryBytes != limits.MemoryBytes {
		t.Fatalf("memory=%d", usage.MemoryBytes)
	}
}

func TestBuilderChargesExposedCapacity(t *testing.T) {
	memory := resourceguard.NewMemory(1 << 20)
	budget := testCPUGuard(cpuGuard{memory: memory})
	var out strings.Builder
	var want int64
	for _, text := range []string{" ", "hidden", " ", "!", strings.Repeat("x", 1000)} {
		grows := len(text) > out.Cap()-out.Len()
		writeBudgetedString(&out, text, budget)
		if grows {
			want += int64(out.Cap())
		}
		if memory.Used() != want {
			t.Fatalf("charged %d, want %d", memory.Used(), want)
		}
	}
}

func TestBuilderRejectsUnadmittedExtraCapacity(t *testing.T) {
	var probe strings.Builder
	probe.Grow(1)
	if probe.Cap() == 1 {
		t.Skip("runtime exposes no extra capacity for this request")
	}
	budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(1)})
	var out strings.Builder
	expectTermination(t, termination.MemoryExceeded, func() { writeBudgetedString(&out, "x", budget) })
	if !budget.memory.Exhausted() || out.Len() != 0 {
		t.Fatal("extra capacity used without admission")
	}
	var next strings.Builder
	expectTermination(t, termination.MemoryExceeded, func() { writeBudgetedString(&next, "x", budget) })
	if next.Cap() != 0 {
		t.Fatal("allocated again after reconciliation failed")
	}
}

func TestVariableDependencyEdgesCheckCancellation(t *testing.T) {
	for _, ref := range []string{"--a", "--missing"} {
		t.Run(ref, func(t *testing.T) {
			// Prepare outside the guarded operation so parsing cannot satisfy the
			// cancellation assertion on behalf of the dependency traversal.
			d := prepareDeclaration(declaration{custom: "--a", value: strings.Repeat("var("+ref+")", 4096)}, nil)
			calls := 0
			budget := testCPUGuard(cpuGuard{shouldStop: func() {
				calls++
				if calls == 2 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			}})
			expectTermination(t, termination.CPUExceeded, func() { buildVariables(nil, map[string]candidate{"--a": {d: &d}}, nil, budget) })
		})
	}
}

func TestVariableColourDependencyEdgesCheckCancellation(t *testing.T) {
	d := prepareDeclaration(declaration{custom: "--a", value: strings.Repeat("var(--missing)", 4096)}, nil)
	defs := map[string]candidate{"--a": {d: &d}}
	// Count the checks needed before colour analysis, then allow that work to
	// finish before requesting cancellation in the additional traversal.
	initialCalls := 0
	buildVariables(nil, defs, nil, testCPUGuard(cpuGuard{shouldStop: func() { initialCalls++; return }}))
	calls := 0
	budget := testCPUGuard(cpuGuard{shouldStop: func() {
		calls++
		if calls == initialCalls+2 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})
	expectTermination(t, termination.CPUExceeded, func() { buildVariables(nil, defs, map[string]bool{"--other": true}, budget) })
}
