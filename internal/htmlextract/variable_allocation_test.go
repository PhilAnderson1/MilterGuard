package htmlextract

import (
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestVariableBuilderChargesReplacementStorage(t *testing.T) {
	memory := resourceguard.NewMemory(10000)
	budget := &cpuGuard{memory: memory}
	var out strings.Builder
	if !writeBudgetedString(&out, strings.Repeat("x", 64), budget) {
		t.Fatal("initial write failed")
	}
	before := memory.Used()
	if !writeBudgetedString(&out, strings.Repeat("y", 128), budget) {
		t.Fatal("growth failed")
	}
	replacement := int64(out.Cap())
	if memory.Used()-before != replacement || out.String() != strings.Repeat("x", 64)+strings.Repeat("y", 128) {
		t.Fatalf("charged=%d want=%d length=%d", memory.Used()-before, replacement, out.Len())
	}
	limited := &cpuGuard{memory: resourceguard.NewMemory(63)}
	var rejected strings.Builder
	if writeBudgetedString(&rejected, strings.Repeat("x", 64), limited) || rejected.Cap() != 0 {
		t.Fatal("allocated output before admission")
	}
}

func TestBudgetedKeywordNormalization(t *testing.T) {
	for _, input := range []string{"", " \t\r\n\f", " Red ", "\u00a0RED\u00a0", "\xffA\x00", strings.Repeat("A", 10000), strings.Repeat(" ", 10000) + "X" + strings.Repeat(" ", 10000)} {
		memory := resourceguard.NewMemory(1 << 20)
		got, ok := normalizeCSSKeywordWithBudget(input, &cpuGuard{memory: memory})
		want := normalizeCSSKeyword(input)
		if !ok || got != want {
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
	if _, ok := normalizeCSSKeywordWithBudget("RED", &cpuGuard{memory: memory}); ok || !memory.Exhausted() {
		t.Fatal("normalization succeeded without allocation admission")
	}
}

func TestExpandedStringWorkChecksCancellation(t *testing.T) {
	for _, operation := range []string{"copy", "trim", "lower", "unchanged"} {
		t.Run(operation, func(t *testing.T) {
			calls := 0
			budget := &cpuGuard{shouldStop: func() bool { calls++; return calls == 4 }}
			var ok bool
			switch operation {
			case "copy":
				var out strings.Builder
				ok = writeBudgetedString(&out, strings.Repeat("x", 64<<10), budget)
			case "trim":
				_, ok = trimCSSWhitespaceWithBudget(strings.Repeat(" ", 64<<10), budget)
			case "lower":
				_, ok = normalizeCSSKeywordWithBudget(strings.Repeat("X", 64<<10), budget)
			case "unchanged":
				_, ok = normalizeCSSKeywordWithBudget(strings.Repeat("x", 64<<10), budget)
			}
			if ok || !budget.stopped || calls != 4 {
				t.Fatalf("ok=%v stopped=%v calls=%d", ok, budget.stopped, calls)
			}
		})
	}
}

func TestRepeatedVariableExpansionExhaustsMemory(t *testing.T) {
	input := []byte("<style>p{--x:" + strings.Repeat("a", 1000) + ";--y:" + strings.Repeat("var(--x)", 10000) + ";display:var(--y)}</style><p>hello</p>")
	limits := DefaultLimits()
	limits.MemoryBytes = 32 << 20
	doc, err := Analyze(input, limits)
	if err == nil || doc.Usage.MemoryBytes != limits.MemoryBytes {
		t.Fatalf("err=%v memory=%d; want memory exhaustion", err, doc.Usage.MemoryBytes)
	}
}

func TestBuilderChargesExposedCapacity(t *testing.T) {
	memory := resourceguard.NewMemory(1 << 20)
	budget := &cpuGuard{memory: memory}
	var out strings.Builder
	var want int64
	for _, text := range []string{" ", "hidden", " ", "!", strings.Repeat("x", 1000)} {
		grows := len(text) > out.Cap()-out.Len()
		if !writeBudgetedString(&out, text, budget) {
			t.Fatal("write failed")
		}
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
	budget := &cpuGuard{memory: resourceguard.NewMemory(1)}
	var out strings.Builder
	if writeBudgetedString(&out, "x", budget) || !budget.memory.Exhausted() || out.Len() != 0 || out.Cap() != 0 {
		t.Fatal("extra capacity was used without admission")
	}
	var next strings.Builder
	if writeBudgetedString(&next, "x", budget) || next.Cap() != 0 {
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
			budget := &cpuGuard{shouldStop: func() bool { calls++; return calls == 2 }}
			scope := buildVariables(nil, map[string]candidate{"--a": {d: &d}}, nil, budget)
			if !budget.stopped || !scope.allUnresolved {
				t.Fatal("repeated cyclic or missing dependencies bypassed cancellation")
			}
		})
	}
}

func TestVariableColourDependencyEdgesCheckCancellation(t *testing.T) {
	d := prepareDeclaration(declaration{custom: "--a", value: strings.Repeat("var(--missing)", 4096)}, nil)
	defs := map[string]candidate{"--a": {d: &d}}
	// Count the checks needed before colour analysis, then allow that work to
	// finish before requesting cancellation in the additional traversal.
	initialCalls := 0
	buildVariables(nil, defs, nil, &cpuGuard{shouldStop: func() bool { initialCalls++; return false }})
	calls := 0
	budget := &cpuGuard{shouldStop: func() bool { calls++; return calls == initialCalls+2 }}
	buildVariables(nil, defs, map[string]bool{"--other": true}, budget)
	if !budget.stopped {
		t.Fatal("repeated colour dependencies bypassed cancellation")
	}
}
