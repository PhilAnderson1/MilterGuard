package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"math"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestCSSNumberRangeAndSyntax(t *testing.T) {
	inputs := []string{"0", "-0", "+.5", "1.7976931348623157e308", "1.7976931348623159e308", "1e309", "-1e309", "1e-999999", "-0e999999", strings.Repeat("0", 10000) + "1", "1" + strings.Repeat("0", 10000) + "e-10000", "0." + strings.Repeat("0", 10000) + "1e10001", "1e" + strings.Repeat("0", 10000) + "2"}
	for _, input := range inputs {
		want, _ := strconv.ParseFloat(input, 64)
		got, ok := parseCSSNumber(input, nil)
		if !ok || math.Float64bits(got) != math.Float64bits(want) {
			t.Fatalf("length=%d: got %g (%v), want %g", len(input), got, ok, want)
		}
		_, finite := number(input)
		if finite == math.IsInf(want, 0) {
			t.Fatalf("finite classification: %g", want)
		}
	}
	for _, input := range []string{"", ".", "1.", "1.e2", "--1", "1e", "1e+", "0x1p2", "NaN", "Inf", "1 2"} {
		if _, ok := parseCSSNumber(input, nil); ok {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestCSSNumberAdmissionAndCancellation(t *testing.T) {
	// Definite overflow never reaches ParseFloat or its error allocation.
	budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(1)})

	if v, ok := parseCSSNumber(strings.Repeat("9", 64000), budget); !ok || !math.IsInf(v, 1) || budget.memory.Exhausted() {
		t.Fatal("definite overflow was not detected before conversion")
	}

	// Borderline overflow requires conversion and must be admitted first.
	expectTermination(t, termination.MemoryExceeded, func() { parseCSSNumber("1.7976931348623159e308", budget) })
	calls := 0
	budget = testCPUGuard(cpuGuard{shouldStop: func() {
		calls++
		{
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}

		return
	}})
	expectTermination(t, termination.CPUExceeded, func() { numberWithBudget(strings.Repeat("9", 64000), budget) })
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestPreparedMathLiteralsKeepContext(t *testing.T) {
	source := "calc(2em + 10%)"
	ts, status := lexValue(source, nil)
	if status != valueResolved {
		t.Fatal(status)
	}
	literals := prepareMathLiterals(ts, nil)
	// Enough for the output strings, but not another conversion: reuse literals.
	budget := testCPUGuard(cpuGuard{memory: resourceguard.NewMemory(64)})
	for _, size := range []float64{10, 20} {
		parent := initialStyle
		parent[fontSize] = Value{Number: size, Known: true}
		value, status := evalPreparedMathTokens(fontSize, source, ts, literals, &parent, &initialStyle, budget)
		if status != valueResolved || value.Number != size*2.1 {
			t.Fatalf("value=%+v status=%v", value, status)
		}
	}
	if budget.memory.Exhausted() {
		t.Fatal("cached conversion charged again")
	}
}

func TestNumericOverflowAllocationAmplification(t *testing.T) {
	// Both obvious overflow and the boundary case that reaches ParseFloat
	// used to copy the enormous operand for every matched element.
	for _, operand := range []string{strings.Repeat("9", 64000), "1.8" + strings.Repeat("0", 64000) + "e308"} {
		input := []byte("<style>p{font-size:calc(" + operand + " * 1em)}</style>" + strings.Repeat("<p>x</p>", 2000))
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		doc, err := Analyze(input, DefaultLimits())
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
			t.Fatalf("allocated %d, charged %d", allocated, doc.Usage.MemoryBytes)
		}
		if len(doc.Text) != 2000 {
			t.Fatalf("got %d text nodes", len(doc.Text))
		}
	}
}
