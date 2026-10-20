package htmlextract

import (
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestBoundedCSSWhitespaceComponents(t *testing.T) {
	for _, test := range []struct {
		input string
		limit int
		want  []string
	}{
		{" \t\r\n\f", 4, nil},
		{" 1px\t2px\r3px\n4px\f", 4, []string{"1px", "2px", "3px", "4px"}},
		{"1px 2px 3px 4px 5px", 4, nil},
		{"hidden auto", 2, []string{"hidden", "auto"}},
		{"hidden auto scroll", 2, nil},
		{"hidden auto", 1, nil},
		{"a\u00a0b", 1, []string{"a\u00a0b"}},
	} {
		if got := splitCSSWhitespace(test.input, make([]string, test.limit)); !slices.Equal(got, test.want) {
			t.Errorf("split(%q, %d) = %q; want %q", test.input, test.limit, got, test.want)
		}
	}
}

func TestColourComponentLimits(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"rgb(1,2,3)", true},
		{"rgba(1,2,3,.5)", true},
		{"rgb(1 2 3 / .5)", true},
		{"hsl(0 0% 0% / .5)", true},
		{"hwb(0 0% 0% / .5)", true},
		{"rgb(1,2,3,4,5)", false},
		{"rgb(1,2,3,)", false},
		{"rgb(1 2 3 4)", false},
		{"rgb(1 2 3 / .5 .5)", false},
		{"rgb(1 2 3 / .5 / .5)", false},
	} {
		_, status := readColour(test.value)
		if status == valueResolved != test.valid {
			t.Errorf("readColour(%q) status = %v; valid = %v", test.value, status, test.valid)
		}
	}
}

func TestExcessComponentsHaveBoundedAllocation(t *testing.T) {
	// Inputs are constructed outside the measurement. The old split-all paths
	// allocate megabytes of string headers before rejecting these values.
	commas := "rgb(" + strings.Repeat(",", 1<<20) + ")"
	spaces := strings.Repeat("0 ", 1<<19)
	spaceColour := "rgb(" + spaces + ")"
	alphaColour := "rgb(0 0 0 / " + spaces + ")"
	check := func() {
		for _, colour := range []string{commas, spaceColour, alphaColour} {
			if _, status := readColour(colour); status != valueInvalid {
				t.Fatal("excess colour components were not rejected")
			}
		}
		if _, ok, _ := marginShorthandValues(spaces); ok {
			t.Fatal("excess margin components were not rejected")
		}
		if _, ok, _ := overflowShorthandValues(spaces); ok {
			t.Fatal("excess overflow components were not rejected")
		}
		if _, status := resolveLayoutProperty(overflowX, spaces); status != valueInvalid {
			t.Fatal("excess overflow longhand components were not rejected")
		}
	}
	check()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range 8 {
		check()
	}
	runtime.ReadMemStats(&after)
	// Leave ample room for incidental runtime allocation while rejecting the
	// input-proportional arrays (tens of megabytes per iteration) being fixed.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("component rejection allocated %d bytes", allocated)
	}
}

func TestOverflowParsingDoesNotAllocateScratch(t *testing.T) {
	for _, value := range []string{"hidden", " hidden auto ", "hidden auto scroll"} {
		if allocations := testing.AllocsPerRun(100, func() {
			overflowShorthandValues(value)
			resolveLayoutProperty(overflowX, value)
		}); allocations != 0 {
			t.Fatalf("%q: %g scratch allocations", value, allocations)
		}
	}
}
