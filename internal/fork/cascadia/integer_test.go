package cascadia

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseIntegerBounds(t *testing.T) {
	const maxInt = int(^uint(0) >> 1)
	for _, tc := range []struct {
		source string
		want   int
	}{
		{"0", 0},
		{"00042", 42},
		{strings.Repeat("0", 16000) + "1", 1},
		{strconv.Itoa(maxInt), maxInt},
	} {
		p := parser{s: "xx" + tc.source + "n", i: 2}
		got, err := p.parseInteger()
		if err != nil || got != tc.want || p.i != 2+len(tc.source) {
			t.Fatalf("got=%d err=%v offset=%d want=%d", got, err, p.i, tc.want)
		}
	}
	for _, source := range []string{"", "n", strconv.FormatUint(uint64(maxInt)+1, 10), strconv.Itoa(maxInt) + "0", strings.Repeat("9", 16000)} {
		allocations := testing.AllocsPerRun(10, func() {
			p := parser{s: source}
			if _, err := p.parseInteger(); err != ErrInvalidSelector {
				t.Fatalf("got %v, want invalid selector", err)
			}
		})
		if allocations != 0 {
			t.Fatalf("rejected integer allocated %v times", allocations)
		}
	}
}

func TestNthIntegerOverflowReturnsSharedError(t *testing.T) {
	const maxInt = int(^uint(0) >> 1)
	if _, err := Parse(":nth-child(" + strconv.Itoa(maxInt) + ")"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{strconv.FormatUint(uint64(maxInt)+1, 10), strings.Repeat("9", 16000)} {
		for _, expression := range []string{value, "-" + value, "2n+" + value, "2n-" + value} {
			if _, err := Parse(":nth-child(" + expression + ")"); err != ErrInvalidSelector {
				t.Fatalf("got %v, want invalid selector", err)
			}
		}
	}
}
