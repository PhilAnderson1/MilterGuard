package message

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"math/rand"
	"strings"
	"testing"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestAnnotationScannerMatchesRegexp(t *testing.T) {
	cases := []string{
		"hello <INVISIBLE x='1'>world</invisible>!",
		"< /invisible>keep</ invisible>",
		"<\tinvisible\n>keep</\r\finvisible>",
		"<invisible_x>keep<invisiblex><invisible-x>text",
		"<viſibility-uncertain>text</viſibility-uncertain>",
		"<invisible<visibility-uncertain>text",
		"<invisible never closed <hidden-content-stripped",
		"<<INVISIBLE>\xff text </invisible>",
	}
	for _, start := range []int{resourceguard.WorkChunk - 1, resourceguard.WorkChunk, 2*resourceguard.WorkChunk - 8} {
		cases = append(cases, strings.Repeat("a", start)+"<visibility-uncertain>text</visibility-uncertain>")
	}
	cases = append(cases, "<"+strings.Repeat(" ", 20000)+"invisible "+strings.Repeat("x", 20000)+">text</invisible>")
	rng := rand.New(rand.NewSource(41))
	pieces := []string{"text", "<", ">", "/", " ", "\t", "\r\n", "\f", "\v", "invisible", "INVISIBLE", "visibility-uncertain", "visibility-varies-by-viewport-size", "hidden-content-stripped", "viſibility-uncertain", "_", "x", "-", "é", "\xff", " attr=\"x\""}
	for range 10000 {
		var b strings.Builder
		for n := rng.Intn(100); n > 0; n-- {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		cases = append(cases, b.String())
	}
	for _, input := range cases {
		want := reservedAnnotation.ReplaceAllString(input, "")
		got := sanitizeSenderTextWithResources(input, resourceguard.NewMemory(1<<20), nil)
		if got != want {
			t.Fatalf("input=%q\nwant=%q\ngot=%q", input, want, got)
		}
	}
}

func TestAnnotationScannerAllocationAdmission(t *testing.T) {
	unchanged := "ordinary <b>text</b> and <invisible unfinished"
	memory := resourceguard.NewMemory(1)
	got := sanitizeSenderTextWithResources(unchanged, memory, nil)
	if memory.Used() != 0 || unsafe.StringData(got) != unsafe.StringData(unchanged) {
		t.Fatal("unchanged input was copied or charged")
	}
	input := "<invisible>" + strings.Repeat("a", 10000) + "</invisible>"
	expectTermination(t, termination.MemoryExceeded, func() { sanitizeSenderTextWithResources(input, memory, nil) })
	if !memory.Exhausted() {
		t.Fatal("missing exhaustion")
	}

	memory = resourceguard.NewMemory(1 << 20)
	got = sanitizeSenderTextWithResources(input, memory, nil)
	used := memory.Used()
	var expected strings.Builder
	resourceguard.GrowText(nil, &expected, len(input), nil)
	if len(got) != 10000 || used != int64(expected.Cap()) {
		t.Fatalf("expected one input-sized buffer: length=%d charged=%d", len(got), used)
	}
}

func TestAnnotationScannerCancelsAcrossLongTokens(t *testing.T) {
	for _, input := range []string{
		strings.Repeat("x", 100000),
		"<" + strings.Repeat(" ", 100000) + "invisible>",
		"<invisible " + strings.Repeat("x", 100000) + ">",
		"<invisible " + strings.Repeat("x", 100000),
	} {
		checks := 0
		expectTermination(t, termination.CPUExceeded, func() {
			sanitizeSenderTextWithResources(input, nil, func() {
				checks++
				if checks >= 3 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}
			})
		})
		if checks != 3 {
			t.Fatalf("checks=%d", checks)
		}
	}
}
