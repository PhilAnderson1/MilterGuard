package message

import (
	"strings"
	"testing"
	"unsafe"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestGuardedBuilderChargesCompleteReplacementAllocation(t *testing.T) {
	memory := resourceguard.NewMemory(11)
	builder := newGuardedBuilder(memory)
	if !builder.WriteString("1234") || memory.Used() != 4 {
		t.Fatalf("first allocation: value=%q used=%d", builder.String(), memory.Used())
	}
	// Growing from four to eight bytes charges all eight bytes while the old
	// four-byte array can still be live. The 11-byte budget must reject it.
	if builder.appendByte('5') || !builder.Failed() || builder.String() != "1234" {
		t.Fatalf("growth exceeded budget: value=%q used=%d", builder.String(), memory.Used())
	}
	if !memory.Exhausted() {
		t.Fatal("failed growth did not exhaust the shared budget")
	}
}

func TestAnnotatedOutputStopsBeforeUnbudgetedChunkAllocation(t *testing.T) {
	var sample outputChunk
	chunkBytes := int64(unsafe.Sizeof(sample))
	memory := resourceguard.NewMemory(chunkBytes)
	output := newAnnotatedOutput(memory)
	output.write(outputAnnotation{kind: "concealed", reason: "display:none"}, "x")
	if _, complete := output.String(); complete {
		t.Fatal("annotated output completed after its chunk allocation was rejected")
	}
	if !memory.Exhausted() {
		t.Fatal("annotated-output allocation did not exhaust the shared budget")
	}
}

func TestGuardedNormalizationPreservesInvalidUTF8Semantics(t *testing.T) {
	input := "a\xff\xfeb"
	want := normalizeHTMLText(input)
	memory := resourceguard.NewMemory(64)
	got, complete := normalizeHTMLTextGuarded(input, memory)
	if !complete || got != want || got != "a�b" {
		t.Fatalf("normalization=%q complete=%v want=%q", got, complete, want)
	}
}

func TestRenderStopsBeforeOverBudgetOutputAllocation(t *testing.T) {
	root := &xhtml.Node{Type: xhtml.DocumentNode}
	textNode := &xhtml.Node{Type: xhtml.TextNode, Data: strings.Repeat("x", 1024)}
	root.AppendChild(textNode)
	memory := resourceguard.NewMemory(128)
	extraction := htmlExtraction{
		inspection: htmlextract.Document{Root: root},
		states:     map[*xhtml.Node]*htmlextract.Text{textNode: {Node: textNode, Label: "visible"}},
		elements:   make(map[*xhtml.Node]*htmlextract.Element),
		memory:     memory,
	}
	got := extraction.render(TagHidden)
	if got.text != "" || !extraction.memoryExhausted || !extraction.extractionIncomplete {
		t.Fatalf("over-budget render=%+v extraction=%+v", got, extraction)
	}
}
