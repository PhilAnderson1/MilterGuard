package message

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
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
	builder.WriteString("1234")
	if memory.Used() != 4 {
		t.Fatalf("first allocation: value=%q used=%d", builder.String(), memory.Used())
	}
	// Growing from four to eight bytes charges all eight bytes while the old
	// four-byte array can still be live. The 11-byte budget must reject it.
	expectTermination(t, termination.MemoryExceeded, func() { builder.appendByte('5') })
	if builder.String() != "1234" {
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
	expectTermination(t, termination.MemoryExceeded, func() {
		output.write(outputAnnotation{kind: "concealed", reason: "display:none"}, "x")
		output.renderAnnotations()
	})

	if !memory.Exhausted() {
		t.Fatal("annotated-output allocation did not exhaust the shared budget")
	}
}

func TestGuardedNormalizationPreservesInvalidUTF8Semantics(t *testing.T) {
	input := "a\xff\xfeb"
	want := normalizeHTMLText(input)
	memory := resourceguard.NewMemory(64)
	got := normalizeHTMLTextGuarded(input, memory)
	if got != want || got != "a�b" {
		t.Fatalf("normalization=%q want=%q", got, want)
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
	expectTermination(t, termination.MemoryExceeded, func() { extraction.render(TagHidden) })
	if !memory.Exhausted() {
		t.Fatal("missing exhaustion")
	}
}
