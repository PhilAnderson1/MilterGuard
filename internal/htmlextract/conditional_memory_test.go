package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"testing"

	html "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestConditionalStylesShareDocumentMemory(t *testing.T) {
	input := []byte(strings.Repeat("<!--[if mso]><style></style><![endif]-->", 30000) + "<p>hello</p>")
	limits := DefaultLimits()
	var usage AnalysisUsage
	expectTermination(t, termination.MemoryExceeded, func() { AnalyzeControlled(input, limits, nil, &usage) })
	if !usage.MemoryLimitExceeded || usage.MemoryBytes > limits.MemoryBytes {
		t.Fatalf("usage=%+v", usage)
	}
}

func TestConditionalStyleAttributeAdmission(t *testing.T) {
	memory := resourceguard.NewMemory(16)
	var style html.Node
	{
		retainConditionalStyleAttribute(&style, []byte("ignored"), []byte(strings.Repeat("x", 1024)), memory)
		if memory.Used() != 0 {
			t.Fatal("ignored attribute consumed memory")
		}
	}
	expectTermination(t, termination.MemoryExceeded, func() {
		retainConditionalStyleAttribute(&style, []byte("media"), []byte(strings.Repeat("x", 1024)), memory)
	})
	if !memory.Exhausted() || len(style.Attr) != 0 {
		t.Fatal("attribute retained before admission")
	}
}

func TestConditionalStyleTextAdmission(t *testing.T) {
	// The tokenizer and source fit, but the collected CSS text does not.
	memory := resourceguard.NewMemory(6000)
	s := sheet{limits: DefaultLimits(), memory: memory}
	expectTermination(t, termination.MemoryExceeded, func() {
		s.parseMSOConditionalStyles("[if mso]><style>" + strings.Repeat(" ", 3000) + "</style><![endif]")
	})
	if !memory.Exhausted() || s.cssBytes != 0 {
		t.Fatalf("exhausted=%v css=%d", memory.Exhausted(), s.cssBytes)
	}
}
