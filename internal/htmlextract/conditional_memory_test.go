package htmlextract

import (
	"strings"
	"testing"

	html "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestConditionalStylesShareDocumentMemory(t *testing.T) {
	input := []byte(strings.Repeat("<!--[if mso]><style></style><![endif]-->", 30000) + "<p>hello</p>")
	limits := DefaultLimits()
	doc, err := Analyze(input, limits)
	if err == nil || doc.Usage.MemoryBytes != limits.MemoryBytes {
		t.Fatalf("err=%v usage=%+v; want shared memory exhaustion", err, doc.Usage)
	}
}

func TestConditionalStyleAttributeAdmission(t *testing.T) {
	memory := resourceguard.NewMemory(16)
	var style html.Node
	if !retainConditionalStyleAttribute(&style, []byte("ignored"), []byte(strings.Repeat("x", 1024)), memory) || memory.Used() != 0 {
		t.Fatal("ignored attribute consumed memory")
	}
	if retainConditionalStyleAttribute(&style, []byte("media"), []byte(strings.Repeat("x", 1024)), memory) || !memory.Exhausted() || len(style.Attr) != 0 {
		t.Fatal("attribute retained before admission")
	}
}

func TestConditionalStyleTextAdmission(t *testing.T) {
	// The tokenizer and source fit, but the collected CSS text does not.
	memory := resourceguard.NewMemory(6000)
	s := sheet{limits: DefaultLimits(), memory: memory}
	s.parseMSOConditionalStyles("[if mso]><style>" + strings.Repeat(" ", 3000) + "</style><![endif]")
	if !memory.Exhausted() || !s.cascadeIncomplete || s.cssBytes != 0 {
		t.Fatalf("exhausted=%v incomplete=%v css=%d", memory.Exhausted(), s.cascadeIncomplete, s.cssBytes)
	}
}
