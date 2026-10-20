package resourceguard

import (
	"regexp"
	"strings"
	"testing"
)

func TestRegexpReaderAdmission(t *testing.T) {
	re := regexp.MustCompile("needle")
	reader := strings.NewReader("hay needle stack")
	memory := NewMemory(1)
	if match, ok := RegexpFindReaderIndex(memory, re, reader); ok || match != nil || !memory.Exhausted() || reader.Len() != len("hay needle stack") {
		t.Fatal("regexp searched before memory admission")
	}
	memory = NewMemory(4096)
	match, ok := RegexpFindReaderIndex(memory, re, reader)
	if !ok || len(match) != 2 || match[0] != 4 || match[1] != 10 || memory.Used() == 0 {
		t.Fatalf("guarded regexp result=%v complete=%v charged=%d", match, ok, memory.Used())
	}
}
