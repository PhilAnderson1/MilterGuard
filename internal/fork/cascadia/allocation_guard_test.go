package cascadia

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	html "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
	"unsafe"
)

func TestCompiledStructuresAreCharged(t *testing.T) {
	for _, source := range []string{strings.Repeat(".a", 1024), strings.TrimSpace(strings.Repeat("a ", 1024))} {
		memory := resourceguard.NewMemory(int64(len(source)))
		expectTermination(t, termination.MemoryExceeded, func() { ParseGroupWithMemory(source, memory) })
		memory = resourceguard.NewMemory(1 << 20)
		group, err := ParseGroupWithMemory(source, memory)
		if err != nil {
			t.Fatal(err)
		}
		compiled := memory.Used()
		metadata, err := MetadataWithMemory(group[0], memory)
		if err != nil || len(metadata.Compounds) == 0 || memory.Used() <= compiled {
			t.Fatalf("metadata: %v", err)
		}
		t.Logf("source=%d compilation=%d withMetadata=%d", len(source), compiled, memory.Used())
		tight := resourceguard.NewMemory(1)
		expectTermination(t, termination.MemoryExceeded, func() { MetadataWithMemory(group[0], tight) })
	}
}
func TestSelectorCompilationSharesBudget(t *testing.T) {
	memory := resourceguard.NewMemory(2000)
	expectTermination(t, termination.MemoryExceeded, func() {
		for i := 0; i < 100; i++ {
			if _, err := ParseGroupWithMemory(`p.notice:not(.hidden)`, memory); err != nil {
				t.Fatal(err)
			}
		}
	})
}
func TestShortAttributeMatchesSampleClock(t *testing.T) {
	group, _ := ParseGroup(`.notice`)
	n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "notice"}}}
	calls := 0
	ctrl := NewMatchControl(func() { calls++; return })
	for i := 0; i < 1000; i++ {
		matched := ctrl.Match(group, n)
		if !matched {
			t.Fatal("match changed")
		}
	}
	t.Logf("1000 short matches callback count=%d", calls)
	if calls == 0 || calls > 30 {
		t.Fatalf("short matches polled clock %d times", calls)
	}
}
func TestLongAttributeOperationsStopInsideScan(t *testing.T) {
	for _, test := range []struct{ selector, key, value string }{
		{`.needle`, "class", strings.Repeat("x", 8192) + " needle"},
		{`.needle`, "class", strings.Repeat("x ", 4096) + "needle"},
		{`[x*="needle" i]`, "x", strings.Repeat("x", 8192) + "needle"},
		{`[x*="needle"]`, "x", strings.Repeat("x", 8192) + "needle"},
		{`[x^=""]`, "x", strings.Repeat("\u2003", 8192)},
		{`[x="` + strings.Repeat("a", 8192) + `" i]`, "x", strings.Repeat("A", 8192)},
	} {
		group, err := ParseGroup(test.selector)
		if err != nil {
			t.Fatal(err)
		}
		n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: test.key, Val: test.value}}}
		calls := 0
		ctrl := NewMatchControl(func() {
			calls++
			if calls == 2 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}

			return
		})
		expectTermination(t, termination.CPUExceeded, func() { ctrl.Match(group, n) })
		if calls != 2 {
			t.Fatalf("%s: calls=%d", test.selector, calls)
		}
	}
}
func TestSubstringPreparationIsReused(t *testing.T) {
	group, err := ParseGroup(`[x*="` + strings.Repeat("a", 1023) + `b" i]`)
	if err != nil {
		t.Fatal(err)
	}
	n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "x", Val: strings.Repeat("A", 2048) + "b"}}}
	ctrl := NewMatchControl(nil)
	allocations := testing.AllocsPerRun(100, func() {
		matched := ctrl.Match(group, n)
		if !matched {
			t.Fatal("match changed")
		}
	})
	// Interface dispatch may allocate its group wrapper; a prefix table must not.
	if allocations > 1 {
		t.Fatalf("per-match allocations=%v", allocations)
	}
	table := group[0].(attrSelector).failure
	if len(table) != 1024 {
		t.Fatal("missing compiled prefix table")
	}
}
func TestSubstringCrossesSamplingBoundary(t *testing.T) {
	for _, flag := range []string{"", " i"} {
		group, _ := ParseGroup(`[x*="aab"` + flag + `]`)
		for _, value := range []string{strings.Repeat("x", 1023) + "aab", strings.Repeat("a", 2048) + "b"} {
			n := &html.Node{Type: html.ElementNode, Attr: []html.Attribute{{Key: "x", Val: value}}}
			matched := NewMatchControl(func() { return }).Match(group, n)
			if !matched {
				t.Fatal("lost boundary-spanning match")
			}
		}
	}
}

func TestSubstringTableAndPositiveMetadataAdmission(t *testing.T) {
	compile := func(operator string) int64 {
		m := resourceguard.NewMemory(1 << 20)
		_, err := ParseGroupWithMemory(`[x`+operator+`"`+strings.Repeat("a", 1024)+`" i]`, m)
		if err != nil {
			t.Fatal(err)
		}
		return m.Used()
	}
	prefix, substring := compile("^="), compile("*=")
	if substring-prefix != 1024*int64(unsafe.Sizeof(int(0))) {
		t.Fatalf("prefix table not independently charged: %d", substring-prefix)
	}
	group, err := ParseGroup(`.a.b:hover`)
	if err != nil {
		t.Fatal(err)
	}
	memory := resourceguard.NewMemory(int64(unsafe.Sizeof(CompoundMetadata{})))
	expectTermination(t, termination.MemoryExceeded, func() { MetadataWithMemory(group[0], memory) })
}
