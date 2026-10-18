package cascadia

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
		if _, err := ParseGroupWithMemory(source, memory); err == nil || !memory.Exhausted() {
			t.Fatal("source-only budget admitted structures")
		}
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
		if _, err := MetadataWithMemory(group[0], tight); err == nil || !tight.Exhausted() {
			t.Fatal("metadata bypassed budget")
		}
	}
}
func TestSelectorCompilationSharesBudget(t *testing.T) {
	memory := resourceguard.NewMemory(2000)
	for i := 0; i < 100; i++ {
		_, err := ParseGroupWithMemory(`p.notice:not(.hidden)`, memory)
		if err != nil {
			if !memory.Exhausted() {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("compilation reset the shared budget")
}
func TestShortAttributeMatchesSampleClock(t *testing.T) {
	group, _ := ParseGroup(`.notice`)
	n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: "notice"}}}
	calls := 0
	ctrl := NewMatchControl(func() bool { calls++; return false })
	for i := 0; i < 1000; i++ {
		matched, stopped := ctrl.Match(group, n)
		if !matched || stopped {
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
		ctrl := NewMatchControl(func() bool { calls++; return calls == 2 })
		matched, stopped := ctrl.Match(group, n)
		if matched || !stopped || calls != 2 {
			t.Fatalf("%s: matched=%v stopped=%v calls=%d", test.selector, matched, stopped, calls)
		}
		if _, stopped := ctrl.Match(group, n); !stopped {
			t.Fatal("stop was not latched")
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
		matched, stopped := ctrl.Match(group, n)
		if !matched || stopped {
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
			matched, stopped := NewMatchControl(func() bool { return false }).Match(group, n)
			if !matched || stopped {
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
	if _, err := MetadataWithMemory(group[0], memory); err == nil || !memory.Exhausted() {
		t.Fatal("positive matcher array escaped metadata admission")
	}
}
