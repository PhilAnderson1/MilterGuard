package html

import (
	"errors"
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
	"unsafe"
)

func TestOrdinaryAttributesParticipateInSharedBudget(t *testing.T) {
	var source strings.Builder
	source.WriteString("<div ")
	for i := 0; i < 4096; i++ {
		fmt.Fprintf(&source, "a%d=x ", i)
	}
	source.WriteString("></div>")
	for _, limit := range []int64{128 << 10, 4 << 20} {
		memory := resourceguard.NewMemory(limit)
		root, err := ParseWithOptions(strings.NewReader(source.String()), ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
		if limit == 128<<10 {
			var limited *ResourceLimitError
			if !errors.As(err, &limited) || !memory.Exhausted() || root != nil {
				t.Fatalf("small budget accepted attributes: %v", err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			n := root.FirstChild.LastChild.FirstChild
			if len(n.Attr) != 4096 {
				t.Fatalf("attribute count=%d", len(n.Attr))
			}
			if memory.Used() < 4096*int64(unsafe.Sizeof(Attribute{})) {
				t.Fatal("retained structures not charged")
			}
			t.Logf("attributes charged=%d", memory.Used())
		}
	}
}

func expectMemoryAbort(t *testing.T, action func()) {
	t.Helper()
	defer func() {
		v := recover()
		abort, ok := v.(resourceAbort)
		if !ok {
			t.Fatalf("panic=%v", v)
		}
		var limited *ResourceLimitError
		if !errors.As(abort.err, &limited) || limited.Resource != "memory bytes" {
			t.Fatalf("error=%v", abort.err)
		}
	}()
	action()
	t.Fatal("expected memory abort")
}
func TestTokenAttributeArrayReservedBeforeAllocation(t *testing.T) {
	z := NewTokenizer(strings.NewReader(`<div a=x b=y>`))
	if z.Next() != StartTagToken {
		t.Fatal(z.Err())
	}
	z.guard = &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(int64(2*unsafe.Sizeof(Attribute{})) - 1)}}
	if token := z.Token(); token.Type != ErrorToken || z.Err() == nil {
		t.Fatalf("token=%v err=%v", token.Type, z.Err())
	}
}
func TestTokenizerReusesNameMapAllowance(t *testing.T) {
	z := NewTokenizer(strings.NewReader(`<p a=x><p a=x>`))
	memory := resourceguard.NewMemory(1 << 20)
	z.guard = &resourceGuard{limits: ResourceLimits{Memory: memory}}
	z.Next()
	before := memory.Used()
	z.Next()
	// Only the new map-key copies allocate. Span and map capacity are reused;
	// attribute values still borrow input until Token() is requested.
	if delta := memory.Used() - before; delta != 2 {
		t.Fatalf("reused storage charged %d bytes", delta)
	}
}
func TestHTMLStackGrowthChargesCompleteReplacement(t *testing.T) {
	memory := resourceguard.NewMemory(1 << 20)
	g := &resourceGuard{limits: ResourceLimits{Memory: memory}}
	var stack []*Node
	stack = growResourceSlice(stack, 1, g)
	stack = append(stack, nil)
	first := memory.Used()
	stack = growResourceSlice(stack, 1, g)
	if memory.Used() != first+2*int64(unsafe.Sizeof((*Node)(nil))) {
		t.Fatal("replacement array charged only delta")
	}
	tight := &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(1)}}
	expectMemoryAbort(t, func() { growResourceSlice([]*Node(nil), 1, tight) })
}
func TestDecodedAttributesAndClonesKeepOwnership(t *testing.T) {
	source := `<html lang="en"><html new="x"><body class="original"><body class="ignored" extra="y"><p><b title="a` + "\x00" + `b">T<div>U</b>V</div>`
	parse := func(guarded bool) *Node {
		var opts []ParseOption
		if guarded {
			opts = append(opts, ParseOptionResourceLimits(ResourceLimits{Memory: resourceguard.NewMemory(1 << 20)}))
		}
		n, e := ParseWithOptions(strings.NewReader(source), opts...)
		if e != nil {
			t.Fatal(e)
		}
		return n
	}
	var before, after strings.Builder
	if e := Render(&before, parse(false)); e != nil {
		t.Fatal(e)
	}
	if e := Render(&after, parse(true)); e != nil {
		t.Fatal(e)
	}
	if before.String() != after.String() {
		t.Fatal("guarded parsing changed recovery")
	}
}
