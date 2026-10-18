package html

import (
	"bytes"
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
)

func TestWorkHelpersCancellation(t *testing.T) {
	for name, run := range map[string]func(*resourceGuard){
		"compare": func(g *resourceGuard) {
			compareStringWithGuard(strings.Repeat("a", 4096), strings.Repeat("a", 4096), g)
		},
		"trim":  func(g *resourceGuard) { trimWithGuard(strings.Repeat(" ", 4096), whitespace, g) },
		"index": func(g *resourceGuard) { indexAnyWithGuard(strings.Repeat("a", 4096), "\"", g) },
		"nul":   func(g *resourceGuard) { replaceNULBytes(bytes.Repeat([]byte{0}, 4096), g) },
		"reparent": func(g *resourceGuard) {
			src, dst := &Node{}, &Node{}
			for i := 0; i < 1000; i++ {
				src.AppendChild(&Node{})
			}
			reparentChildrenWithGuard(dst, src, g)
		},
	} {
		t.Run(name, func(t *testing.T) {
			g := &resourceGuard{limits: ResourceLimits{ShouldStop: func() bool { return true }}}
			defer func() {
				v, ok := recover().(resourceAbort)
				if !ok || v.err != ErrResourceStopped {
					t.Fatalf("%v", v)
				}
			}()
			run(g)
		})
	}
}

func TestNewlineConversionCannotSkipCheckpoints(t *testing.T) {
	for _, prefix := range []string{"", "a", strings.Repeat("a", 1023)} {
		t.Run(fmt.Sprint(len(prefix)), func(t *testing.T) {
			source := prefix + strings.Repeat("\r\n", 4096)
			want := prefix + strings.Repeat("\n", 4096)
			if got := string(convertNewlines([]byte(source))); got != want {
				t.Fatal("incorrect newline conversion")
			}
			g := &resourceGuard{limits: ResourceLimits{ShouldStop: func() bool { return true }}}
			defer func() {
				v, ok := recover().(resourceAbort)
				if !ok || v.err != ErrResourceStopped {
					t.Fatalf("expected cancellation, got %v", v)
				}
			}()
			convertNewlinesWithGuard([]byte(source), g)
		})
	}
}
func TestNULByteReplacementAdmissionAndSemantics(t *testing.T) {
	src := []byte{'a', 0, 0xff, 'b', 0}
	want := []byte{'a', 0xef, 0xbf, 0xbd, 0xff, 'b', 0xef, 0xbf, 0xbd}
	mem := resourceguard.NewMemory(int64(len(want)))
	if got := replaceNULBytes(src, &resourceGuard{limits: ResourceLimits{Memory: mem}}); !bytes.Equal(got, want) || mem.Used() != int64(len(want)) {
		t.Fatalf("%x used %d", got, mem.Used())
	}
	defer func() {
		if _, ok := recover().(resourceAbort); !ok {
			t.Fatal("missing admission")
		}
	}()
	replaceNULBytes(src, &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(1)}})
}
func TestChunkedStringSemantics(t *testing.T) {
	for _, a := range []string{"", strings.Repeat(" ", 2048) + "x  ", strings.Repeat("a", 2048) + "x"} {
		if got := trimWithGuard(a, whitespace, nil); got != strings.Trim(a, whitespace) {
			t.Fatal(got)
		}
		for _, b := range []string{a, a + "x", strings.Repeat("a", 2048) + "y"} {
			if compareStringWithGuard(a, b, nil) != strings.Compare(a, b) {
				t.Fatal("comparison")
			}
		}
	}
}

func TestReparentStopsDuringMove(t *testing.T) {
	src, dst := &Node{}, &Node{}
	for i := 0; i < 1000; i++ {
		src.AppendChild(&Node{})
	}
	calls := 0
	g := &resourceGuard{limits: ResourceLimits{ShouldStop: func() bool { calls++; return calls == 2 }}}
	func() {
		defer func() {
			if _, ok := recover().(resourceAbort); !ok {
				t.Fatal("no stop")
			}
		}()
		reparentChildrenWithGuard(dst, src, g)
	}()
	moved := 0
	for n := dst.FirstChild; n != nil; n = n.NextSibling {
		moved++
		if n.Parent != dst {
			t.Fatal("bad parent")
		}
	}
	if moved != 255 || src.FirstChild == nil {
		t.Fatalf("moved %d", moved)
	}
}
func TestNULStopsDuringOutput(t *testing.T) {
	calls := 0
	g := &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(1 << 20), ShouldStop: func() bool { calls++; return calls == 4 }}}
	defer func() {
		if _, ok := recover().(resourceAbort); !ok || calls != 4 {
			t.Fatalf("calls %d", calls)
		}
	}()
	replaceNULBytes(bytes.Repeat([]byte{0}, 4096), g)
}
