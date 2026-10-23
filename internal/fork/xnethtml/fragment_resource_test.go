package html

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"io"
	"strings"
	"testing"
	"unsafe"

	a "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/atom"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type fragmentEOFReader struct {
	io.Reader
	onEOF func()
}

func (r fragmentEOFReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	if err == io.EOF {
		r.onEOF()
	}
	return n, err
}

func TestFragmentResultMemoryAdmission(t *testing.T) {
	const count = 1000
	source := strings.Repeat("<i></i>", count)
	context := &Node{Type: ElementNode, Data: "div", DataAtom: a.Div}
	var lastEOF int64
	parse := func(memory *resourceguard.Memory) ([]*Node, int64, error) {
		var beforeCollection int64
		r := fragmentEOFReader{strings.NewReader(source), func() { beforeCollection = memory.Used(); lastEOF = beforeCollection }}
		nodes, err := ParseFragmentWithOptions(r, context, ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
		return nodes, beforeCollection, err
	}
	memory := resourceguard.NewMemory(1 << 20)
	nodes, beforeCollection, err := parse(memory)
	if err != nil || len(nodes) != count {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
	if charged := memory.Used() - beforeCollection; charged < int64(count)*int64(unsafe.Sizeof((*Node)(nil))) {
		t.Fatalf("result storage undercharged: %d bytes", charged)
	}
	for _, n := range nodes {
		if n.DataAtom != a.I || n.Parent != nil || n.PrevSibling != nil || n.NextSibling != nil {
			t.Fatal("fragment result not correctly detached")
		}
	}
	memory = resourceguard.NewMemory(beforeCollection + 1)
	nodes = nil
	expectTermination(t, termination.MemoryExceeded, func() { nodes, _, _ = parse(memory) })
	if lastEOF != beforeCollection || nodes != nil || !memory.Exhausted() {
		t.Fatalf("collection limit: eof=%d nodes=%d", lastEOF, len(nodes))
	}
}

func TestNilContextFragmentFormControls(t *testing.T) {
	for _, source := range []string{"<input>", "<select>", "Hello <select>world</select>"} {
		nodes, err := ParseFragmentWithOptions(strings.NewReader(source), nil)
		if err != nil {
			t.Errorf("ParseFragmentWithOptions(%q): %v", source, err)
			continue
		}
		if len(nodes) == 0 {
			t.Errorf("ParseFragmentWithOptions(%q) returned no nodes", source)
		}
	}
}

func TestFragmentResultCancellation(t *testing.T) {
	atEOF := false
	r := fragmentEOFReader{strings.NewReader(strings.Repeat("<i></i>", 1000)), func() { atEOF = true }}
	context := &Node{Type: ElementNode, Data: "div", DataAtom: a.Div}
	expectTermination(t, termination.CPUExceeded, func() {
		ParseFragmentWithOptions(r, context, ParseOptionResourceLimits(ResourceLimits{
			ShouldStop: func() {
				if atEOF {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			},
		}))
	})
	if !atEOF {
		t.Fatal("cancellation occurred before collection")
	}
}

func TestFragmentAncestorCancellation(t *testing.T) {
	context := &Node{Type: ElementNode, Data: "div", DataAtom: a.Div}
	for i := 0; i < 1000; i++ {
		parent := &Node{Type: ElementNode, Data: "div", DataAtom: a.Div}
		parent.AppendChild(context)
		context = parent
	}
	for context.FirstChild != nil {
		context = context.FirstChild
	}
	calls := 0
	atEOF := false
	r := fragmentEOFReader{strings.NewReader(""), func() { atEOF = true }}
	expectTermination(t, termination.CPUExceeded, func() {
		ParseFragmentWithOptions(r, context, ParseOptionResourceLimits(ResourceLimits{
			ShouldStop: func() {
				calls++
				if calls > 1 {
					termination.Fail(termination.Failure{Code: termination.CPUExceeded})
				}

				return
			},
		}))
	})
	if atEOF {
		t.Fatal("ancestor scan continued to reader")
	}
}
