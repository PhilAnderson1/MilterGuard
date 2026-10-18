package html

import (
	"errors"
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
	parse := func(memory *resourceguard.Memory) ([]*Node, int64, error) {
		var beforeCollection int64
		r := fragmentEOFReader{strings.NewReader(source), func() { beforeCollection = memory.Used() }}
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
	nodes, reachedEOF, err := parse(memory)
	var limited *ResourceLimitError
	if reachedEOF != beforeCollection || nodes != nil || !errors.As(err, &limited) || !memory.Exhausted() {
		t.Fatalf("collection limit: eof=%d nodes=%d err=%v", reachedEOF, len(nodes), err)
	}
}

func TestFragmentResultCancellation(t *testing.T) {
	atEOF := false
	r := fragmentEOFReader{strings.NewReader(strings.Repeat("<i></i>", 1000)), func() { atEOF = true }}
	context := &Node{Type: ElementNode, Data: "div", DataAtom: a.Div}
	nodes, err := ParseFragmentWithOptions(r, context, ParseOptionResourceLimits(ResourceLimits{
		ShouldStop: func() bool { return atEOF },
	}))
	if nodes != nil || !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
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
	nodes, err := ParseFragmentWithOptions(r, context, ParseOptionResourceLimits(ResourceLimits{
		ShouldStop: func() bool { calls++; return calls > 1 },
	}))
	if atEOF || nodes != nil || !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("eof=%v nodes=%d err=%v", atEOF, len(nodes), err)
	}
}
