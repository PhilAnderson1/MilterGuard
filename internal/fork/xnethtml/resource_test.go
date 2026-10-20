package html

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/atom"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestSharedMemoryBudgetStopsTokenizerAndTreeBuilder(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	expectTermination(t, termination.MemoryExceeded, func() {
		ParseWithOptions(strings.NewReader(`<div `+strings.Repeat(`a=x `, 100)+`>text</div>`), ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
	})
	if !memory.Exhausted() {
		t.Fatal("missing exhaustion")
	}
}

func TestOpenElementDepthLimitIsResourceError(t *testing.T) {
	_, err := Parse(strings.NewReader(strings.Repeat("<dl>", 511)))
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("err=%v, want ResourceLimitError", err)
	}
	if limitErr.Resource != "open elements" || limitErr.Limit != 512 {
		t.Fatalf("limit error = %+v", limitErr)
	}
}

func TestAttributeCountLimitIsResourceError(t *testing.T) {
	source := "<div " + strings.Repeat("a=x ", maxAttributesPerTag+1) + "></div>"
	_, err := Parse(strings.NewReader(source))
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("err=%v, want ResourceLimitError", err)
	}
	if limitErr.Resource != "attributes per tag" || limitErr.Limit != maxAttributesPerTag {
		t.Fatalf("limit error = %+v", limitErr)
	}

	withinLimit := "<div " + strings.Repeat("a=x ", maxAttributesPerTag) + "></div>"
	if _, err := Parse(strings.NewReader(withinLimit)); err != nil {
		t.Fatalf("tag at attribute limit rejected: %v", err)
	}
}

func TestDocumentAttributeCountLimitIsResourceError(t *testing.T) {
	attributes := strings.Repeat("a=x ", maxAttributesPerTag)
	withinLimit := strings.Repeat("<div "+attributes+"></div>", maxDocumentAttributes/maxAttributesPerTag)
	if _, err := Parse(strings.NewReader(withinLimit)); err != nil {
		t.Fatalf("document at attribute limit rejected: %v", err)
	}

	_, err := Parse(strings.NewReader(withinLimit + "<div a=x></div>"))
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("err=%v, want ResourceLimitError", err)
	}
	if limitErr.Resource != "document attributes" || limitErr.Limit != maxDocumentAttributes {
		t.Fatalf("limit error = %+v", limitErr)
	}
}

func TestDocumentNodeLimitIsResourceError(t *testing.T) {
	p := parser{nodeCount: maxDocumentNodes}
	defer func() {
		recovered := recover()
		abort, ok := recovered.(resourceAbort)
		if !ok {
			t.Fatalf("panic=%v, want resourceAbort", recovered)
		}
		var limitErr *ResourceLimitError
		if !errors.As(abort.err, &limitErr) || limitErr.Resource != "document nodes" || limitErr.Limit != maxDocumentNodes {
			t.Fatalf("limit error = %v", abort.err)
		}
	}()
	p.newNode(Node{Type: ElementNode, Data: "div"})
}

func TestResourceStopDuringLargeToken(t *testing.T) {
	checks := 0
	expectTermination(t, termination.CPUExceeded, func() {
		ParseWithOptions(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() {
			checks++
			if checks > 1 {
				termination.Fail(termination.Failure{Code: termination.CPUExceeded})
			}
		}}))
	})
	if checks != 2 {
		t.Fatalf("checks=%d", checks)
	}
}

func TestTreeBuilderStopCheckIsSampled(t *testing.T) {
	checks := 0
	guard := resourceGuard{limits: ResourceLimits{ShouldStop: func() { checks++ }}}
	guard.sampler = resourceguard.NewStopSampler(256, guard.limits.ShouldStop)
	for range 512 {
		guard.stop()
	}
	if checks != 2 {
		t.Fatalf("external checks=%d want 2", checks)
	}
}

func TestTreeBuilderAllocationTerminatesBeforeCPUCheckpoint(t *testing.T) {
	memory := resourceguard.NewMemory(1)
	checks := 0
	expectTermination(t, termination.MemoryExceeded, func() { memory.Reserve(2); checks++; t.Fatal("allocation returned") })
	if checks != 0 {
		t.Fatal("continued after memory refusal")
	}
}

func TestStandaloneTokenizerResourceStop(t *testing.T) {
	checks := 0
	z := NewTokenizerWithStop(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), func() {
		checks++
		if checks > 1 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	})
	expectTermination(t, termination.CPUExceeded, func() {
		for z.Next() != ErrorToken {
		}
	})
	if checks != 2 {
		t.Fatalf("checks=%d", checks)
	}
}

func TestAttributeContentIsChargedToMemoryBudget(t *testing.T) {
	used := func(value string) int64 {
		t.Helper()
		memory := resourceguard.NewMemory(1 << 20)
		_, err := ParseWithOptions(
			strings.NewReader(`<div data-value="`+value+`"></div>`),
			ParseOptionResourceLimits(ResourceLimits{Memory: memory}),
		)
		if err != nil {
			t.Fatal(err)
		}
		return memory.Used()
	}

	short := used("x")
	long := used(strings.Repeat("x", 2048))
	if difference := long - short; difference < 2047 {
		t.Fatalf("long attribute added %d charged bytes, want at least 2047", difference)
	}
}

func TestRepeatedHTMLAndBodyAttributeCachesAreIndependent(t *testing.T) {
	htmlNode := Node{Type: ElementNode, DataAtom: atom.Html, Data: "html", Attr: []Attribute{{Key: "lang", Val: "en"}}}
	bodyNode := Node{Type: ElementNode, DataAtom: atom.Body, Data: "body", Attr: []Attribute{{Key: "class", Val: "original"}}}
	p := parser{}
	for i := range 100 {
		p.copyAttributes(&htmlNode, Token{Attr: []Attribute{{Key: fmt.Sprintf("h%d", i), Val: "x"}}})
		p.copyAttributes(&bodyNode, Token{Attr: []Attribute{{Key: fmt.Sprintf("b%d", i), Val: "x"}}})
	}
	p.copyAttributes(&htmlNode, Token{Attr: []Attribute{{Key: "lang", Val: "replaced"}}})
	p.copyAttributes(&bodyNode, Token{Attr: []Attribute{{Key: "class", Val: "replaced"}}})

	if len(htmlNode.Attr) != 101 || len(bodyNode.Attr) != 101 {
		t.Fatalf("attribute counts: html=%d body=%d", len(htmlNode.Attr), len(bodyNode.Attr))
	}
	if htmlNode.Attr[0].Val != "en" || bodyNode.Attr[0].Val != "original" {
		t.Fatalf("original attributes were replaced: html=%q body=%q", htmlNode.Attr[0].Val, bodyNode.Attr[0].Val)
	}
	if p.htmlAttributeNames.Len() != 101 || p.bodyAttributeNames.Len() != 101 {
		t.Fatalf("cache sizes: html=%d body=%d", p.htmlAttributeNames.Len(), p.bodyAttributeNames.Len())
	}
}

func TestTagAccessAvoidsCopiesWithoutNUL(t *testing.T) {
	z := NewTokenizer(strings.NewReader(`<DIV KEY=value>`))
	if token := z.Next(); token != StartTagToken {
		t.Fatalf("token=%v, want %v", token, StartTagToken)
	}
	nameStart := z.data.start
	name, hasAttr := z.TagName()
	if !hasAttr || string(name) != "div" || &name[0] != &z.buf[nameStart] {
		t.Fatalf("name=%q hasAttr=%v; ordinary tag name was copied", name, hasAttr)
	}
	keyStart, valueStart := z.attr[0][0].start, z.attr[0][1].start
	key, value, more := z.TagAttr()
	if more || string(key) != "key" || string(value) != "value" {
		t.Fatalf("key=%q value=%q more=%v", key, value, more)
	}
	if &key[0] != &z.buf[keyStart] || &value[0] != &z.buf[valueStart] {
		t.Fatal("ordinary attribute key or value was copied")
	}
}
