package html

import (
	"errors"
	"strings"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestSharedMemoryBudgetStopsTokenizerAndTreeBuilder(t *testing.T) {
	memory := resourceguard.NewMemory(512)
	_, err := ParseWithOptions(strings.NewReader(`<div `+strings.Repeat(`a=x `, 100)+`>text</div>`), ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) || !memory.Exhausted() {
		t.Fatalf("err=%v exhausted=%v", err, memory.Exhausted())
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
	_, err := ParseWithOptions(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() bool { checks++; return checks > 1 }}))
	if !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("err=%v", err)
	}
}

func TestTreeBuilderStopCheckIsSampled(t *testing.T) {
	checks := 0
	guard := resourceGuard{limits: ResourceLimits{ShouldStop: func() bool {
		checks++
		return false
	}}}
	for range 512 {
		guard.stop()
	}
	if checks != 3 {
		t.Fatalf("external stop checks = %d, want 3", checks)
	}
}

func TestTreeBuilderStopChecksExhaustedMemoryImmediately(t *testing.T) {
	memory := resourceguard.NewMemory(1)
	if memory.Reserve(2) {
		t.Fatal("memory budget did not become exhausted")
	}
	guard := resourceGuard{limits: ResourceLimits{Memory: memory}}
	defer func() {
		recovered := recover()
		abort, ok := recovered.(resourceAbort)
		if !ok {
			t.Fatalf("panic = %v, want resourceAbort", recovered)
		}
		var limitErr *ResourceLimitError
		if !errors.As(abort.err, &limitErr) || limitErr.Resource != "memory bytes" {
			t.Fatalf("limit error = %v", abort.err)
		}
	}()
	guard.stop()
}

func TestStandaloneTokenizerResourceStop(t *testing.T) {
	checks := 0
	z := NewTokenizerWithStop(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), func() bool {
		checks++
		return checks > 1
	})
	for z.Next() != ErrorToken {
	}
	if !errors.Is(z.Err(), ErrResourceStopped) {
		t.Fatalf("err=%v", z.Err())
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
