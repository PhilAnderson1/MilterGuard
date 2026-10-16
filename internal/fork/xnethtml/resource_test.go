package html

import (
	"errors"
	"strconv"
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

func TestResourceStopDuringLargeToken(t *testing.T) {
	checks := 0
	_, err := ParseWithOptions(strings.NewReader(`<!--`+strings.Repeat("x", 5000)+`-->`), ParseOptionResourceLimits(ResourceLimits{ShouldStop: func() bool { checks++; return checks > 1 }}))
	if !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("err=%v", err)
	}
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

func TestUniqueAttributeStructuralMemoryIsCharged(t *testing.T) {
	used := func(source string) int64 {
		t.Helper()
		memory := resourceguard.NewMemory(1 << 20)
		if _, err := ParseWithOptions(strings.NewReader(source), ParseOptionResourceLimits(ResourceLimits{Memory: memory})); err != nil {
			t.Fatal(err)
		}
		return memory.Used()
	}

	var source strings.Builder
	source.WriteString("<div ")
	for i := range 100 {
		source.WriteString("data-")
		source.WriteString(strconv.Itoa(i))
		source.WriteString("=x ")
	}
	source.WriteString("></div>")

	withoutAttributes := used("<div></div>")
	withAttributes := used(source.String())
	if difference := withAttributes - withoutAttributes; difference < 100*64 {
		t.Fatalf("100 unique attributes added %d charged bytes, want at least %d", difference, 100*64)
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
