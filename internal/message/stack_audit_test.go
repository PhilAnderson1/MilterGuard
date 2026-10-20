package message

import (
	"net/url"
	"strings"
	"testing"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

func TestPrimaryDestinationsUseMemoryBudget(t *testing.T) {
	for _, raw := range []string{
		"https://example.test/" + strings.Repeat("x", 8192),
		"https://example.test/a\nb",
		"https://example.test/a\x01b",
	} {
		memory := resourceguard.NewMemory(1)
		e := htmlExtraction{memory: memory}
		expectTermination(t, termination.MemoryExceeded, func() { e.destination(raw) })
		if !memory.Exhausted() {
			t.Fatal("URL allocation bypassed ledger")
		}
	}
	memory := resourceguard.NewMemory(1)
	e := htmlExtraction{memory: memory}
	n := &xhtml.Node{Type: xhtml.ElementNode, Data: "base", Attr: []xhtml.Attribute{{Key: "href", Val: "https://example.test/"}}}
	expectTermination(t, termination.MemoryExceeded, func() { e.findBase(n) })
}

func TestPrimaryDestinationCleaningAndResolution(t *testing.T) {
	base, _ := url.Parse("https://example.test/root/")
	for _, tc := range []struct {
		input, want string
		valid       bool
	}{
		{" https://example.test/a\nb\tc\x00d ", "https://example.test/abcd", true},
		{"https://example.test/a\x01b", "https://example.test/a%01b", true},
		{"https://exa\x01mple.test/", "", false},
		{"../page", "https://example.test/page", true},
		{"https://example.test/\xff", "https://example.test/%EF%BF%BD", true},
		{"javascript:alert(1)", "", false},
		{"http:///missing-host", "", false},
	} {
		e := htmlExtraction{memory: resourceguard.NewMemory(1 << 20), base: base}
		got, valid := e.destination(tc.input)
		if got != tc.want || valid != tc.valid {
			t.Fatalf("%q: %q/%v, want %q/%v", tc.input, got, valid, tc.want, tc.valid)
		}
	}
	calls := 0
	e := htmlExtraction{memory: resourceguard.NewMemory(1 << 20), shouldStop: func() {
		calls++
		if calls == 3 {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}}
	expectTermination(t, termination.CPUExceeded, func() { e.destination("https://example.test/" + strings.Repeat("x", 100000)) })
}

func TestURLLabelsUseMemoryWithoutLinkCollection(t *testing.T) {
	text := "https://example.test/" + strings.Repeat("long-path/", 1000)
	memory := resourceguard.NewMemory(1)
	expectTermination(t, termination.MemoryExceeded, func() { rewritePlainTextURLs(text, true, nil, memory, nil) })
}

func TestMIMETypeParametersUseMemoryBudget(t *testing.T) {
	budget := newExtractionBudgetWithControl(HTMLProcessingControl{MemoryBytes: 4096, StopOnMemoryLimit: true})
	result := extractMIMEWithBudget("text/plain; name="+strings.Repeat("x", 8192), "", "", nil, 0, budget)
	if !result.HTMLMemoryLimitExceeded || !result.incomplete() {
		t.Fatalf("uncharged MIME parameters: %+v", result)
	}
}

func TestGuardedMarkdownEscaping(t *testing.T) {
	value := `a\[b](c) <d>`
	for _, urlMode := range []bool{false, true} {
		memory := resourceguard.NewMemory(1)
		expectTermination(t, termination.MemoryExceeded, func() { escapeMarkdown(value, urlMode, memory, nil) })
		memory = resourceguard.NewMemory(1 << 20)
		want := markdownURL(value)
		if !urlMode {
			want = strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`).Replace(value)
		}
		if got := escapeMarkdown(value, urlMode, memory, nil); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestPrimaryImageReferenceCollectionIsCharged(t *testing.T) {
	extract := func(unique bool) (extractedContent, int64) {
		var source strings.Builder
		for i := 0; i < 80; i++ {
			id := "image00"
			if unique {
				id = "image" + string(byte('A'+i/26)) + string(byte('a'+i%26))
			}
			source.WriteString(`<img src="cid:` + id + `">`)
		}
		budget := newExtractionBudget()
		result, complete := runExtraction(budget, func() extractedContent { return htmlToTextWithBudget(source.String(), budget) })
		if !complete || result.HTMLFallbackUsed {
			t.Fatal("primary extraction failed")
		}
		return result, budget.primaryMemory.Used()
	}
	duplicate, duplicateBytes := extract(false)
	unique, uniqueBytes := extract(true)
	if len(duplicate.ImageRefs) != 1 || len(unique.ImageRefs) != 80 {
		t.Fatal("incorrect CID collection")
	}
	// Input and rendered-output lengths are identical. Unique references must
	// charge their additional retained slice/table storage on the primary ledger.
	if uniqueBytes <= duplicateBytes {
		t.Fatalf("unique references were uncharged: %d <= %d", uniqueBytes, duplicateBytes)
	}
}
