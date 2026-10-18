package html

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestEntityVocabularyBoundAndDecoding(t *testing.T) {
	for name, r := range entity {
		if len(name) > longestEntityName {
			t.Fatalf("entity %q exceeds lookup bound", name)
		}
		if got := UnescapeString("&" + name); got != string(r) {
			t.Fatalf("%s: %q", name, got)
		}
	}
	for name, pair := range entity2 {
		if len(name) > longestEntityName {
			t.Fatalf("entity %q exceeds lookup bound", name)
		}
		if got := UnescapeString("&" + name); got != string(pair[:]) {
			t.Fatalf("%s: %q", name, got)
		}
	}
	for _, tc := range []struct {
		source, want string
		attribute    bool
	}{
		{"&not" + strings.Repeat("a", 10000), "¬" + strings.Repeat("a", 10000), false},
		{"&not" + strings.Repeat("a", 10000), "&not" + strings.Repeat("a", 10000), true},
		{"&notit=", "&notit=", true}, {"&not=", "&not=", true},
		{"&#0;&#x80;&nGt;", "�€≫⃒", false},
		{"&amp;&nGt;tail", "&≫⃒tail", false},
	} {
		if got := string(unescape([]byte(tc.source), tc.attribute)); got != tc.want {
			t.Fatalf("decode mismatch: got %.60q want %.60q", got, tc.want)
		}
	}
}

func TestDecoderStopsInsideToken(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("&nGt;", 2000), "&#" + strings.Repeat("0", 10000) + ";",
		"&" + strings.Repeat("a", 10000), "&amp;" + strings.Repeat("x", 10000),
		strings.Repeat("\r\n", 5000),
	} {
		for _, attribute := range []bool{false, true} {
			source := text
			if attribute {
				source = "<p title='" + text + "'>"
			}
			calls := 0
			decoding := false
			z := NewTokenizerWithStop(strings.NewReader(source), func() bool {
				if !decoding {
					return false
				}
				calls++
				return true
			})
			z.Next()
			decoding = true
			if attribute {
				z.TagName()
				_, val, more := z.TagAttr()
				if val != nil || more {
					t.Fatal("partial attribute escaped cancellation")
				}
			} else if value := z.Text(); value != nil {
				t.Fatal("partial text escaped cancellation")
			}
			if !errors.Is(z.Err(), ErrResourceStopped) || calls != 1 {
				t.Fatalf("attribute=%v calls=%d err=%v", attribute, calls, z.Err())
			}
			if z.Next() != ErrorToken || z.Token().Type != ErrorToken {
				t.Fatal("resource failure was not sticky")
			}
		}
	}
}

func TestDecoderExpansionAdmission(t *testing.T) {
	source := strings.Repeat("&nGt;", 200000)
	for _, limit := range []int64{1, int64(len(source)), 4 << 20} {
		input := []byte(source)
		memory := resourceguard.NewMemory(limit)
		g := &resourceGuard{limits: ResourceLimits{Memory: memory}}
		if limit < 4<<20 {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			expectMemoryAbort(t, func() { unescapeWithGuard(input, false, g) })
			runtime.ReadMemStats(&after)
			// A failing first reservation must not allocate a source-sized buffer;
			// a failing later one may allocate only the admitted first buffer.
			allowance := uint64(64 << 10)
			if limit > 1 {
				allowance += uint64(len(source))
			}
			if after.TotalAlloc-before.TotalAlloc > allowance {
				t.Fatalf("allocated %d before rejection, allowance %d", after.TotalAlloc-before.TotalAlloc, allowance)
			}
		} else {
			decoded := unescapeWithGuard(input, false, g)
			if len(decoded) != 1200000 || !utf8.Valid(decoded) {
				t.Fatal("wrong expanded output")
			}
			if memory.Used() != 3*int64(len(source)) {
				t.Fatalf("replacement arrays charged %d", memory.Used())
			}
		}
	}
}

func TestDiscardedTokensConsumeBudget(t *testing.T) {
	for _, source := range []string{
		strings.Repeat("</"+strings.Repeat("x", 4097)+">", 2000),
		strings.Repeat(strings.Repeat(" ", 10000)+"</ignored>", 100),
	} {
		memory := resourceguard.NewMemory(256 << 10)
		root, err := ParseWithOptions(strings.NewReader(source), ParseOptionResourceLimits(ResourceLimits{Memory: memory}))
		var limited *ResourceLimitError
		if root != nil || !errors.As(err, &limited) || limited.Resource != "memory bytes" {
			t.Fatalf("discarded tokens passed: %v", err)
		}
	}
}

func TestTokenCopiesAdmittedBeforeAllocation(t *testing.T) {
	for _, source := range []string{strings.Repeat("x", 1<<20), "</" + strings.Repeat("x", 1<<20) + ">", "<!--" + strings.Repeat("x", 1<<20) + "-->"} {
		z := NewTokenizer(strings.NewReader(source))
		z.Next()
		z.guard = &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(1)}}
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		token := z.Token()
		runtime.ReadMemStats(&after)
		if token.Type != ErrorToken || z.Err() == nil {
			t.Fatal("copy passed admission")
		}
		if after.TotalAlloc-before.TotalAlloc > 64<<10 {
			t.Fatal("token copied before reservation")
		}
	}
}

func TestNodeTransferDoesNotChargeSharedStrings(t *testing.T) {
	m := resourceguard.NewMemory(1 << 20)
	p := parser{guard: &resourceGuard{limits: ResourceLimits{Memory: m}}}
	n := p.newNode(Node{Type: ElementNode, Data: strings.Repeat("x", 10000), Attr: []Attribute{{Key: "x", Val: "y"}}})
	clone := p.cloneNode(n)
	want := int64(2*unsafe.Sizeof(Node{}) + unsafe.Sizeof(Attribute{}))
	if m.Used() != want || clone.Data != n.Data {
		t.Fatalf("charge=%d want=%d", m.Used(), want)
	}
}

func TestGuardedStringNormalization(t *testing.T) {
	for _, s := range []string{"unchanged", "A\u023a\xff\x00 B", strings.Repeat("A\x00 \n", 1000)} {
		if got := mapStringWithGuard(s, unicode.ToLower, nil); got != strings.ToLower(s) {
			t.Fatalf("lower mismatch %q", got)
		}
		for _, replacement := range []string{"", "�"} {
			if got := replaceNULString(s, replacement, nil); got != strings.ReplaceAll(s, "\x00", replacement) {
				t.Fatal("NUL replacement changed bytes")
			}
		}
	}
	calls := 0
	g := &resourceGuard{limits: ResourceLimits{ShouldStop: func() bool { calls++; return true }}}
	func() {
		defer func() {
			abort, ok := recover().(resourceAbort)
			if !ok || !errors.Is(abort.err, ErrResourceStopped) {
				t.Fatal("mapping did not stop")
			}
		}()
		mapStringWithGuard(strings.Repeat("A", 10000), unicode.ToLower, g)
	}()
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

// Exercise the decoder directly: an earlier newline-normalization checkpoint
// must not hide missing checkpoints in entity recognition or decoded output.
func TestEntityDecoderProgress(t *testing.T) {
	for _, source := range []string{
		strings.Repeat("&nGt;", 2000), "&#" + strings.Repeat("0", 10000) + ";",
		"&" + strings.Repeat("a", 10000), "&amp;" + strings.Repeat("x", 10000),
		strings.Repeat("x", 10000),
	} {
		for _, attribute := range []bool{false, true} {
			calls := 0
			g := &resourceGuard{limits: ResourceLimits{ShouldStop: func() bool { calls++; return true }}}
			func() {
				defer func() {
					abort, ok := recover().(resourceAbort)
					if !ok || !errors.Is(abort.err, ErrResourceStopped) {
						t.Fatalf("decoder failed to cancel: %v", abort)
					}
				}()
				unescapeWithGuard([]byte(source), attribute, g)
			}()
			if calls != 1 {
				t.Fatalf("decoder callbacks=%d", calls)
			}
		}
	}
}

func TestExpandedEntityLiteralSuffixGrowthIsAdmitted(t *testing.T) {
	source := []byte("&nGt;" + strings.Repeat("x", 4096))
	g := &resourceGuard{limits: ResourceLimits{Memory: resourceguard.NewMemory(int64(len(source)))}}
	// The first owned array fits; the extra output byte at the end does not.
	expectMemoryAbort(t, func() { unescapeWithGuard(source, false, g) })
}
