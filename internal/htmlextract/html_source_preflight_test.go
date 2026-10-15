package htmlextract

import (
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestSourceAttributeScanMatchesTokenizer(t *testing.T) {
	for _, source := range []string{
		`<p>`,
		`<p a b=c d = "x > y" / >`,
		`<p =foo bar>`,
		`<p a=b/c=d>`,
		`<p a='x' b disabled=>`,
	} {
		z := html.NewTokenizer(strings.NewReader(source))
		if token := z.Next(); token != html.StartTagToken && token != html.SelfClosingTagToken {
			t.Fatalf("%q token = %v", source, token)
		}
		_, more := z.TagName()
		want := 0
		for more {
			_, _, more = z.TagAttr()
			want++
		}

		var work int64
		got, err := sourceStartTagAttributes([]byte(source), 1, &work, 1<<20, nil)
		if err != nil || got != want {
			t.Fatalf("%q source attributes = %d, %v; tokenizer = %d", source, got, err, want)
		}
	}
}

func TestSourceAttributeScanRejectsDefaultLimitBeforeTokenizer(t *testing.T) {
	limits := DefaultLimits()
	source := `<p` + strings.Repeat(` a`, limits.Attributes+1) + `>`
	err := preflightStartTagAttributes([]byte(source), limits.Attributes, nil)
	if err == nil || !strings.Contains(err.Error(), "source tag attributes") {
		t.Fatalf("oversized tag error = %v", err)
	}
}

func TestSourceAttributeScanBoundsOverlappingCandidates(t *testing.T) {
	source := strings.Repeat(`<a title="`, 2_000)
	err := preflightStartTagAttributes([]byte(source), DefaultLimits().Attributes, nil)
	if err == nil || !strings.Contains(err.Error(), "source preflight work") {
		t.Fatalf("overlapping candidate error = %v", err)
	}
}
