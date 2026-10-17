package cascadia

import "testing"

func TestSelectorMetadata(t *testing.T) {
	group, err := ParseGroupWithPseudoElements(`SVG > .card[data-x]:not(#disabled)::before`)
	if err != nil {
		t.Fatal(err)
	}
	metadata := Metadata(group[0])
	if len(metadata.Compounds) != 2 || len(metadata.Combinators) != 1 || metadata.Combinators[0] != '>' {
		t.Fatalf("unexpected structure: %#v", metadata)
	}
	if got := metadata.Compounds[0].OriginalTypeName; got != "SVG" {
		t.Fatalf("original type name = %q, want SVG", got)
	}
	if got := metadata.Compounds[0].Key; got != (IndexKey{Kind: IndexTag, Value: "svg"}) {
		t.Fatalf("first key = %#v", got)
	}
	if got := metadata.Compounds[1].Key; got != (IndexKey{Kind: IndexClass, Value: "card"}) {
		t.Fatalf("second key = %#v", got)
	}
	if !metadata.Compounds[1].AttributeSensitive {
		t.Fatal("attribute-sensitive compound not reported")
	}
	if metadata.PseudoElement != "before" {
		t.Fatalf("pseudo-element = %q, want before", metadata.PseudoElement)
	}
	if metadata.Supported {
		t.Fatal("generated-content selector should use conservative email handling")
	}
}

func TestSplitSelectorList(t *testing.T) {
	branches, exceeded := SplitSelectorList(`a:not(.x,.y), [title="a,b"], p`, 3)
	if exceeded || len(branches) != 3 {
		t.Fatalf("branches = %#v, exceeded = %v", branches, exceeded)
	}
	if branches[0] != `a:not(.x,.y)` || branches[1] != `[title="a,b"]` || branches[2] != `p` {
		t.Fatalf("unexpected branches: %#v", branches)
	}
	if _, exceeded := SplitSelectorList(`a,b`, 1); !exceeded {
		t.Fatal("branch limit was not reported")
	}
}

func TestConservativeFallback(t *testing.T) {
	for _, test := range []struct {
		source string
		want   FallbackMetadata
	}{
		{`p[data-value#=(a+)]`, FallbackMetadata{PositiveSource: "p", Key: IndexKey{Kind: IndexTag, Value: "p"}, OriginalTypeName: "p"}},
		{`svg|text[data-x]`, FallbackMetadata{PositiveSource: "text", Key: IndexKey{Kind: IndexTag, Value: "text"}, OriginalTypeName: "text"}},
		{`div > span::before`, FallbackMetadata{PositiveSource: "span", Key: IndexKey{Kind: IndexTag, Value: "span"}, OriginalTypeName: "span", GeneratedPseudo: true}},
	} {
		if got := ConservativeFallback(test.source); got != test.want {
			t.Errorf("ConservativeFallback(%q) = %#v, want %#v", test.source, got, test.want)
		}
	}
}

func TestSelectorMetadataReportsInactiveSelector(t *testing.T) {
	group, err := ParseGroup(`.card:hover img`)
	if err != nil {
		t.Fatal(err)
	}
	if !Metadata(group[0]).Inactive {
		t.Fatal("interaction pseudo-class should be inactive in static email")
	}
}
