package cascadia

import "testing"

func TestCSSRejectsAttributeExtensions(t *testing.T) {
	for _, source := range []string{`p[x!=y]`, `p:not([x!=y])`, `p[x#=y]`} {
		if _, err := ParseCSSGroupWithMemory(source, nil); err != ErrInvalidAttributeOperator {
			t.Errorf("%q: %v", source, err)
		}
	}
	if _, err := ParseGroup(`p[x!=y]`); err != nil {
		t.Fatalf("legacy extension: %v", err)
	}
	for _, source := range []string{`p[x=y]`, `p[x~=y]`, `p[x|=y]`, `p[x^=y]`, `p[x$=y]`, `p[x*=y]`} {
		if _, err := ParseCSSGroupWithMemory(source, nil); err != nil {
			t.Errorf("valid %q: %v", source, err)
		}
	}
}

func TestSelectorIteratorReportsEmptyBranches(t *testing.T) {
	for _, source := range []string{`,p`, `p,`, `p,,a`, `p, ,a`} {
		it := NewSelectorListIterator(source)
		for {
			if _, ok := it.Next(); !ok {
				break
			}
		}
		if !it.EmptyBranch() {
			t.Errorf("missed empty branch: %q", source)
		}
	}
	it := NewSelectorListIterator(`p[x=","],a`)
	for {
		if _, ok := it.Next(); !ok {
			break
		}
	}
	if it.EmptyBranch() {
		t.Fatal("comma in string treated as branch")
	}
}
