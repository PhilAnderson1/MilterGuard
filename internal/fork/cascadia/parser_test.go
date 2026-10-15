package cascadia

import (
	"strings"
	"testing"
)

var identifierTests = map[string]string{
	"x":             "x",
	"96":            "",
	"-x":            "-x",
	`r\e9 sumé`:     "résumé",
	`r\0000e9 sumé`: "résumé",
	`r\0000e9sumé`:  "résumé",
	`a\"b`:          `a"b`,
}

func TestParseIdentifier(t *testing.T) {
	for source, want := range identifierTests {
		p := &parser{s: source}
		got, err := p.parseIdentifier()
		if err != nil {
			if want == "" {
				// It was supposed to be an error.
				continue
			}
			t.Errorf("parsing %q: got error (%s), want %q", source, err, want)
			continue
		}

		if want == "" {
			if err == nil {
				t.Errorf("parsing %q: got %q, want error", source, got)
			}
			continue
		}

		if p.i < len(source) {
			t.Errorf("parsing %q: %d bytes left over", source, len(source)-p.i)
			continue
		}

		if got != want {
			t.Errorf("parsing %q: got %q, want %q", source, got, want)
		}
	}
}

var stringTests = map[string]string{
	`"x"`:             "x",
	`'x'`:             "x",
	`'x`:              "",
	"'x\\\r\nx'":      "xx",
	`"r\e9 sumé"`:     "résumé",
	`"r\0000e9 sumé"`: "résumé",
	`"r\0000e9sumé"`:  "résumé",
	`"a\"b"`:          `a"b`,
}

func TestParseString(t *testing.T) {
	for source, want := range stringTests {
		p := &parser{s: source}
		got, err := p.parseString()
		if err != nil {
			if want == "" {
				// It was supposed to be an error.
				continue
			}
			t.Errorf("parsing %q: got error (%s), want %q", source, err, want)
			continue
		}

		if want == "" {
			if err == nil {
				t.Errorf("parsing %q: got %q, want error", source, got)
			}
			continue
		}

		if p.i < len(source) {
			t.Errorf("parsing %q: %d bytes left over", source, len(source)-p.i)
			continue
		}

		if got != want {
			t.Errorf("parsing %q: got %q, want %q", source, got, want)
		}
	}
}

func TestEscapeHeavyParsingUsesBoundedAllocations(t *testing.T) {
	const escapes = 4096
	want := strings.Repeat("z", escapes)
	for _, test := range []struct {
		name   string
		source string
		parse  func(*parser) (string, error)
	}{
		{"name", strings.Repeat(`\z`, escapes), (*parser).parseName},
		{"string", `"` + strings.Repeat(`\z`, escapes) + `"`, (*parser).parseString},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			allocs := testing.AllocsPerRun(10, func() {
				p := &parser{s: test.source}
				var err error
				got, err = test.parse(p)
				if err != nil {
					t.Fatalf("parse failed: %v", err)
				}
			})
			if got != want {
				t.Fatalf("parsed value has length %d, want %d", len(got), len(want))
			}
			if allocs > 64 {
				t.Fatalf("parse used %.0f allocations for %d escapes, want at most 64", allocs, escapes)
			}
		})
	}
}
