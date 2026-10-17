package css

import (
	"errors"
	"io"
	"strings"
	"testing"

	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
)

func TestCommentsPreserveSelectorTokenBoundaries(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{`.a/**/p{color:red}`, `.a p`},
		{`di/**/v p{color:red}`, `di v p`},
		{`[title="a/**/b"]{color:red}`, `[title="a/**/b"]`},
	} {
		parser := NewParser(parse.NewInputString(test.source), false)
		grammar, _, _ := parser.Next()
		if grammar != BeginRulesetGrammar {
			t.Fatalf("%q grammar = %s, want BeginRuleset", test.source, grammar)
		}
		if got := joinTokenData(parser.Values()); got != test.want {
			t.Errorf("%q selector = %q, want %q", test.source, got, test.want)
		}
	}
}

func TestMismatchedCloserRemainsInsideComponentValue(t *testing.T) {
	source := `p{--x:var(--missing,[unused)]);--joined:re/**/d;color:var(--missing,[unused)])}`
	parser := NewParser(parse.NewInputString(source), false)
	values := map[string]string{}
	for {
		grammar, _, data := parser.Next()
		if grammar == ErrorGrammar {
			if errors.Is(parser.Err(), io.EOF) {
				break
			}
			t.Fatal(parser.Err())
		}
		if grammar == DeclarationGrammar || grammar == CustomPropertyGrammar {
			values[string(data)] = joinTokenData(parser.Values())
		}
	}
	if got := values["--x"]; got != `var(--missing,[unused)])` {
		t.Fatalf("custom value = %q", got)
	}
	if got := values["color"]; got != `var(--missing,[unused)])` {
		t.Fatalf("ordinary value = %q", got)
	}
	if got := values["--joined"]; got != `re    d` {
		t.Fatalf("comment-separated custom value = %q", got)
	}
}

func TestDeclarationOriginalDataPreservesEscapedCase(t *testing.T) {
	parser := NewParser(parse.NewInputString(`p{\2d\2dX:red}`), false)
	for {
		grammar, _, _ := parser.Next()
		if grammar == DeclarationGrammar {
			if got := string(parser.OriginalData()); got != `\2d\2dX` {
				t.Fatalf("original declaration name = %q", got)
			}
			return
		}
		if grammar == ErrorGrammar {
			t.Fatal(parser.Err())
		}
	}
}

func joinTokenData(tokens []Token) string {
	var builder strings.Builder
	for _, token := range tokens {
		builder.Write(token.Data)
	}
	return builder.String()
}
