package css

import (
	parse "github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"testing"

	"github.com/tdewolff/test"
)

func TestIsIdent(t *testing.T) {
	test.That(t, IsIdent([]byte("color")))
	test.That(t, !IsIdent([]byte("4.5")))
}

func TestIsURLUnquoted(t *testing.T) {
	test.That(t, IsURLUnquoted([]byte("http://x")))
	test.That(t, !IsURLUnquoted([]byte(")")))
}

func TestHsl2Rgb(t *testing.T) {
	r, g, b := HSL2RGB(0.0, 1.0, 0.5)
	test.T(t, r, 1.0)
	test.T(t, g, 0.0)
	test.T(t, b, 0.0)

	r, g, b = HSL2RGB(1.0, 1.0, 0.5)
	test.T(t, r, 1.0)
	test.T(t, g, 0.0)
	test.T(t, b, 0.0)

	r, g, b = HSL2RGB(0.66, 0.0, 1.0)
	test.T(t, r, 1.0)
	test.T(t, g, 1.0)
	test.T(t, b, 1.0)
}

// These upstream lexer probes are test-only; production uses guarded parser entrypoints.
// IsIdent returns true if the bytes are a valid identifier.
func IsIdent(b []byte) bool {
	l := NewLexer(parse.NewInputBytes(b))
	l.consumeIdentToken()
	l.r.Restore()
	return l.r.Pos() == len(b)
}

// IsURLUnquoted returns true if the bytes are a valid unquoted URL.
func IsURLUnquoted(b []byte) bool {
	l := NewLexer(parse.NewInputBytes(b))
	l.consumeUnquotedURL()
	l.r.Restore()
	return l.r.Pos() == len(b)
}
