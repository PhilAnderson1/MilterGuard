package htmlextract

import "strings"

// CSS syntactic whitespace is deliberately narrower than Unicode whitespace.
// CR and FF are converted to LF during CSS input preprocessing, but accepting
// them here gives the same result without requiring every caller to preprocess.
func isCSSWhitespace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f':
		return true
	default:
		return false
	}
}

func trimCSSWhitespace(s string) string {
	return strings.TrimFunc(s, isCSSWhitespace)
}

// asciiLower applies the case folding used by CSS and HTML keyword grammars.
// Unicode case folding is deliberately inappropriate here: for example, the
// Kelvin sign must not be accepted as an ASCII "k" in a CSS identifier.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			out := []byte(s)
			for j := i; j < len(out); j++ {
				if out[j] >= 'A' && out[j] <= 'Z' {
					out[j] += 'a' - 'A'
				}
			}
			return string(out)
		}
	}
	return s
}

func normalizeCSSKeyword(s string) string {
	return asciiLower(trimCSSWhitespace(s))
}

func equalASCIIFold(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		a, b := left[i], right[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func equalASCIIFoldBytes(left []byte, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i, a := range left {
		b := right[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

func splitCSSWhitespace(s string) []string {
	return strings.FieldsFunc(s, isCSSWhitespace)
}
