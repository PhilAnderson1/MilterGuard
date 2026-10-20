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
func asciiLower(s string) string { return asciiLowerWithBudget(s, nil) }

func asciiLowerWithBudget(s string, budget *cpuGuard) string {
	value := lowerASCIIWithBudget(s, budget)
	return value
}

func normalizeCSSKeyword(s string) string {
	return asciiLower(trimCSSWhitespace(s))
}

// Expanded variables can be much larger than the stylesheet that defines them.
// Trim in bounded chunks and admit one owned lowercase string only if needed.
func trimCSSWhitespaceWithBudget(s string, budget *cpuGuard) string {
	const whitespace = " \t\r\n\f"
	for len(s) > 0 {
		if len(s) > stringWorkChunk {
			budget.checkpoint()
		}

		n := min(len(s), stringWorkChunk)
		tail := strings.TrimLeft(s[:n], whitespace)
		s = s[n-len(tail):]
		if len(tail) != 0 {
			break
		}
	}
	for len(s) > 0 {
		if len(s) > stringWorkChunk {
			budget.checkpoint()
		}

		start := max(0, len(s)-stringWorkChunk)
		head := strings.TrimRight(s[start:], whitespace)
		s = s[:start+len(head)]
		if len(head) != 0 {
			break
		}
	}
	return s
}

func normalizeCSSKeywordWithBudget(s string, budget *cpuGuard) string {
	s = trimCSSWhitespaceWithBudget(s, budget)

	return lowerASCIIWithBudget(s, budget)
}

func lowerASCIIWithBudget(s string, budget *cpuGuard) string {
	changed := false
	for start := 0; start < len(s) && !changed; start += stringWorkChunk {
		if len(s) > stringWorkChunk {
			budget.checkpoint()
		}

		for _, c := range []byte(s[start:min(start+stringWorkChunk, len(s))]) {
			if c >= 'A' && c <= 'Z' {
				changed = true
				break
			}
		}
	}
	if !changed {
		return s
	}
	var out strings.Builder

	growBuilder(&out, len(s), budget)

	for start := 0; start < len(s); start += stringWorkChunk {
		if len(s) > stringWorkChunk {
			budget.checkpoint()
		}

		for _, c := range []byte(s[start:min(start+stringWorkChunk, len(s))]) {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out.WriteByte(c)
		}
	}
	return out.String()
}

func equalASCIIFold(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := 0; i < len(left); i++ {
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

// splitCSSWhitespace fills caller-owned storage without allocating. An extra
// component rejects the value without collecting the rest of the input.
func splitCSSWhitespace(s string, storage []string) []string {
	limit := len(storage)
	parts := storage[:0]
	for part := range strings.FieldsFuncSeq(s, isCSSWhitespace) {
		if len(parts) == limit {
			return nil
		}
		parts = append(parts, part)
	}
	return parts
}
