package html

import (
	"strings"
	"unicode/utf8"
)

// mapStringWithGuard preserves strings.Map semantics, but sizes the owned
// string before allocation and samples both passes. Unchanged strings are shared.
func mapStringWithGuard(s string, mapping func(rune) rune, guard *resourceGuard) string {
	size, changed, next := 0, false, 1024
	for i := 0; i < len(s); {
		if i >= next {
			guard.check()
			next = i + 1024
		}
		r, width := utf8.DecodeRuneInString(s[i:])
		mapped := mapping(r)
		changed = changed || mapped != r || r == utf8.RuneError && width == 1
		if mapped >= 0 {
			n := utf8.RuneLen(mapped)
			if n < 0 {
				n = 3
			}
			size += n
		}
		i += width
	}
	if !changed {
		return s
	}
	var b strings.Builder
	guard.initStringBuilder(&b, size)
	next = 1024
	for i, r := range s {
		if i >= next {
			guard.check()
			next = i + 1024
		}
		if r = mapping(r); r >= 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func whitespaceStringWithGuard(s string, guard *resourceGuard) string {
	return mapStringWithGuard(s, func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\f', '\r':
			return r
		}
		return -1
	}, guard)
}

// Unlike rune mapping, replacing NUL must preserve other invalid UTF-8 bytes.
func replaceNULString(s, replacement string, guard *resourceGuard) string {
	count := 0
	for start := 0; start < len(s); start += 1024 {
		if start > 0 {
			guard.check()
		}
		count += strings.Count(s[start:min(start+1024, len(s))], "\x00")
	}
	if count == 0 {
		return s
	}
	size := len(s) + count*(len(replacement)-1)
	var b strings.Builder
	guard.initStringBuilder(&b, size)
	for start := 0; start < len(s); start += 1024 {
		if start > 0 {
			guard.check()
		}
		chunk := s[start:min(start+1024, len(s))]
		for {
			i := strings.IndexByte(chunk, 0)
			if i < 0 {
				b.WriteString(chunk)
				break
			}
			b.WriteString(chunk[:i])
			b.WriteString(replacement)
			chunk = chunk[i+1:]
		}
	}
	return b.String()
}
