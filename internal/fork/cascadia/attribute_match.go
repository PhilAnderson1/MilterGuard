package cascadia

import (
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Long attribute scans sample every 1024 processed bytes. Short operations are
// covered by MatchControl.step, so they do not each require a clock syscall.
const attributeScanChunk = 1024

func equalAttribute(left, right string, insensitive bool, guard *MatchControl) bool {
	if len(left) != len(right) {
		return false
	}
	for offset := 0; offset < len(left); {
		end := min(offset+attributeScanChunk, len(left))

		if offset > 0 {
			guard.checkNow()
		}

		if !insensitive {
			if left[offset:end] != right[offset:end] {
				return false
			}
		} else {
			for i := offset; i < end; i++ {
				if foldASCII(left[i]) != foldASCII(right[i]) {
					return false
				}
			}
		}
		offset = end
	}
	return true
}

func matchIncludeResource(needle, value string, insensitive bool, guard *MatchControl) bool {
	start := 0
	nextCheck := attributeScanChunk
	for i := 0; i < len(value); i++ {
		if i >= nextCheck {
			nextCheck = i + attributeScanChunk

			guard.checkNow()
		}
		switch value[i] {
		case ' ', '\t', '\r', '\n', '\f':
			if equalAttribute(value[start:i], needle, insensitive, guard) {
				return true
			}
			start = i + 1
		}
	}
	return start < len(value) && equalAttribute(value[start:], needle, insensitive, guard)
}

// Match the prior TrimSpace(value)!="" semantics without one uninterruptible
// scan over a large whitespace-only attribute. Unicode whitespace is preserved.
func nonBlankAttribute(value string, guard *MatchControl) bool {
	next := attributeScanChunk
	for i := 0; i < len(value); {
		if i >= next {
			guard.checkNow()

			next = i + attributeScanChunk
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if !unicode.IsSpace(r) {
			return true
		}
		i += size
	}
	return false
}

func (t attrSelector) matchValue(value string, guard *MatchControl) bool {
	switch t.operation {
	case "=", "!=":
		return equalAttribute(value, t.val, t.insensitive, guard)
	case "~=":
		return matchIncludeResource(t.val, value, t.insensitive, guard)
	case "|=":
		return equalAttribute(value, t.val, t.insensitive, guard) ||
			len(value) > len(t.val) && value[len(t.val)] == '-' && equalAttribute(value[:len(t.val)], t.val, t.insensitive, guard)
	case "^=", "$=", "*=":
		if !nonBlankAttribute(value, guard) || len(value) < len(t.val) {
			return false
		}
		switch t.operation {
		case "^=":
			return equalAttribute(value[:len(t.val)], t.val, t.insensitive, guard)
		case "$=":
			return equalAttribute(value[len(value)-len(t.val):], t.val, t.insensitive, guard)
		default:
			return t.contains(value, guard)
		}
	}
	return false
}

// KMP keeps adversarial repeated prefixes linear. The table belongs to the
// immutable compiled selector, not to any match or document cache.
func substringFailure(needle string, insensitive bool) []int {
	return substringFailureWithMemory(needle, insensitive, nil)
}
func substringFailureWithMemory(needle string, insensitive bool, memory *resourceguard.Memory) []int {
	table := selectorSlice[int](memory, len(needle), len(needle))
	for i, matched := 1, 0; i < len(needle); i++ {
		for matched > 0 && !sameAttributeByte(needle[i], needle[matched], insensitive) {
			matched = table[matched-1]
		}
		if sameAttributeByte(needle[i], needle[matched], insensitive) {
			matched++
		}
		table[i] = matched
	}
	return table
}
func sameAttributeByte(a, b byte, insensitive bool) bool {
	if insensitive {
		return foldASCII(a) == foldASCII(b)
	}
	return a == b
}
func (t attrSelector) contains(value string, guard *MatchControl) bool {
	if len(t.val) == 0 {
		return true
	}
	// Select the comparison once, outside the byte loop. The two small loops
	// avoid paying for case-mode dispatch on every byte of a large attribute.
	nextCheck := attributeScanChunk
	if t.insensitive {
		for i, matched := 0, 0; i < len(value); i++ {
			if i >= nextCheck {
				nextCheck = i + attributeScanChunk

				guard.checkNow()
			}
			c := foldASCII(value[i])
			for matched > 0 && c != foldASCII(t.val[matched]) {
				matched = t.failure[matched-1]
			}
			if c == foldASCII(t.val[matched]) {
				matched++
				if matched == len(t.val) {
					return true
				}
			}
		}
		return false
	}
	for i, matched := 0, 0; i < len(value); i++ {
		if i >= nextCheck {
			nextCheck = i + attributeScanChunk

			guard.checkNow()
		}
		for matched > 0 && value[i] != t.val[matched] {
			matched = t.failure[matched-1]
		}
		if value[i] == t.val[matched] {
			matched++
			if matched == len(t.val) {
				return true
			}
		}
	}
	return false
}
