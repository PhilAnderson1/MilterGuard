package html

import (
	"bytes"
	"strings"
)

const workChunk = 1024

func compareStringWithGuard(a, b string, guard *resourceGuard) int {
	for start := 0; start < min(len(a), len(b)); start += workChunk {
		if start > 0 {
			guard.check()
		}
		end := min(start+workChunk, len(a), len(b))
		if c := strings.Compare(a[start:end], b[start:end]); c != 0 {
			return c
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
func attrCompareWithGuard(a, b Attribute, guard *resourceGuard) int {
	if c := compareStringWithGuard(a.Namespace, b.Namespace, guard); c != 0 {
		return c
	}
	if c := compareStringWithGuard(a.Key, b.Key, guard); c != 0 {
		return c
	}
	return compareStringWithGuard(a.Val, b.Val, guard)
}
func equalAttrsWithGuard(a, b []Attribute, guard *resourceGuard) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		guard.stop()
		if attrCompareWithGuard(a[i], b[i], guard) != 0 {
			return false
		}
	}
	return true
}

func trimLeftWithGuard(s, cutset string, guard *resourceGuard) string {
	for start := 0; start < len(s); start += workChunk {
		if start > 0 {
			guard.check()
		}
		end := min(start+workChunk, len(s))
		tail := strings.TrimLeft(s[start:end], cutset)
		if len(tail) > 0 {
			return s[end-len(tail):]
		}
	}
	return s[len(s):]
}
func trimWithGuard(s, cutset string, guard *resourceGuard) string {
	s = trimLeftWithGuard(s, cutset, guard)
	for end := len(s); end > 0; {
		if end < len(s) {
			guard.check()
		}
		start := max(0, end-workChunk)
		head := strings.TrimRight(s[start:end], cutset)
		if len(head) > 0 {
			return s[:start+len(head)]
		}
		end = start
	}
	return s[:0]
}
func indexAnyWithGuard(s, chars string, guard *resourceGuard) int {
	for start := 0; start < len(s); start += workChunk {
		if start > 0 {
			guard.check()
		}
		if i := strings.IndexAny(s[start:min(start+workChunk, len(s))], chars); i >= 0 {
			return start + i
		}
	}
	return -1
}

// replaceNULBytes preserves all non-NUL bytes, including invalid UTF-8. Both
// passes are sampled; unchanged input remains borrowed and owned output is
// admitted before allocation.
func replaceNULBytes(s []byte, guard *resourceGuard) []byte {
	count := 0
	for start := 0; start < len(s); start += workChunk {
		if start > 0 {
			guard.check()
		}
		count += bytes.Count(s[start:min(start+workChunk, len(s))], nul)
	}
	if count == 0 {
		return s
	}
	size := len(s) + count*(len(replacement)-1)
	out := guard.makeBytes(size)[:0]
	for start := 0; start < len(s); start += workChunk {
		if start > 0 {
			guard.check()
		}
		chunk := s[start:min(start+workChunk, len(s))]
		for {
			i := bytes.IndexByte(chunk, 0)
			if i < 0 {
				out = append(out, chunk...)
				break
			}
			out = append(out, chunk[:i]...)
			out = append(out, replacement...)
			chunk = chunk[i+1:]
		}
	}
	return out
}
