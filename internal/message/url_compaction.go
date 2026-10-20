package message

import (
	"strings"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// promptURL preserves the existing component limits and filename suffix rule.
func promptURL(value string, compact bool) string {
	result := promptURLWithBudget(value, compact, nil, nil)
	return result
}

// urlOutput retains one extra rune to distinguish an exact fit from truncation.
// Storage is bounded regardless of the size or number of URL components.
type urlOutput struct {
	data         [utf8.UTFMax * (maxPromptURLChars + 1)]byte
	bytes, runes int
}

func (o *urlOutput) full() bool { return o.runes > maxPromptURLChars }
func (o *urlOutput) write(s string, normalize bool) {
	for len(s) > 0 && !o.full() {
		r, n := utf8.DecodeRuneInString(s)
		if normalize {
			o.bytes += utf8.EncodeRune(o.data[o.bytes:], r)
		} else {
			o.bytes += copy(o.data[o.bytes:], s[:n])
		}
		o.runes++
		s = s[n:]
	}
}
func runePrefix(s string, limit int) (string, bool) {
	end := 0
	for i := 0; i < limit && end < len(s); i++ {
		_, n := utf8.DecodeRuneInString(s[end:])
		end += n
	}
	return s[:end], end < len(s)
}
func (o *urlOutput) part(s string, limit int, path bool) bool {
	prefix, changed := runePrefix(s, limit)
	if changed && path && hasLikelyFileExtension(s) {
		start := len(s)
		for i := 0; i < limit; i++ {
			_, n := utf8.DecodeLastRuneInString(s[:start])
			start -= n
		}
		prefix = s[start:]
	}
	o.write(prefix, changed)
	return changed
}
func (o *urlOutput) result(memory *resourceguard.Memory, stop resourceguard.Stop) string {
	if o.full() {
		// The old final []rune conversion also normalized invalid UTF-8 when
		// truncating. Keep that behaviour without materializing the entire URL.
		var normalized urlOutput
		for offset, count := 0, 0; count < maxPromptURLChars; count++ {
			r, n := utf8.DecodeRune(o.data[offset:o.bytes])
			normalized.bytes += utf8.EncodeRune(normalized.data[normalized.bytes:], r)
			offset += n
		}
		return resourceguard.CopyString(memory, normalized.data[:normalized.bytes], stop)
	}
	return resourceguard.CopyString(memory, o.data[:o.bytes], stop)
}

// File extensions are at most 16 decoded ASCII characters. Inspect only that
// suffix, decoding percent escapes backwards rather than unescaping the path.
func hasLikelyFileExtension(s string) bool {
	letters := 0
	for end := len(s); end > 0; {
		c := s[end-1]
		end--
		if end >= 2 && s[end-2] == '%' {
			hi, lo := urlHex(s[end-1]), urlHex(c)
			if hi < 0 || lo < 0 {
				return false
			}
			c = byte(hi<<4 | lo)
			end -= 2
		}
		if c == '.' {
			return end > 0 && letters > 0
		}
		if letters == 16 || !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
		letters++
	}
	return false
}
func urlHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// cutURL samples cancellation even when a single component spans megabytes.
func cutURL(s string, delimiter byte, stop resourceguard.Stop) (string, string, bool) {
	for start := 0; start < len(s); start += resourceguard.WorkChunk {
		if stop != nil {
			stop()
		}

		end := min(start+resourceguard.WorkChunk, len(s))

		if i := strings.IndexByte(s[start:end], delimiter); i >= 0 {
			i += start
			return s[:i], s[i+1:], true
		}

	}
	return s, "", false
}
func promptURLWithBudget(value string, compact bool, memory *resourceguard.Memory, stop resourceguard.Stop) string {
	if !compact {
		return value
	}

	if stop != nil {
		stop()
	}

	parsed, err := resourceguard.ParseURL(memory, value)

	if stop != nil {
		stop()
	}

	var out urlOutput
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		prefix, truncated := runePrefix(value, maxPromptURLChars)
		if !truncated {
			return value
		}
		out.write(prefix, true)
		return out.result(memory, stop)
	}
	out.write(parsed.Scheme, false)
	out.write("://", false)
	if parsed.User != nil {
		out.write("[userinfo-omitted]@", false)
	}
	out.write(parsed.Host, false)
	changed := false
	if !out.full() {
		path := parsed.EscapedPath()
		for {
			part, rest, found := cutURL(path, '/', stop)

			changed = out.part(part, maxPromptURLPathChars, true) || changed
			if out.full() || !found {
				break
			}
			out.write("/", false)
			path = rest
		}
	}
	if !out.full() && (parsed.ForceQuery || parsed.RawQuery != "") {
		out.write("?", false)
		query := parsed.RawQuery
		for {
			parameter, rest, found := cutURL(query, '&', stop)

			key, val, equals := cutURL(parameter, '=', stop)

			changed = out.part(key, maxPromptURLParameterChars, false) || changed
			if equals {
				out.write("=", false)
				changed = out.part(val, maxPromptURLParameterChars, false) || changed
			}
			if out.full() || !found {
				break
			}
			out.write("&", false)
			query = rest
		}
	}
	if !out.full() && parsed.Fragment != "" {
		out.write("#", false)
		changed = out.part(parsed.EscapedFragment(), maxPromptURLFragmentChars, false) || changed
	}
	_, long := runePrefix(value, maxPromptURLChars)
	if !changed && !long {
		return value
	}
	return out.result(memory, stop)
}
