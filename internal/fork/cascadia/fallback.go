package cascadia

import (
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// FallbackMetadata contains the small, safe positive constraint that can be
// recovered when the authoritative parser rejects a selector. It never claims
// an exact match; callers use it only to limit conservative uncertainty.
type FallbackMetadata struct {
	PositiveSource   string
	Key              IndexKey
	OriginalTypeName string
	GeneratedPseudo  bool
}

// ConservativeFallback finds the rightmost compound outside strings,
// attributes, and functional pseudo-classes, then retains only its positive
// type, ID, and class prefix. Unsupported namespaces retain a lowercase local
// type name when doing so is safe.
func ConservativeFallback(source string) FallbackMetadata {
	result, _ := ConservativeFallbackWithMemory(source, nil)
	return result
}

// ConservativeFallbackWithMemory bounds rejected input and admits owned keys.
func ConservativeFallbackWithMemory(source string, memory *resourceguard.Memory) (result FallbackMetadata, err error) {
	if len(source) > maxSelectorBytes {
		// Keep the entire rule uncertain. A bounded suffix check retains the same
		// generated-content handling without scanning or normalizing the source.
		return FallbackMetadata{GeneratedPseudo: generatedSuffix(source)}, nil
	}

	start, brackets, parens := 0, 0, 0
	var quote byte
	for i := 0; i < len(source); i++ {
		c := source[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '(':
			if brackets == 0 {
				parens++
			}
		case ')':
			if brackets == 0 && parens > 0 {
				parens--
			}
		case '>', '+', '~':
			if brackets == 0 && parens == 0 {
				start = i + 1
			}
		default:
			if brackets == 0 && parens == 0 && isCSSWhitespace(c) {
				j := i
				for j < len(source) && isCSSWhitespace(source[j]) {
					j++
				}
				if j < len(source) && source[j] != '>' && source[j] != '+' && source[j] != '~' {
					start = j
				}
				i = j - 1
			}
		}
	}
	compound := strings.Trim(source[start:], " \t\r\n\f")
	prefix, original := conservativePositivePrefix(compound)
	result = FallbackMetadata{
		PositiveSource:   prefix,
		Key:              indexKeyFromPositiveSourceWithMemory(prefix, memory),
		OriginalTypeName: original,
	}
	result.GeneratedPseudo = generatedSuffix(compound)
	return result, nil
}

func conservativePositivePrefix(compound string) (prefix, originalType string) {
	for i := 0; i < len(compound); i++ {
		if compound[i] == '\\' {
			return "", ""
		}
		if compound[i] == ':' || compound[i] == '[' {
			compound = strings.Trim(compound[:i], " \t\r\n\f")
			break
		}
		if compound[i] == '|' {
			start := i + 1
			if start >= len(compound) || compound[start] == '|' || compound[start] == '*' || compound[start] == '\\' {
				return "", ""
			}
			end := start
			for end < len(compound) && isNameByte(compound[end]) {
				end++
			}
			if end == start {
				return "", ""
			}
			local := compound[start:end]
			if !isLowerName(local) {
				return "", local
			}
			return local, local
		}
	}
	if compound == "" || compound == "*" {
		return compound, ""
	}
	end := 0
	for end < len(compound) && isNameByte(compound[end]) {
		end++
	}
	if end > 0 {
		originalType = compound[:end]
	}
	return compound, originalType
}

func indexKeyFromPositiveSource(source string) IndexKey {
	return indexKeyFromPositiveSourceWithMemory(source, nil)
}
func indexKeyFromPositiveSourceWithMemory(source string, memory *resourceguard.Memory) IndexKey {
	if source == "" || source == "*" || strings.ContainsAny(source, "\\|[") {
		return IndexKey{}
	}
	var tag, id, class string
	for i := 0; i < len(source); {
		kind := byte(0)
		if source[i] == '#' || source[i] == '.' {
			kind = source[i]
			i++
		}
		start := i
		for i < len(source) && isNameByte(source[i]) {
			i++
		}
		if start == i {
			return IndexKey{}
		}
		switch kind {
		case '#':
			id = source[start:i]
		case '.':
			if class == "" {
				class = source[start:i]
			}
		default:
			if tag != "" {
				return IndexKey{}
			}
			tag = source[start:i]
			if !isLowerName(tag) {
				p := parser{memory: memory}
				tag = p.lowerASCII(tag)
			}
		}
	}
	if id != "" {
		return IndexKey{Kind: IndexID, Value: id}
	}
	if class != "" {
		return IndexKey{Kind: IndexClass, Value: class}
	}
	if tag != "" {
		return IndexKey{Kind: IndexTag, Value: tag}
	}
	return IndexKey{}
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func isCSSWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}

func isLowerName(s string) bool {
	// Callers pass ASCII name bytes only.
	for i := range s {
		if 'A' <= s[i] && s[i] <= 'Z' {
			return false
		}
	}
	return true
}
func generatedSuffix(s string) bool {
	for _, suffix := range []string{":before", ":after"} {
		if len(s) >= len(suffix) && equalAttribute(s[len(s)-len(suffix):], suffix, true, nil) {
			return true
		}
	}
	return false
}
