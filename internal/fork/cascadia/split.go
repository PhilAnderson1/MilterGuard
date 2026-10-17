package cascadia

import "strings"

// SelectorListIterator yields top-level selector branches without allocating
// an intermediate slice.
type SelectorListIterator struct {
	source string
	offset int
}

func NewSelectorListIterator(source string) SelectorListIterator {
	return SelectorListIterator{source: source}
}

func (iterator *SelectorListIterator) Next() (string, bool) {
	for iterator.offset <= len(iterator.source) {
		start := iterator.offset
		brackets, parens := 0, 0
		var quote byte
		end := len(iterator.source)
		for i := start; i < len(iterator.source); i++ {
			c := iterator.source[i]
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
			case ',':
				if brackets == 0 && parens == 0 {
					end = i
					i = len(iterator.source)
				}
			}
		}
		if end == len(iterator.source) {
			iterator.offset = len(iterator.source) + 1
		} else {
			iterator.offset = end + 1
		}
		branch := strings.Trim(iterator.source[start:end], " \t\r\n\f")
		if branch != "" {
			return branch, true
		}
	}
	return "", false
}

// SplitSelectorList separates top-level selector branches without treating
// commas in strings, attribute selectors, or functional pseudo-classes as
// separators. Empty branches are omitted.
func SplitSelectorList(source string, limit int) (branches []string, exceeded bool) {
	iterator := NewSelectorListIterator(source)
	for {
		branch, ok := iterator.Next()
		if !ok {
			return branches, false
		}
		if len(branches) >= limit {
			return branches, true
		}
		branches = append(branches, branch)
	}
}
