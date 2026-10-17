package cascadia

import "strings"

// SplitSelectorList separates top-level selector branches without treating
// commas in strings, attribute selectors, or functional pseudo-classes as
// separators. Empty branches are omitted.
func SplitSelectorList(source string, limit int) (branches []string, exceeded bool) {
	start, brackets, parens := 0, 0, 0
	var quote byte
	appendBranch := func(end int) bool {
		branch := strings.Trim(source[start:end], " \t\r\n\f")
		if branch == "" {
			return true
		}
		if len(branches) >= limit {
			return false
		}
		branches = append(branches, branch)
		return true
	}
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
		case ',':
			if brackets == 0 && parens == 0 {
				if !appendBranch(i) {
					return branches, true
				}
				start = i + 1
			}
		}
	}
	if !appendBranch(len(source)) {
		return branches, true
	}
	return branches, false
}
