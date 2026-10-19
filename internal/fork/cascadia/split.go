package cascadia

// SelectorListIterator yields top-level selector branches without allocating
// an intermediate slice.
type SelectorListIterator struct {
	source      string
	offset      int
	control     MatchControl
	nextCheck   int
	emptyBranch bool
}

func NewSelectorListIterator(source string) SelectorListIterator {
	return SelectorListIterator{source: source}
}

// NewSelectorListIteratorWithStop samples source scanning, including empty branches.
func NewSelectorListIteratorWithStop(source string, shouldStop func() bool) SelectorListIterator {
	return SelectorListIterator{source: source, control: MatchControl{shouldStop: shouldStop}}
}
func (iterator *SelectorListIterator) Stopped() bool {
	return iterator.control.stopped
}

// EmptyBranch reports invalid empty branches without changing splitting semantics.
func (iterator *SelectorListIterator) EmptyBranch() bool { return iterator.emptyBranch }

func (iterator *SelectorListIterator) Next() (string, bool) {
	if iterator.Stopped() {
		return "", false
	}
	for iterator.offset <= len(iterator.source) {
		start := iterator.offset
		brackets, parens := 0, 0
		var quote byte
		first, last := -1, start
		end := len(iterator.source)
		for i := start; i < len(iterator.source); i++ {
			if iterator.control.shouldStop != nil && i >= iterator.nextCheck {
				iterator.nextCheck = i + 1024
				if iterator.control.checkNow() {
					return "", false
				}
			}
			c := iterator.source[i]
			if !isCSSWhitespace(c) && !(c == ',' && quote == 0 && brackets == 0 && parens == 0) {
				if first == -1 {
					first = i
				}
				last = i + 1
			}

			if c == '\\' {
				if i+1 < len(iterator.source) && !isCSSWhitespace(iterator.source[i+1]) {
					last = i + 2
				}
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
		branch := ""
		if first >= 0 {
			branch = iterator.source[first:last]
		}
		if branch != "" {
			return branch, true
		}
		iterator.emptyBranch = true
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
