package message

import "strings"

// lexicalVisiblyHidden recognizes only explicit, high-confidence hiding on
// the element itself. It does not try to compute stylesheet rules or layout.
func lexicalVisiblyHidden(rawTag string) bool {
	if _, present := lexicalAttributeValue(rawTag, "hidden"); present {
		return true
	}
	style, present := lexicalAttributeValue(rawTag, "style")
	if !present {
		return false
	}
	var display, visibility lexicalCSSChoice
	for _, declaration := range lexicalCSSDeclarations(style) {
		property, value, found := strings.Cut(declaration, ":")
		if !found {
			continue
		}
		property = strings.ToLower(strings.TrimSpace(property))
		value = strings.ToLower(strings.TrimSpace(value))
		important := false
		if before, suffix, found := strings.Cut(value, "!"); found && strings.TrimSpace(suffix) == "important" {
			value = strings.TrimSpace(before)
			important = true
		}
		switch property {
		case "display":
			display.set(value, important)
		case "visibility":
			visibility.set(value, important)
		}
	}
	return display.value == "none" || visibility.value == "hidden" || visibility.value == "collapse"
}

type lexicalCSSChoice struct {
	value     string
	important bool
}

func (choice *lexicalCSSChoice) set(value string, important bool) {
	if !choice.important || important {
		choice.value = value
		choice.important = important
	}
}

// lexicalCSSDeclarations separates inline declarations without splitting
// semicolons inside quoted values, functions, or comments.
func lexicalCSSDeclarations(style string) []string {
	var declarations []string
	depth := 0
	var quote byte
	var clean strings.Builder
	for offset := 0; offset < len(style); offset++ {
		value := style[offset]
		if quote != 0 {
			clean.WriteByte(value)
			if value == '\\' && offset+1 < len(style) {
				offset++
				clean.WriteByte(style[offset])
			} else if value == quote {
				quote = 0
			}
			continue
		}
		if value == '/' && offset+1 < len(style) && style[offset+1] == '*' {
			if end := strings.Index(style[offset+2:], "*/"); end >= 0 {
				offset += end + 3
				continue
			}
			break
		}
		switch value {
		case '\'', '"':
			quote = value
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ';':
			if depth == 0 {
				declarations = append(declarations, clean.String())
				clean.Reset()
				continue
			}
		}
		clean.WriteByte(value)
	}
	declarations = append(declarations, clean.String())
	return declarations
}

// lexicalHiddenSubtreeEnd finds the matching closing tag, including nested
// instances of the same element. Unclosed hidden elements remain hidden to EOF.
func lexicalHiddenSubtreeEnd(source, lower string, offset int, name string) (int, bool) {
	if lexicalVoidElement(name) {
		return offset, true
	}
	depth := 1
	var scope []string
	for offset < len(source) {
		relative := strings.IndexByte(source[offset:], '<')
		if relative < 0 {
			break
		}
		opening := offset + relative
		if strings.HasPrefix(lower[opening:], "<!--") {
			end, found := lexicalCommentEnd(source, opening+4)
			if !found {
				break
			}
			offset = end
			continue
		}
		if !lexicalMarkupStart(source, opening) {
			offset = opening + 1
			continue
		}
		closing, found := lexicalTagEnd(source, opening+1)
		if !found {
			break
		}
		rawTag := source[opening+1 : closing]
		tag, isClosing := lexicalTagName(rawTag)
		isOpeningTag := !isClosing && lexicalExactOpeningTag(rawTag, tag)
		isClosingTag := isClosing && lexicalExactClosingTag(rawTag, tag)
		optionalEnd := lexicalOptionalEndElement(name)
		if optionalEnd {
			if end, found := lexicalImplicitHiddenEnd(name, tag, opening, closing, isOpeningTag, isClosingTag, scope); found {
				return end, true
			}
		}
		if tag == "plaintext" && isOpeningTag {
			// PLAINTEXT changes the tokenizer state through EOF. Apparent closing
			// tags after it remain children of the hidden element as text.
			return 0, false
		} else if optionalEnd {
			scope = lexicalUpdateHiddenScope(scope, name, tag, isOpeningTag, isClosingTag)
		} else if tag == name {
			if isClosing && lexicalExactClosingTag(rawTag, name) {
				depth--
				if depth == 0 {
					return closing + 1, true
				}
			} else if !isClosing && lexicalExactOpeningTag(rawTag, name) {
				depth++
			}
		} else if !isClosing && lexicalExactOpeningTag(rawTag, tag) && lexicalRawTextElement(tag) {
			_, end, found := lexicalElementEnd(source, lower, closing+1, tag)
			if !found {
				break
			}
			offset = end
			continue
		}
		offset = closing + 1
	}
	return 0, false
}

func lexicalOptionalEndElement(name string) bool {
	switch name {
	case "p", "li", "dt", "dd", "td", "th", "tr":
		return true
	default:
		return false
	}
}

// lexicalImplicitHiddenEnd mirrors the HTML tree builder's implied endings
// for the optional-end elements that commonly structure email. It returns the
// opening byte of an implied closer so the outer extractor reprocesses that
// tag, or the byte after an explicit closing tag.
func lexicalImplicitHiddenEnd(root, tag string, opening, closing int, isOpening, isClosing bool, scope []string) (int, bool) {
	switch root {
	case "p":
		if isClosing && tag == root && len(scope) == 0 {
			return closing + 1, true
		}
		if len(scope) != 0 {
			return 0, false
		}
		if isOpening && lexicalClosesParagraph(tag) || isClosing && lexicalEndsParagraphContainer(tag) {
			return opening, true
		}
	case "li":
		if isClosing && tag == root && len(scope) == 0 {
			return closing + 1, true
		}
		if isOpening && tag == root && len(scope) == 0 {
			return opening, true
		}
		if isClosing && lexicalListContainer(tag) && !lexicalScopeContains(scope, lexicalListContainer) {
			return opening, true
		}
	case "dt", "dd":
		if isClosing && tag == root && len(scope) == 0 {
			return closing + 1, true
		}
		if isOpening && (tag == "dt" || tag == "dd") && len(scope) == 0 {
			return opening, true
		}
		if isClosing && tag == "dl" && !lexicalScopeContainsTag(scope, "dl") {
			return opening, true
		}
	case "td", "th":
		if isClosing && tag == root && len(scope) == 0 {
			return closing + 1, true
		}
		if len(scope) == 0 && (isOpening && lexicalClosesTableCell(tag) || isClosing && lexicalEndsTableCell(tag)) {
			return opening, true
		}
	case "tr":
		if isClosing && tag == root && len(scope) == 0 {
			return closing + 1, true
		}
		if len(scope) == 0 && (isOpening && lexicalClosesTableRow(tag) || isClosing && lexicalEndsTableRow(tag)) {
			return opening, true
		}
	}
	return 0, false
}

func lexicalUpdateHiddenScope(scope []string, root, tag string, isOpening, isClosing bool) []string {
	if isClosing {
		for index := len(scope) - 1; index >= 0; index-- {
			if scope[index] == tag {
				return scope[:index]
			}
		}
		return scope
	}
	if !isOpening || lexicalVoidElement(tag) || !lexicalHiddenScopeBarrier(root, tag, len(scope) > 0) {
		return scope
	}
	return append(scope, tag)
}

func lexicalHiddenScopeBarrier(root, tag string, insideBarrier bool) bool {
	switch root {
	case "p":
		if tag == "p" && insideBarrier {
			return true
		}
		switch tag {
		case "applet", "button", "caption", "html", "marquee", "object", "table", "td", "template", "th":
			return true
		}
	case "li", "dt", "dd":
		return lexicalListItemScopeBarrier(tag)
	case "td", "th", "tr":
		return tag == "table" || tag == "template"
	}
	return false
}

func lexicalClosesParagraph(tag string) bool {
	switch tag {
	case "address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div", "dl",
		"fieldset", "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header",
		"hgroup", "hr", "form", "listing", "main", "menu", "nav", "ol", "p", "plaintext", "pre", "search",
		"section", "summary", "table", "ul", "xmp":
		return true
	default:
		return false
	}
}

func lexicalEndsParagraphContainer(tag string) bool {
	switch tag {
	case "address", "article", "aside", "blockquote", "button", "center", "details", "dialog", "dir", "div",
		"dl", "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "listing", "main", "menu",
		"nav", "ol", "pre", "search", "section", "select", "summary", "ul":
		return true
	default:
		return false
	}
}

func lexicalListContainer(tag string) bool { return tag == "ol" || tag == "ul" || tag == "menu" }

func lexicalListItemScopeBarrier(tag string) bool {
	switch tag {
	case "applet", "article", "aside", "blockquote", "button", "caption", "center", "details", "dialog", "dir",
		"dl", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6",
		"header", "hgroup", "html", "li", "listing", "main", "marquee", "menu", "nav", "object", "ol",
		"pre", "search", "section", "select", "summary", "table", "tbody", "td", "template", "tfoot", "th",
		"thead", "tr", "ul":
		return true
	default:
		return false
	}
}

func lexicalClosesTableCell(tag string) bool {
	switch tag {
	case "caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr":
		return true
	default:
		return false
	}
}

func lexicalEndsTableCell(tag string) bool {
	switch tag {
	case "table", "tbody", "tfoot", "thead", "tr":
		return true
	default:
		return false
	}
}

func lexicalClosesTableRow(tag string) bool {
	switch tag {
	case "caption", "col", "colgroup", "tbody", "tfoot", "thead", "tr":
		return true
	default:
		return false
	}
}

func lexicalEndsTableRow(tag string) bool {
	switch tag {
	case "table", "tbody", "tfoot", "thead":
		return true
	default:
		return false
	}
}

func lexicalScopeContainsTag(scope []string, wanted string) bool {
	for _, tag := range scope {
		if tag == wanted {
			return true
		}
	}
	return false
}

func lexicalScopeContains(scope []string, predicate func(string) bool) bool {
	for _, tag := range scope {
		if predicate(tag) {
			return true
		}
	}
	return false
}

func lexicalVoidElement(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}
