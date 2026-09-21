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
		closing, found, _ := lexicalTagEnd(source, opening+1)
		if !found {
			break
		}
		rawTag := source[opening+1 : closing]
		tag, isClosing := lexicalTagName(rawTag)
		if tag == name {
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

func lexicalVoidElement(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}
