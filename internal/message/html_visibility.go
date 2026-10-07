package message

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

type lexicalHiddenKind uint8

const (
	lexicalNotHidden     lexicalHiddenKind = 0
	lexicalDisplayHidden lexicalHiddenKind = 1 << iota
	lexicalVisibilityHidden
	lexicalFontSizeHidden
)

type lexicalVisibilityDecision struct {
	hidden                lexicalHiddenKind
	explicitlyVisible     bool
	explicitlyNonzeroFont bool
}

// lexicalElementVisibility recognizes only explicit, high-confidence
// visibility on the element itself. It does not try to compute stylesheet
// rules or layout.
func lexicalElementVisibility(rawTag string) lexicalVisibilityDecision {
	hiddenValue, hidden := lexicalAttributeValue(rawTag, "hidden")
	hiddenUntilFound := hidden && strings.EqualFold(strings.TrimSpace(hiddenValue), "until-found")
	style, present := lexicalAttributeValue(rawTag, "style")
	if !present {
		if hidden {
			return lexicalVisibilityDecision{hidden: lexicalDisplayHidden}
		}
		return lexicalVisibilityDecision{}
	}
	var display, visibility, opacity, fontSize lexicalCSSChoice
	for _, declaration := range lexicalCSSDeclarations(style) {
		property, value, found := lexicalCSSDeclaration(declaration)
		if !found {
			continue
		}
		property = strings.ToLower(strings.TrimSpace(lexicalCSSUnescape(property)))
		value = strings.ToLower(strings.TrimSpace(lexicalCSSUnescape(value)))
		important := false
		if before, suffix, found := strings.Cut(value, "!"); found && strings.TrimSpace(suffix) == "important" {
			value = strings.TrimSpace(before)
			important = true
		}
		switch property {
		case "display":
			if lexicalValidDisplay(value) {
				display.set(value, important)
			}
		case "visibility":
			if lexicalValidVisibility(value) {
				visibility.set(value, important)
			}
		case "opacity":
			if lexicalValidOpacity(value) {
				opacity.set(value, important)
			}
		case "font-size":
			if lexicalFontSizeState(value) != lexicalFontSizeUnknown {
				fontSize.set(value, important)
			}
		}
	}
	if display.value == "none" || lexicalZeroOpacity(opacity.value) ||
		hiddenUntilFound || hidden && !lexicalDisplayOverridesHidden(display.value) {
		return lexicalVisibilityDecision{hidden: lexicalDisplayHidden}
	}
	decision := lexicalVisibilityDecision{
		explicitlyVisible:     visibility.value == "visible" || visibility.value == "initial",
		explicitlyNonzeroFont: lexicalFontSizeState(fontSize.value) == lexicalFontSizeNonzero,
	}
	if visibility.value == "hidden" || visibility.value == "collapse" {
		decision.hidden |= lexicalVisibilityHidden
	}
	if lexicalFontSizeState(fontSize.value) == lexicalFontSizeZero {
		decision.hidden |= lexicalFontSizeHidden
	}
	return decision
}

func lexicalValidOpacity(value string) bool {
	if value == "initial" || value == "inherit" || value == "unset" || value == "revert" || value == "revert-layer" {
		return true
	}
	percentage := strings.HasSuffix(value, "%")
	if percentage {
		value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return false
	}
	return true
}

func lexicalZeroOpacity(value string) bool {
	if !lexicalValidOpacity(value) {
		return false
	}
	value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && !math.IsNaN(number) && number <= 0
}

type lexicalFontSize uint8

const (
	lexicalFontSizeUnknown lexicalFontSize = iota
	lexicalFontSizeZero
	lexicalFontSizeNonzero
)

// lexicalFontSizeState recognizes only values whose effect is unambiguous
// without computed styles. Relative em/ex/% values cannot restore text below
// a zero-sized parent, while ordinary absolute lengths and keywords can.
func lexicalFontSizeState(value string) lexicalFontSize {
	switch value {
	case "xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "xxx-large", "initial":
		return lexicalFontSizeNonzero
	case "inherit", "unset", "revert", "revert-layer", "smaller", "larger", "":
		return lexicalFontSizeUnknown
	}

	unit := ""
	for _, candidate := range []string{"vmax", "vmin", "rem", "rlh", "cap", "ch", "em", "ex", "lh", "px", "pt", "pc", "in", "cm", "mm", "q", "vw", "vh", "%"} {
		if strings.HasSuffix(value, candidate) {
			unit = candidate
			value = strings.TrimSpace(strings.TrimSuffix(value, candidate))
			break
		}
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
		return lexicalFontSizeUnknown
	}
	if number == 0 {
		// CSS accepts a unitless zero as well as zero in any valid length.
		return lexicalFontSizeZero
	}
	if unit == "" || unit == "em" || unit == "ex" || unit == "ch" || unit == "cap" || unit == "lh" || unit == "rlh" || unit == "%" {
		return lexicalFontSizeUnknown
	}
	return lexicalFontSizeNonzero
}

// lexicalDisplayOverridesHidden reports whether a valid inline display value
// definitely replaces the user-agent display:none rule for the ordinary
// hidden state. Values that fall back to lower cascade origins remain
// conservative because an external stylesheet is intentionally not computed.
func lexicalDisplayOverridesHidden(value string) bool {
	return value != "" && value != "none" && value != "revert" && value != "revert-layer"
}

func lexicalValidVisibility(value string) bool {
	switch value {
	case "visible", "hidden", "collapse", "initial", "inherit", "unset", "revert", "revert-layer":
		return true
	default:
		return false
	}
}

// lexicalValidDisplay recognizes the CSS display grammar needed to avoid an
// invalid later declaration overriding an earlier valid declaration. It covers
// the standard single-keyword, legacy, internal, and multi-keyword forms.
func lexicalValidDisplay(value string) bool {
	fields := strings.Fields(value)
	if len(fields) == 1 {
		switch fields[0] {
		case "none", "contents",
			"block", "inline", "run-in",
			"flow", "flow-root", "table", "flex", "grid", "ruby", "math",
			"list-item",
			"inline-block", "inline-table", "inline-flex", "inline-grid",
			"table-row-group", "table-header-group", "table-footer-group", "table-row",
			"table-cell", "table-column-group", "table-column", "table-caption",
			"ruby-base", "ruby-text", "ruby-base-container", "ruby-text-container",
			"initial", "inherit", "unset", "revert", "revert-layer":
			return true
		default:
			return false
		}
	}
	if len(fields) < 2 || len(fields) > 3 {
		return false
	}
	var outside, inside, listItem bool
	for _, field := range fields {
		switch field {
		case "block", "inline", "run-in":
			if outside {
				return false
			}
			outside = true
		case "flow", "flow-root", "table", "flex", "grid", "ruby", "math":
			if inside {
				return false
			}
			inside = true
		case "list-item":
			if listItem {
				return false
			}
			listItem = true
		default:
			return false
		}
	}
	if listItem {
		return !inside || fieldsContainOnlyListInside(fields)
	}
	return outside && inside
}

func fieldsContainOnlyListInside(fields []string) bool {
	for _, field := range fields {
		if field == "table" || field == "flex" || field == "grid" || field == "ruby" || field == "math" {
			return false
		}
	}
	return true
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

// lexicalCSSDeclaration separates a property from its value at a literal CSS
// colon token. An escaped colon remains part of an identifier and must not be
// promoted into declaration syntax by unescaping it first.
func lexicalCSSDeclaration(declaration string) (string, string, bool) {
	var quote byte
	for offset := 0; offset < len(declaration); offset++ {
		value := declaration[offset]
		if value == '\\' {
			offset = lexicalCSSEscapeEnd(declaration, offset) - 1
			continue
		}
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			continue
		}
		if value == '\'' || value == '"' {
			quote = value
			continue
		}
		if value == ':' {
			return declaration[:offset], declaration[offset+1:], true
		}
	}
	return "", "", false
}

// lexicalCSSUnescape implements CSS escaped-code-point handling for the small
// inline-style subset used by visibility detection. Structural punctuation is
// located before this runs, so decoded punctuation cannot become CSS syntax.
func lexicalCSSUnescape(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var decoded strings.Builder
	decoded.Grow(len(value))
	for offset := 0; offset < len(value); {
		if value[offset] != '\\' {
			decoded.WriteByte(value[offset])
			offset++
			continue
		}
		offset++
		if offset >= len(value) {
			decoded.WriteRune(utf8.RuneError)
			break
		}
		if lexicalCSSNewlineLength(value, offset) > 0 {
			offset += lexicalCSSNewlineLength(value, offset)
			continue
		}
		if !lexicalCSSHex(value[offset]) {
			decoded.WriteByte(value[offset])
			offset++
			continue
		}
		hexStart := offset
		for offset < len(value) && offset-hexStart < 6 && lexicalCSSHex(value[offset]) {
			offset++
		}
		codePoint, err := strconv.ParseUint(value[hexStart:offset], 16, 32)
		if err != nil || codePoint == 0 || codePoint > utf8.MaxRune || codePoint >= 0xd800 && codePoint <= 0xdfff {
			decoded.WriteRune(utf8.RuneError)
		} else {
			decoded.WriteRune(rune(codePoint))
		}
		if offset < len(value) {
			if newlineLength := lexicalCSSNewlineLength(value, offset); newlineLength > 0 {
				offset += newlineLength
			} else if value[offset] == ' ' || value[offset] == '\t' {
				offset++
			}
		}
	}
	return decoded.String()
}

func lexicalCSSEscapeEnd(value string, offset int) int {
	offset++
	if offset >= len(value) {
		return offset
	}
	if newlineLength := lexicalCSSNewlineLength(value, offset); newlineLength > 0 {
		return offset + newlineLength
	}
	if !lexicalCSSHex(value[offset]) {
		return offset + 1
	}
	hexStart := offset
	for offset < len(value) && offset-hexStart < 6 && lexicalCSSHex(value[offset]) {
		offset++
	}
	if offset < len(value) {
		if newlineLength := lexicalCSSNewlineLength(value, offset); newlineLength > 0 {
			return offset + newlineLength
		}
		if value[offset] == ' ' || value[offset] == '\t' {
			return offset + 1
		}
	}
	return offset
}

func lexicalCSSNewlineLength(value string, offset int) int {
	if offset >= len(value) {
		return 0
	}
	switch value[offset] {
	case '\n', '\f':
		return 1
	case '\r':
		if offset+1 < len(value) && value[offset+1] == '\n' {
			return 2
		}
		return 1
	default:
		return 0
	}
}

func lexicalCSSHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
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
		if value == '\\' {
			end := lexicalCSSEscapeEnd(style, offset)
			clean.WriteString(style[offset:end])
			offset = end - 1
			continue
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
