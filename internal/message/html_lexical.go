package message

import (
	stdhtml "html"
	"net/url"
	"strings"
	"unicode"
)

// lexicalHTMLExtractor deliberately does not construct a DOM. Email HTML is
// frequently malformed or deliberately adversarial, so this extractor scans
// tag boundaries while retaining only the evidence needed by the AI prompt.
type lexicalHTMLExtractor struct{}

var markdownURLReplacer = strings.NewReplacer(
	"\\", "%5C",
	" ", "%20",
	"(", "%28",
	")", "%29",
	"<", "%3C",
	">", "%3E",
)

type lexicalAnchor struct {
	href       string
	label      strings.Builder
	plainLabel strings.Builder
}

type lexicalOutput struct {
	text   strings.Builder
	anchor *lexicalAnchor
}

type lexicalLinkCollector struct {
	links []string
	seen  map[string]struct{}
	chars int
}

type imageRefCollector struct {
	refs  []string
	seen  map[string]struct{}
	chars int
}

func (collector *imageRefCollector) Add(candidate string) {
	candidate = normalizeContentID(candidate)
	if candidate == "" {
		return
	}
	if collector.seen == nil {
		collector.seen = make(map[string]struct{})
	}
	if _, found := collector.seen[candidate]; found {
		return
	}
	candidateChars := len([]rune(candidate))
	if len(collector.refs) >= maxExtractedLinks || candidateChars > maxExtractedLinkLength || collector.chars+candidateChars > maxExtractedLinkChars {
		return
	}
	collector.seen[candidate] = struct{}{}
	collector.refs = append(collector.refs, candidate)
	collector.chars += candidateChars
}

func (collector *imageRefCollector) AddAll(candidates []string) {
	for _, candidate := range candidates {
		collector.Add(candidate)
	}
}

func (collector *lexicalLinkCollector) Add(candidate string) {
	candidate = strings.TrimSpace(stripInvisibleFormatting(candidate))
	if candidate == "" {
		return
	}
	if collector.seen == nil {
		collector.seen = make(map[string]struct{})
	}
	if _, found := collector.seen[candidate]; found {
		return
	}
	parsed, err := url.Parse(candidate)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return
	}
	candidateChars := len([]rune(candidate))
	if len(collector.links) >= maxExtractedLinks || candidateChars > maxExtractedLinkLength || collector.chars+candidateChars > maxExtractedLinkChars {
		return
	}
	collector.seen[candidate] = struct{}{}
	collector.seen[markdownURL(candidate)] = struct{}{}
	collector.links = append(collector.links, candidate)
	collector.chars += candidateChars
}

func (collector *lexicalLinkCollector) AddAll(candidates []string) {
	for _, candidate := range candidates {
		collector.Add(candidate)
	}
}

func (output *lexicalOutput) WriteString(value string) {
	if output.anchor != nil {
		output.anchor.label.WriteString(value)
		output.anchor.plainLabel.WriteString(value)
		return
	}
	output.text.WriteString(value)
}

func (output *lexicalOutput) WriteByte(value byte) {
	if output.anchor != nil {
		output.anchor.label.WriteByte(value)
		output.anchor.plainLabel.WriteByte(value)
		return
	}
	output.text.WriteByte(value)
}

func (output *lexicalOutput) finishAnchor(links *lexicalLinkCollector, markdown bool) {
	if output.anchor == nil {
		return
	}
	anchor := output.anchor
	output.anchor = nil
	label := anchor.label.String()
	if markdown {
		leadingSpace := len(strings.TrimLeftFunc(label, unicode.IsSpace)) != len(label)
		trailingSpace := len(strings.TrimRightFunc(label, unicode.IsSpace)) != len(label)
		label = strings.TrimSpace(label)
		if label == "" {
			label = "link"
		}
		if leadingSpace {
			output.text.WriteByte(' ')
		}
		output.text.WriteByte('[')
		output.text.WriteString(label)
		output.text.WriteString("](")
		output.text.WriteString(markdownURL(anchor.href))
		output.text.WriteByte(')')
		if trailingSpace {
			output.text.WriteByte(' ')
		}
	} else {
		output.text.WriteString(anchor.plainLabel.String())
	}
	links.Add(anchor.href)
}

func htmlToText(source string) extractedContent {
	return (lexicalHTMLExtractor{}).extract(source)
}

func (lexicalHTMLExtractor) extract(source string) extractedContent {
	// HTML syntax is ASCII. Keep this copy byte-for-byte aligned with source so
	// byte offsets found in one string are always safe to use in the other.
	lower := lexicalASCIILower(source)

	var text lexicalOutput
	var links lexicalLinkCollector
	var imageRefs imageRefCollector
	var baseURL *url.URL
	baseSeen := false
	for offset := 0; offset < len(source); {
		opening := strings.IndexByte(source[offset:], '<')
		if opening < 0 {
			lexicalWriteDecodedText(&text, source[offset:])
			break
		}
		opening += offset
		lexicalWriteDecodedText(&text, source[offset:opening])
		if !lexicalMarkupStart(source, opening) {
			text.WriteByte('<')
			offset = opening + 1
			continue
		}

		if strings.HasPrefix(lower[opening:], "<!--") {
			commentEnd, found := lexicalCommentEnd(source, opening+4)
			if !found {
				break
			}
			offset = commentEnd
			continue
		}

		closing, found, unterminatedQuote := lexicalTagEnd(source, opening+1)
		if !found {
			// A lone '<' is more useful as text than silently dropping the tail.
			// An unfinished quoted tag, however, remains markup through EOF in
			// HTML tokenizers and must not become AI-only visible text.
			if !unterminatedQuote {
				lexicalWriteDecodedText(&text, source[opening:])
			}
			break
		}
		rawTag := source[opening+1 : closing]
		name, isClosing := lexicalTagName(rawTag)

		if !isClosing && lexicalExactOpeningTag(rawTag, name) && lexicalHiddenElement(name) {
			var blockEnd int
			var found bool
			if name == "template" {
				blockEnd, found = lexicalTemplateEnd(source, lower, closing+1)
			} else {
				_, blockEnd, found = lexicalElementEnd(source, lower, closing+1, name)
			}
			if !found {
				offset = len(source)
				continue
			}
			offset = blockEnd
			text.WriteByte(' ')
			continue
		}
		if !isClosing && lexicalExactOpeningTag(rawTag, name) && name == "plaintext" {
			// The HTML plaintext state has no closing tag: every remaining byte is
			// text through EOF, including strings that resemble HTML markup.
			text.WriteUntrustedString(source[closing+1:])
			offset = len(source)
			continue
		}
		if !isClosing && lexicalExactOpeningTag(rawTag, name) && lexicalVisibleRawElement(name) {
			closingStart, blockEnd, found := lexicalElementEnd(source, lower, closing+1, name)
			if !found {
				if name == "textarea" {
					lexicalWriteDecodedText(&text, source[closing+1:])
				} else {
					text.WriteUntrustedString(source[closing+1:])
				}
				offset = len(source)
				continue
			}
			if name == "textarea" {
				lexicalWriteDecodedText(&text, source[closing+1:closingStart])
			} else {
				text.WriteUntrustedString(source[closing+1 : closingStart])
			}
			offset = blockEnd
			continue
		}

		switch {
		case name == "base" && !isClosing:
			// HTML uses only the first base element with an href. Remember that
			// occurrence even when it is invalid so a later attacker-controlled
			// base cannot be interpreted differently from the recipient's client.
			if !baseSeen {
				if rawBase, present := lexicalAttributeValue(rawTag, "href"); present {
					baseSeen = true
					if absolute, valid := lexicalHTTPURL(rawBase); valid {
						baseURL, _ = url.Parse(absolute)
					}
				}
			}
		case name == "blockquote" && !isClosing:
			text.WriteString("\n[quoted content begins]\n")
		case name == "blockquote" && isClosing:
			text.WriteString("\n[quoted content ends]\n")
		case name == "a" && !isClosing:
			// HTML does not nest anchors; a new opening anchor implicitly ends
			// the previous one.
			text.finishAnchor(&links, true)
			href, valid := lexicalResolvedHTTPURL(lexicalAttribute(rawTag, "href"), baseURL)
			if valid {
				text.anchor = &lexicalAnchor{href: href}
			}
		case name == "a" && isClosing:
			text.finishAnchor(&links, true)
		case name == "img" && !isClosing:
			src := lexicalAttribute(rawTag, "src")
			if len(src) > 4 && strings.EqualFold(src[:4], "cid:") {
				contentID := normalizeContentID(src[4:])
				if contentID != "" {
					alt := markdownLabel(lexicalAttribute(rawTag, "alt"))
					if alt == "" {
						alt = "embedded image"
					}
					text.WriteString(" ![")
					text.WriteString(alt)
					text.WriteString("](cid:")
					text.WriteString(markdownURL(contentID))
					text.WriteString(") ")
					imageRefs.Add(contentID)
				}
			} else if src, valid := lexicalResolvedHTTPURL(src, baseURL); valid {
				alt := markdownLabel(lexicalAttribute(rawTag, "alt"))
				if alt == "" {
					alt = "image"
				}
				text.WriteString(" ![")
				text.WriteString(alt)
				text.WriteString("](")
				text.WriteString(markdownURL(src))
				text.WriteString(") ")
				links.Add(src)
			}
		case lexicalBlockElement(name):
			text.WriteByte('\n')
		}
		offset = closing + 1
	}
	// An unclosed anchor may consume a large malformed tail. Preserve its label
	// as ordinary text and retain the destination as independent link evidence.
	text.finishAnchor(&links, false)

	decoded := text.text.String()
	flatText := strings.Join(strings.Fields(decoded), " ")
	visibleText := lexicalVisibleText(decoded)
	links.AddAll(findHTTPURLs(flatText))
	return extractedContent{Text: flatText, VisibleText: visibleText, Links: links.links, ImageRefs: imageRefs.refs}
}

func lexicalWriteDecodedText(text *lexicalOutput, value string) {
	text.WriteUntrustedString(stdhtml.UnescapeString(value))
}

// WriteUntrustedString preserves ordinary text while preventing attacker-controlled
// anchor labels from changing the structure of the Markdown emitted for a link.
// Keep the unescaped form separately for an unclosed anchor, which is deliberately
// emitted as plain text rather than Markdown.
func (output *lexicalOutput) WriteUntrustedString(value string) {
	if output.anchor == nil {
		output.text.WriteString(value)
		return
	}
	output.anchor.label.WriteString(markdownLabelText(value))
	output.anchor.plainLabel.WriteString(value)
}

func lexicalCommentEnd(source string, contentStart int) (int, bool) {
	if contentStart >= len(source) {
		return 0, false
	}
	// These are the HTML tokenizer's abrupt empty-comment endings.
	if source[contentStart] == '>' {
		return contentStart + 1, true
	}
	if source[contentStart] == '-' && contentStart+1 < len(source) && source[contentStart+1] == '>' {
		return contentStart + 2, true
	}
	for offset := contentStart; offset < len(source); offset++ {
		if strings.HasPrefix(source[offset:], "-->") {
			return offset + 3, true
		}
		if strings.HasPrefix(source[offset:], "--!>") {
			return offset + 4, true
		}
	}
	return 0, false
}

func lexicalASCIILower(source string) string {
	lower := []byte(source)
	for index, value := range lower {
		if value >= 'A' && value <= 'Z' {
			lower[index] = value + ('a' - 'A')
		}
	}
	return string(lower)
}

func lexicalMarkupStart(source string, opening int) bool {
	if opening+1 >= len(source) {
		return false
	}
	next := source[opening+1]
	if lexicalASCIILetter(next) || next == '!' || next == '?' {
		return true
	}
	return next == '/' && opening+2 < len(source) && lexicalASCIILetter(source[opening+2])
}

func lexicalASCIILetter(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func lexicalTagEnd(source string, offset int) (end int, found, unterminatedQuote bool) {
	var quote byte
	for offset < len(source) {
		value := source[offset]
		if quote != 0 {
			if value == quote {
				quote = 0
			}
			offset++
			continue
		}
		switch value {
		case '\'', '"':
			quote = value
		case '>':
			return offset, true, false
		}
		offset++
	}
	return 0, false, quote != 0
}

func lexicalExactOpeningTag(rawTag, name string) bool {
	rawTag = strings.TrimLeft(rawTag, " \t\r\n\f")
	if name == "" || strings.HasPrefix(rawTag, "/") || len(rawTag) < len(name) || !strings.EqualFold(rawTag[:len(name)], name) {
		return false
	}
	return len(rawTag) == len(name) || lexicalSpace(rawTag[len(name)]) || rawTag[len(name)] == '/'
}

func lexicalExactClosingTag(rawTag, name string) bool {
	rawTag = strings.TrimLeft(rawTag, " \t\r\n\f")
	if !strings.HasPrefix(rawTag, "/") {
		return false
	}
	rawTag = strings.TrimLeft(rawTag[1:], " \t\r\n\f")
	if name == "" || len(rawTag) < len(name) || !strings.EqualFold(rawTag[:len(name)], name) {
		return false
	}
	return len(rawTag) == len(name) || lexicalSpace(rawTag[len(name)]) || rawTag[len(name)] == '/'
}

func lexicalClosingTagStart(lower string, offset int, name string) int {
	prefix := "</" + name
	for offset < len(lower) {
		relative := strings.Index(lower[offset:], prefix)
		if relative < 0 {
			return -1
		}
		candidate := offset + relative
		afterName := candidate + len(prefix)
		if afterName < len(lower) && (lower[afterName] == '>' || lower[afterName] == '/' || lexicalSpace(lower[afterName])) {
			return candidate
		}
		offset = candidate + len(prefix)
	}
	return -1
}

func lexicalElementEnd(source, lower string, offset int, name string) (closingStart, blockEnd int, found bool) {
	closingStart = lexicalClosingTagStart(lower, offset, name)
	if closingStart < 0 {
		return 0, 0, false
	}
	closingEnd, found, _ := lexicalTagEnd(source, closingStart+1)
	if !found {
		return 0, 0, false
	}
	return closingStart, closingEnd + 1, true
}

func lexicalTemplateEnd(source, lower string, offset int) (int, bool) {
	depth := 1
	for offset < len(source) {
		relative := strings.IndexByte(source[offset:], '<')
		if relative < 0 {
			return 0, false
		}
		opening := offset + relative
		if strings.HasPrefix(lower[opening:], "<!--") {
			commentEnd, found := lexicalCommentEnd(source, opening+4)
			if !found {
				return 0, false
			}
			offset = commentEnd
			continue
		}
		closing, found, _ := lexicalTagEnd(source, opening+1)
		if !found {
			return 0, false
		}
		rawTag := source[opening+1 : closing]
		name, isClosing := lexicalTagName(rawTag)
		switch {
		case name == "template" && !isClosing && lexicalExactOpeningTag(rawTag, name):
			depth++
		case name == "template" && isClosing && lexicalExactClosingTag(rawTag, name):
			depth--
			if depth == 0 {
				return closing + 1, true
			}
		case !isClosing && lexicalExactOpeningTag(rawTag, name) && lexicalRawTextElement(name):
			_, rawEnd, found := lexicalElementEnd(source, lower, closing+1, name)
			if !found {
				return 0, false
			}
			offset = rawEnd
			continue
		}
		offset = closing + 1
	}
	return 0, false
}

func lexicalTagName(raw string) (string, bool) {
	raw = strings.TrimLeft(raw, " \t\r\n")
	isClosing := strings.HasPrefix(raw, "/")
	if isClosing {
		raw = strings.TrimLeft(raw[1:], " \t\r\n")
	}
	end := 0
	for end < len(raw) {
		c := raw[end]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			break
		}
		end++
	}
	return strings.ToLower(raw[:end]), isClosing
}

func lexicalAttribute(raw, wanted string) string {
	value, _ := lexicalAttributeValue(raw, wanted)
	return value
}

func lexicalAttributeValue(raw, wanted string) (string, bool) {
	offset := 0
	for offset < len(raw) && !lexicalSpace(raw[offset]) {
		offset++
	}
	for offset < len(raw) {
		for offset < len(raw) && lexicalSpace(raw[offset]) {
			offset++
		}
		start := offset
		for offset < len(raw) && lexicalAttributeNameByte(raw[offset]) {
			offset++
		}
		if start == offset {
			offset++
			continue
		}
		name := raw[start:offset]
		for offset < len(raw) && lexicalSpace(raw[offset]) {
			offset++
		}
		if offset < len(raw) && raw[offset] == '=' {
			offset++
		} else {
			if strings.EqualFold(name, wanted) {
				return "", true
			}
			continue
		}
		for offset < len(raw) && lexicalSpace(raw[offset]) {
			offset++
		}
		valueStart, valueEnd := offset, offset
		if offset < len(raw) && (raw[offset] == '\'' || raw[offset] == '"') {
			quote := raw[offset]
			valueStart = offset + 1
			offset = valueStart
			for offset < len(raw) && raw[offset] != quote {
				offset++
			}
			valueEnd = offset
			if offset < len(raw) {
				offset++
			}
		} else {
			for offset < len(raw) && !lexicalSpace(raw[offset]) {
				offset++
			}
			valueEnd = offset
		}
		if strings.EqualFold(name, wanted) {
			return strings.TrimSpace(stdhtml.UnescapeString(raw[valueStart:valueEnd])), true
		}
	}
	return "", false
}

func lexicalSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f'
}

func lexicalAttributeNameByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '-' || value == '_' || value == ':'
}

func lexicalHTTPURL(value string) (string, bool) {
	// Browsers remove ASCII tab and newline characters anywhere in a URL before
	// parsing it. Match that behavior so the prompt contains the destination the
	// recipient's mail client will actually navigate to.
	value = stripInvisibleFormatting(lexicalBrowserURL(value))
	parsed, err := url.Parse(value)
	return value, err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != ""
}

func lexicalResolvedHTTPURL(value string, base *url.URL) (string, bool) {
	value = lexicalBrowserURL(value)
	if value == "" {
		return "", false
	}
	reference, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if !reference.IsAbs() {
		if base == nil {
			return "", false
		}
		value = base.ResolveReference(reference).String()
	}
	return lexicalHTTPURL(value)
}

func lexicalBrowserURL(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(value))
}

func markdownLabel(value string) string {
	value = strings.Join(strings.Fields(sanitize(value)), " ")
	return markdownLabelText(value)
}

func markdownLabelText(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "[", `\[`)
	return strings.ReplaceAll(value, "]", `\]`)
}

func markdownURL(value string) string {
	return markdownURLReplacer.Replace(value)
}

func lexicalVisibleText(value string) string {
	lines := strings.Split(value, "\n")
	clean := lines[:0]
	for _, line := range lines {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			clean = append(clean, line)
		}
	}
	return strings.Join(clean, "\n")
}

func lexicalHiddenElement(name string) bool {
	return name == "style" || name == "script" || name == "template" || name == "iframe" || name == "title"
}

func lexicalVisibleRawElement(name string) bool {
	return name == "textarea" || name == "xmp" || name == "noembed" || name == "noframes"
}

func lexicalRawTextElement(name string) bool {
	return name == "style" || name == "script" || name == "iframe" || name == "title" || lexicalVisibleRawElement(name)
}

func lexicalBlockElement(name string) bool {
	switch name {
	case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6":
		return true
	default:
		return false
	}
}
