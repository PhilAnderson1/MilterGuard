package message

import (
	stdhtml "html"
	"net/url"
	"regexp"
	"strings"
)

// lexicalHTMLExtractor deliberately does not construct a DOM. Email HTML is
// frequently malformed or deliberately adversarial; this extractor treats the
// next '>' as the end of a tag regardless of broken attribute quoting.
type lexicalHTMLExtractor struct{}

var (
	lexicalSoftLineBreak = regexp.MustCompile(`=\r?\n`)
)

type lexicalAnchor struct {
	href         string
	contentStart int
	markdown     bool
}

func htmlToText(source string) extractedContent {
	return (lexicalHTMLExtractor{}).extract(source)
}

func (lexicalHTMLExtractor) extract(source string) extractedContent {
	// Repair quoted-printable soft wrapping found inside parts incorrectly
	// labelled as 8bit. This also rejoins split entity names such as &zwnj;.
	source = lexicalSoftLineBreak.ReplaceAllString(source, "")
	lower := strings.ToLower(source)

	var text strings.Builder
	var links, imageRefs []string
	var anchorStack []lexicalAnchor
	for offset := 0; offset < len(source); {
		opening := strings.IndexByte(source[offset:], '<')
		if opening < 0 {
			text.WriteString(source[offset:])
			break
		}
		opening += offset
		text.WriteString(source[offset:opening])

		if strings.HasPrefix(lower[opening:], "<!--") {
			closing := strings.Index(lower[opening+4:], "-->")
			if closing < 0 {
				break
			}
			offset = opening + 4 + closing + 3
			continue
		}

		closing := strings.IndexByte(source[opening+1:], '>')
		if closing < 0 {
			// A lone '<' is more useful as text than silently dropping the tail.
			text.WriteString(source[opening:])
			break
		}
		closing += opening + 1
		rawTag := source[opening+1 : closing]
		name, isClosing := lexicalTagName(rawTag)

		if !isClosing && lexicalHiddenElement(name) {
			closingPrefix := "</" + name
			blockEnd := strings.Index(lower[closing+1:], closingPrefix)
			if blockEnd < 0 {
				if recovery := lexicalHiddenRecovery(source, closing+1); recovery >= 0 {
					offset = recovery
					text.WriteByte(' ')
					continue
				}
				// With no recognizable content tag to recover at, the remaining
				// bytes belong to the malformed hidden element.
				offset = len(source)
				continue
			}
			blockEnd += closing + 1
			endTag := strings.IndexByte(source[blockEnd+len(closingPrefix):], '>')
			if endTag < 0 {
				break
			}
			offset = blockEnd + len(closingPrefix) + endTag + 1
			text.WriteByte(' ')
			continue
		}

		switch {
		case name == "blockquote" && !isClosing:
			text.WriteString("\n[quoted content begins]\n")
		case name == "blockquote" && isClosing:
			text.WriteString("\n[quoted content ends]\n")
		case name == "a" && !isClosing:
			href, valid := lexicalHTTPURL(lexicalAttribute(rawTag, "href"))
			anchor := lexicalAnchor{href: href, markdown: valid}
			if valid {
				text.WriteByte('[')
				anchor.contentStart = text.Len()
			}
			anchorStack = append(anchorStack, anchor)
		case name == "a" && isClosing:
			if len(anchorStack) > 0 {
				anchor := anchorStack[len(anchorStack)-1]
				anchorStack = anchorStack[:len(anchorStack)-1]
				closeLexicalAnchor(&text, &links, anchor)
			}
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
					imageRefs = append(imageRefs, contentID)
				}
			} else if src, valid := lexicalHTTPURL(src); valid {
				alt := markdownLabel(lexicalAttribute(rawTag, "alt"))
				if alt == "" {
					alt = "image"
				}
				text.WriteString(" ![")
				text.WriteString(alt)
				text.WriteString("](")
				text.WriteString(markdownURL(src))
				text.WriteString(") ")
				links = append(links, src)
			}
		case lexicalBlockElement(name):
			text.WriteByte('\n')
		}
		offset = closing + 1
	}
	for len(anchorStack) > 0 {
		anchor := anchorStack[len(anchorStack)-1]
		anchorStack = anchorStack[:len(anchorStack)-1]
		closeLexicalAnchor(&text, &links, anchor)
	}

	decoded := stdhtml.UnescapeString(text.String())
	flatText := strings.Join(strings.Fields(decoded), " ")
	visibleText := lexicalVisibleText(decoded)
	links = append(links, findHTTPURLs(flatText)...)
	return extractedContent{Text: flatText, VisibleText: visibleText, Links: links, ImageRefs: imageRefs}
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
		switch {
		case offset+3 <= len(raw) && strings.EqualFold(raw[offset:offset+3], "=3d"):
			offset += 3
		case offset < len(raw) && raw[offset] == '=':
			offset++
		default:
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
			value := strings.TrimSpace(stdhtml.UnescapeString(raw[valueStart:valueEnd]))
			return strings.ReplaceAll(value, "=3D", "=")
		}
	}
	return ""
}

func lexicalSpace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f'
}

func lexicalAttributeNameByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9') || value == '-' || value == '_' || value == ':'
}

func lexicalHiddenRecovery(source string, offset int) int {
	for offset < len(source) {
		relative := strings.IndexByte(source[offset:], '<')
		if relative < 0 {
			return -1
		}
		candidate := offset + relative
		end := strings.IndexByte(source[candidate+1:], '>')
		if end < 0 {
			return -1
		}
		end += candidate + 1
		name, closing := lexicalTagName(source[candidate+1 : end])
		if lexicalRecoveryElement(name, closing) {
			return candidate
		}
		offset = end + 1
	}
	return -1
}

func lexicalRecoveryElement(name string, closing bool) bool {
	if closing {
		return name == "head"
	}
	if name == "body" || name == "blockquote" || name == "a" || name == "img" || name == "span" || name == "section" || name == "article" || name == "main" || name == "header" || name == "footer" {
		return true
	}
	return lexicalBlockElement(name)
}

func closeLexicalAnchor(text *strings.Builder, links *[]string, anchor lexicalAnchor) {
	if !anchor.markdown {
		return
	}
	if text.Len() == anchor.contentStart {
		text.WriteString("link")
	}
	text.WriteString("](")
	text.WriteString(markdownURL(anchor.href))
	text.WriteString(")")
	*links = append(*links, anchor.href)
}

func lexicalHTTPURL(value string) (string, bool) {
	value = strings.TrimSpace(sanitize(value))
	parsed, err := url.Parse(value)
	return value, err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != ""
}

func markdownLabel(value string) string {
	value = strings.Join(strings.Fields(sanitize(stdhtml.UnescapeString(value))), " ")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "[", `\[`)
	return strings.ReplaceAll(value, "]", `\]`)
}

func markdownURL(value string) string {
	replacer := strings.NewReplacer(" ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E")
	return replacer.Replace(value)
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
	return name == "style" || name == "script" || name == "noscript"
}

func lexicalBlockElement(name string) bool {
	switch name {
	case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6":
		return true
	default:
		return false
	}
}
