package message

import (
	stdhtml "html"
	"regexp"
	"strings"
)

// lexicalHTMLExtractor deliberately does not construct a DOM. Email HTML is
// frequently malformed or deliberately adversarial; this extractor treats the
// next '>' as the end of a tag regardless of broken attribute quoting.
type lexicalHTMLExtractor struct{}

var (
	lexicalSoftLineBreak = regexp.MustCompile(`=\r?\n`)
	lexicalHrefPattern   = regexp.MustCompile(`(?is)\bhref\s*(?:=3d|=)\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
	lexicalSrcPattern    = regexp.MustCompile(`(?is)\bsrc\s*(?:=3d|=)\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func htmlToText(source string) extractedContent {
	return (lexicalHTMLExtractor{}).extract(source)
}

func (lexicalHTMLExtractor) extract(source string) extractedContent {
	// Repair quoted-printable soft wrapping found inside parts incorrectly
	// labelled as 8bit. This also rejoins split entity names such as &zwnj;.
	source = lexicalSoftLineBreak.ReplaceAllString(source, "")
	lower := strings.ToLower(source)

	var text strings.Builder
	var links, imageRefs, anchorStack []string
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
				break
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
			anchorStack = append(anchorStack, lexicalAttribute(rawTag, lexicalHrefPattern))
		case name == "a" && isClosing:
			if len(anchorStack) > 0 {
				href := anchorStack[len(anchorStack)-1]
				anchorStack = anchorStack[:len(anchorStack)-1]
				writeLexicalLink(&text, &links, href)
			}
		case name == "img" && !isClosing:
			src := lexicalAttribute(rawTag, lexicalSrcPattern)
			if len(src) > 4 && strings.EqualFold(src[:4], "cid:") {
				imageRefs = append(imageRefs, normalizeContentID(src[4:]))
			}
		case lexicalBlockElement(name):
			text.WriteByte('\n')
		}
		offset = closing + 1
	}
	for len(anchorStack) > 0 {
		href := anchorStack[len(anchorStack)-1]
		anchorStack = anchorStack[:len(anchorStack)-1]
		writeLexicalLink(&text, &links, href)
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

func lexicalAttribute(raw string, pattern *regexp.Regexp) string {
	match := pattern.FindStringSubmatch(raw)
	if len(match) != 4 {
		return ""
	}
	for _, value := range match[1:] {
		if value != "" {
			return strings.ReplaceAll(strings.TrimSpace(stdhtml.UnescapeString(value)), "=3D", "=")
		}
	}
	return ""
}

func writeLexicalLink(text *strings.Builder, links *[]string, href string) {
	if href == "" {
		return
	}
	text.WriteString(" [link: ")
	text.WriteString(sanitize(href))
	text.WriteString("] ")
	*links = append(*links, href)
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
