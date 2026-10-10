package message

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	xhtml "golang.org/x/net/html"
)

var markdownURLReplacer = strings.NewReplacer(
	"\\", "%5C", " ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E",
)

type linkCollector struct {
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
	characters := utf8.RuneCountInString(candidate)
	if len(collector.refs) >= maxExtractedLinks || characters > maxExtractedLinkLength || collector.chars+characters > maxExtractedLinkChars {
		return
	}
	collector.seen[candidate] = struct{}{}
	collector.refs = append(collector.refs, candidate)
	collector.chars += characters
}

func (collector *imageRefCollector) AddAll(candidates []string) {
	for _, candidate := range candidates {
		collector.Add(candidate)
	}
}

func markdownLabelText(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "[", `\[`)
	return strings.ReplaceAll(value, "]", `\]`)
}

func markdownURL(value string) string { return markdownURLReplacer.Replace(value) }

// extractBoundedHTMLFallback retains tokenizer text after a tree/style resource
// limit. It never bypasses the primary limits and deliberately makes no
// visibility claim; callers disclose that extraction was incomplete.
func extractBoundedHTMLFallback(source string) extractedContent {
	z := xhtml.NewTokenizer(bytes.NewBufferString(source))
	var text strings.Builder
	var links linkCollector
	var images imageRefCollector
	var base *url.URL
	baseSeen, suppressed := false, 0
	complete := true
	const fallbackTextBytes = 1 << 20
	for text.Len() < fallbackTextBytes {
		token := z.Next()
		if token == xhtml.ErrorToken {
			if z.Err() != nil && z.Err() != io.EOF {
				text.WriteString(" [HTML tokenization stopped] ")
				complete = false
			}
			break
		}
		switch token {
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			t := z.Token()
			name := strings.ToLower(t.Data)
			if omittedHTMLElement(name) {
				suppressed++
				continue
			}
			if suppressed > 0 {
				continue
			}
			attr := func(key string) (string, bool) {
				for _, a := range t.Attr {
					if strings.EqualFold(a.Key, key) {
						return a.Val, true
					}
				}
				return "", false
			}
			if name == "base" && !baseSeen {
				if raw, ok := attr("href"); ok {
					baseSeen = true
					if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") {
						base = u
					}
				}
			}
			if name == "a" {
				if raw, ok := attr("href"); ok {
					if destination, valid := fallbackDestination(raw, base); valid {
						links.AddDestination(destination)
					}
				}
			}
			if name == "img" {
				if raw, ok := attr("src"); ok {
					if strings.HasPrefix(strings.ToLower(raw), "cid:") {
						images.Add(raw[4:])
					} else if destination, valid := fallbackDestination(raw, base); valid {
						links.AddDestination(destination)
					}
				}
			}
		case xhtml.EndTagToken:
			name, _ := z.TagName()
			if omittedHTMLElement(strings.ToLower(string(name))) && suppressed > 0 {
				suppressed--
			}
		case xhtml.TextToken:
			if suppressed > 0 {
				continue
			}
			text.Write(z.Text())
			text.WriteByte(' ')
		}
	}
	if text.Len() >= fallbackTextBytes {
		complete = false
	}
	value := normalizeHTMLText(sanitizeSenderText(text.String()))
	tagged := value
	if value != "" {
		tagged = "<visibility-uncertain>" + value + "</visibility-uncertain>"
	}
	links.AddAllHTTP(findHTTPURLs(value))
	return extractedContent{Text: tagged, VisibleText: value,
		Links: links.links, ImageRefs: images.refs, ExtractionIncomplete: !complete}
}

func fallbackDestination(raw string, base *url.URL) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(raw) == "" {
		return "", false
	}
	if !u.IsAbs() && base != nil {
		u = base.ResolveReference(u)
	}
	if u.IsAbs() {
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "mailto" && scheme != "tel" {
			return "", false
		}
	}
	return u.String(), true
}

func (collector *linkCollector) AddAllHTTP(values []string) {
	for _, value := range values {
		collector.AddDestination(value)
	}
}
