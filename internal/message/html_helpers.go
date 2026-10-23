package message

import (
	"bytes"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

const fallbackTextBytes = 1 << 20

var markdownURLReplacer = strings.NewReplacer(
	"\\", "%5C", " ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E",
)

type linkCollector struct {
	links       []string
	seen        resourceguard.Table[string, struct{}]
	rendered    resourceguard.Table[string, string]
	chars       int
	full        bool
	compactURLs bool
	memory      *resourceguard.Memory
	shouldStop  func()
}

func (collector *linkCollector) Full() bool {
	return collector != nil && (collector.full || len(collector.links) >= maxExtractedLinks)
}

type imageRefCollector struct {
	refs   []string
	seen   resourceguard.Table[string, struct{}]
	chars  int
	memory *resourceguard.Memory
}

func (collector *imageRefCollector) Add(candidate string) {
	// Normalization can allocate an unescaped copy and a lower-case copy.
	collector.memory.Reserve(int64(len(candidate)) * 4)

	candidate = normalizeContentID(candidate)
	if candidate == "" {
		return
	}

	if _, found := collector.seen.Get(candidate); found {
		return
	}

	characters := utf8.RuneCountInString(candidate)
	if len(collector.refs) >= maxExtractedLinks || characters > maxExtractedReferenceLength || collector.chars+characters > maxExtractedLinkChars {
		return
	}

	collector.seen.Set(collector.memory, candidate, struct{}{})

	grown := growGuardedSlice(collector.refs, len(collector.refs)+1, collector.memory)

	collector.refs = append(grown, candidate)
	collector.chars += characters
}

func (collector *imageRefCollector) AddAll(candidates []string) {
	for _, candidate := range candidates {
		collector.Add(candidate)
	}
}

func markdownURL(value string) string { return markdownURLReplacer.Replace(value) }

func fallbackHeadElement(name string) bool {
	switch name {
	case "html", "head", "base", "basefont", "bgsound", "link", "meta", "noframes", "noscript", "script", "style", "template", "title":
		return true
	}
	return false
}

func fallbackHTMLWhitespaceOnly(value []byte) bool {
	for _, c := range value {
		switch c {
		case ' ', '\t', '\n', '\r', '\f':
		default:
			return false
		}
	}
	return true
}

// extractBoundedHTMLFallback owns no primary-stage state. Admission and
// resource-limit policy are handled by the caller before entering this stage.
func extractBoundedHTMLFallback(source string, compactURLs bool, resources *fallbackResources) extractedContent {
	memory, shouldStop := resources.memory, resources.checkpoint

	shouldStop()

	z := xhtml.NewTokenizerWithLimits(strings.NewReader(source), xhtml.ResourceLimits{Memory: memory, ShouldStop: shouldStop})
	text := newGuardedBuilder(memory)
	links := linkCollector{compactURLs: compactURLs, memory: memory, shouldStop: shouldStop}
	images := imageRefCollector{memory: memory}
	var base *url.URL
	baseSeen := false
	var suppressed []string
	complete := true
	for {
		if !(text.Len() < fallbackTextBytes) {
			break
		}
		shouldStop()

		resources.prefix = text.String()

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
			rawName, moreAttributes := z.TagName()
			name := resourceguard.CopyString(memory, rawName, shouldStop)

			if len(suppressed) > 0 && suppressed[len(suppressed)-1] == "head" {
				if name == "head" {
					continue
				}
				if !fallbackHeadElement(name) {
					suppressed = suppressed[:len(suppressed)-1]
				}
			}
			if omittedHTMLElement(name) {
				suppressed = resourceguard.Append(memory, suppressed, shouldStop, name)
				continue
			}
			if len(suppressed) > 0 {
				continue
			}
			var attributeName []byte
			switch name {
			case "base", "a":
				attributeName = []byte("href")
			case "img":
				attributeName = []byte("src")
			}
			var raw string
			present := false
			for {
				if !(moreAttributes) {
					break
				}
				shouldStop()
				key, value, more := z.TagAttr()
				moreAttributes = more
				if !present && attributeName != nil && bytes.EqualFold(key, attributeName) {
					raw = resourceguard.CopyString(memory, value, shouldStop)

					present = true
				}
			}
			if name == "base" && !baseSeen && present {
				baseSeen = true

				if u, err := resourceguard.ParseURL(memory, strings.TrimSpace(raw)); err == nil && u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") {
					base = u
				}

			}
			if name == "a" && present {

				if destination, valid := fallbackDestinationWithBudget(raw, base, memory); valid {
					links.AddDestination(destination)
				}

			}
			if name == "img" && present {
				if len(raw) >= 4 && strings.EqualFold(raw[:4], "cid:") {
					images.Add(raw[4:])
				} else {

					if destination, valid := fallbackDestinationWithBudget(raw, base, memory); valid {
						links.AddDestination(destination)
					}

				}
			}
		case xhtml.EndTagToken:
			rawName, _ := z.TagName()
			name := resourceguard.CopyString(memory, rawName, shouldStop)

			if len(suppressed) > 0 && suppressed[len(suppressed)-1] == name {
				suppressed = suppressed[:len(suppressed)-1]
			}
		case xhtml.TextToken:
			value := z.Text()
			if len(suppressed) > 0 && suppressed[len(suppressed)-1] == "head" && !fallbackHTMLWhitespaceOnly(value) {
				suppressed = suppressed[:len(suppressed)-1]
			}
			if len(suppressed) > 0 {
				continue
			}
			remaining := fallbackTextBytes - text.Len()
			if len(value) >= remaining {
				text.Write(value[:remaining])
				complete = false
				continue
			}
			text.Write(value)
			text.appendByte(' ')
		}
	}
	if text.Len() >= fallbackTextBytes {
		complete = false
	}
	if len(suppressed) > 0 {
		complete = false
	}
	value := text.String()
	textStop := resources.textStopCallback()
	value = sanitizeSenderTextWithResources(value, memory, textStop)
	value = normalizeHTMLTextWithResources(value, memory, textStop)
	value = rewritePlainTextURLs(value, compactURLs, &links, memory, shouldStop)
	return extractedContent{Text: value, HTMLFallbackUsed: true, Links: links.links, ImageRefs: images.refs, ExtractionIncomplete: !complete}
}

func fallbackDestinationWithBudget(raw string, base *url.URL, memory *resourceguard.Memory) (string, bool) {
	u, err := resourceguard.ParseURL(memory, strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(raw) == "" {
		return "", false
	}
	reserveResolvedURL(memory, raw, base)

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

func reserveResolvedURL(memory *resourceguard.Memory, raw string, base *url.URL) {
	// ResolveReference and URL.String can copy/escape components. Admit a
	// conservative allowance for their intermediates before calling either.
	size := len(raw)
	if base != nil {
		if base.User != nil {
			size += len(base.User.Username())
			password, _ := base.User.Password()
			size += len(password)
		}
		size += len(base.Scheme) + len(base.Host) + len(base.Path) + len(base.RawPath) + len(base.RawQuery) + len(base.Fragment) + len(base.RawFragment)
	}

	memory.Reserve(int64(size)*16 + 1024)
}

// escapeMarkdown owns any label/URL escaping buffer. Unchanged strings are borrowed.
func escapeMarkdown(value string, urlMode bool, memory *resourceguard.Memory, stop func()) string {
	out := newGuardedBuilder(memory)
	changed := false
	for i := 0; i < len(value); i++ {
		if i%resourceguard.WorkChunk == 0 && stop != nil {
			stop()
		}
		c := value[i]
		escape := c == '\\' || (!urlMode && (c == '[' || c == ']')) || (urlMode && (c == ' ' || c == '(' || c == ')' || c == '<' || c == '>'))
		if escape {
			if !changed {
				out.Grow(len(value))
				out.WriteString(value[:i])
				changed = true
			}
			if urlMode {
				const hex = "0123456789ABCDEF"
				out.appendByte('%')
				out.appendByte(hex[c>>4])
				out.appendByte(hex[c&15])
			} else {
				out.appendByte('\\')
				out.appendByte(c)
			}
		} else if changed {
			out.appendByte(c)
		}
	}
	if !changed {
		return value
	}
	return out.String()
}
