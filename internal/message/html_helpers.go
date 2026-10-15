package message

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

var markdownURLReplacer = strings.NewReplacer(
	"\\", "%5C", " ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E",
)

type linkCollector struct {
	links       []string
	seen        map[string]struct{}
	chars       int
	compactURLs bool
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
	if len(collector.refs) >= maxExtractedLinks || characters > maxExtractedReferenceLength || collector.chars+characters > maxExtractedLinkChars {
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

// promptURL selects a URL's LLM-facing representation. Oversized path segments
// and query values are shortened independently so the host, parameter names
// and useful value prefixes remain visible.
func promptURL(value string, compact bool) string {
	if !compact {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return compactURLPart(value, maxPromptURLChars)
	}

	path, pathChanged := compactURLPath(parsed.EscapedPath())
	query, queryChanged := compactURLQuery(parsed.RawQuery)
	fragment, fragmentChanged := compactURLPartChanged(parsed.EscapedFragment(), maxPromptURLFragmentChars)
	if !pathChanged && !queryChanged && !fragmentChanged && utf8.RuneCountInString(value) <= maxPromptURLChars {
		return value
	}

	var b strings.Builder
	b.WriteString(parsed.Scheme)
	b.WriteString("://")
	if parsed.User != nil {
		b.WriteString("[userinfo-omitted]@")
	}
	b.WriteString(parsed.Host)
	b.WriteString(path)
	if parsed.ForceQuery || query != "" {
		b.WriteByte('?')
		b.WriteString(query)
	}
	if fragment != "" {
		b.WriteByte('#')
		b.WriteString(fragment)
	}
	return compactURLPart(b.String(), maxPromptURLChars)
}

func compactURLPath(value string) (string, bool) {
	parts := strings.Split(value, "/")
	changed := false
	for i := range parts {
		var partChanged bool
		parts[i], partChanged = compactURLPathPart(parts[i], maxPromptURLPathChars)
		changed = changed || partChanged
	}
	return strings.Join(parts, "/"), changed
}

func compactURLPathPart(value string, limit int) (string, bool) {
	runes := []rune(value)
	if len(runes) <= limit {
		return value, false
	}
	if hasLikelyFileExtension(value) {
		return string(runes[len(runes)-limit:]), true
	}
	return string(runes[:limit]), true
}

func hasLikelyFileExtension(escapedName string) bool {
	name, err := url.PathUnescape(escapedName)
	if err != nil {
		return false
	}
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 || len(name)-dot-1 < 1 || len(name)-dot-1 > 16 {
		return false
	}
	for _, c := range name[dot+1:] {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func compactURLQuery(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	parameters := strings.Split(value, "&")
	changed := false
	for i, parameter := range parameters {
		key, parameterValue, found := strings.Cut(parameter, "=")
		var keyChanged, valueChanged bool
		key, keyChanged = compactURLPartChanged(key, maxPromptURLParameterChars)
		if found {
			parameterValue, valueChanged = compactURLPartChanged(parameterValue, maxPromptURLParameterChars)
			parameters[i] = key + "=" + parameterValue
		} else {
			parameters[i] = key
		}
		changed = changed || keyChanged || valueChanged
	}
	return strings.Join(parameters, "&"), changed
}

func compactURLPart(value string, limit int) string {
	compacted, _ := compactURLPartChanged(value, limit)
	return compacted
}

func compactURLPartChanged(value string, limit int) (string, bool) {
	runes := []rune(value)
	if len(runes) <= limit {
		return value, false
	}
	return string(runes[:limit]), true
}

// extractBoundedHTMLFallback retains tokenizer text after a tree/style resource
// limit. It never bypasses the primary limits and deliberately makes no
// visibility claim; callers disclose that extraction was incomplete.
func extractBoundedHTMLFallback(source string, compactURLs bool, shouldStop func() bool) extractedContent {
	if shouldStop != nil && shouldStop() {
		return extractedContent{Text: "[HTML tokenization stopped]", HTMLFallbackUsed: true,
			ExtractionIncomplete: true, HTMLCPULimitExceeded: true}
	}
	z := xhtml.NewTokenizerWithStop(bytes.NewBufferString(source), shouldStop)
	var text strings.Builder
	links := linkCollector{compactURLs: compactURLs}
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
			rawName, moreAttributes := z.TagName()
			name := strings.ToLower(string(rawName))
			if omittedHTMLElement(name) {
				suppressed++
				continue
			}
			if suppressed > 0 {
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
			for moreAttributes {
				key, value, more := z.TagAttr()
				moreAttributes = more
				if !present && attributeName != nil && bytes.EqualFold(key, attributeName) {
					raw = string(value)
					present = true
				}
			}
			if name == "base" && !baseSeen {
				if present {
					baseSeen = true
					if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") {
						base = u
					}
				}
			}
			if name == "a" {
				if present {
					if destination, valid := fallbackDestination(raw, base); valid {
						links.AddDestination(destination)
					}
				}
			}
			if name == "img" {
				if present {
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
	value = rewritePlainTextURLs(value, compactURLs, &links)
	return extractedContent{Text: value, HTMLFallbackUsed: true,
		Links: links.links, ImageRefs: images.refs, ExtractionIncomplete: !complete,
		HTMLCPULimitExceeded: errors.Is(z.Err(), xhtml.ErrResourceStopped)}
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
