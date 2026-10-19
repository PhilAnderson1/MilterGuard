package message

import (
	"bytes"
	"errors"
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
	shouldStop  func() bool
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
	if !collector.memory.Reserve(int64(len(candidate)) * 4) {
		return
	}
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
	if !collector.seen.Set(collector.memory, candidate, struct{}{}) {
		return
	}
	grown, ok := growGuardedSlice(collector.refs, len(collector.refs)+1, collector.memory)
	if !ok {
		return
	}
	collector.refs = append(grown, candidate)
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

// extractBoundedHTMLFallback owns no primary-stage state. Admission and
// resource-limit policy are handled by the caller before entering this stage.
func extractBoundedHTMLFallback(source string, compactURLs bool, resources *fallbackResources) extractedContent {
	memory, shouldStop := resources.memory, resources.stopped
	if shouldStop() {
		return extractedContent{Text: "[HTML tokenization stopped]", HTMLFallbackUsed: true, ExtractionIncomplete: true,
			HTMLCPULimitExceeded: resources.cpuStopped, HTMLMemoryLimitExceeded: memory.Exhausted()}
	}
	z := xhtml.NewTokenizerWithLimits(strings.NewReader(source), xhtml.ResourceLimits{Memory: memory, ShouldStop: shouldStop})
	text := newGuardedBuilder(memory)
	links := linkCollector{compactURLs: compactURLs, memory: memory, shouldStop: shouldStop}
	images := imageRefCollector{memory: memory}
	var base *url.URL
	baseSeen, suppressed := false, 0
	complete := true
	for text.Len() < fallbackTextBytes && !text.Failed() && !shouldStop() {
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
			name, ok := resourceguard.CopyString(memory, rawName, shouldStop)
			if !ok {
				complete = false
				break
			}
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
			for moreAttributes && !shouldStop() {
				key, value, more := z.TagAttr()
				moreAttributes = more
				if !present && attributeName != nil && bytes.EqualFold(key, attributeName) {
					raw, ok = resourceguard.CopyString(memory, value, shouldStop)
					if !ok {
						break
					}
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
				} else if destination, valid := fallbackDestinationWithBudget(raw, base, memory); valid {
					links.AddDestination(destination)
				}
			}
		case xhtml.EndTagToken:
			rawName, _ := z.TagName()
			name, ok := resourceguard.CopyString(memory, rawName, shouldStop)
			if !ok {
				complete = false
				break
			}
			if omittedHTMLElement(name) && suppressed > 0 {
				suppressed--
			}
		case xhtml.TextToken:
			if suppressed > 0 {
				continue
			}
			value := z.Text()
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
	if text.Len() >= fallbackTextBytes || text.Failed() || resources.cpuStopped || memory.Exhausted() {
		complete = false
	}
	value := text.String()
	// Keep a safe prefix when storage is exhausted; do not allocate from a new
	// budget merely to finish output. Annotation-like or invalid UTF-8 prefixes
	// must not escape the normal sanitization path.
	safePrefix := value
	if strings.Contains(value, "<") || !utf8.ValidString(value) {
		safePrefix = ""
	}
	if complete || !memory.Exhausted() && !resources.cpuStopped {
		var ok bool
		value, ok = sanitizeSenderTextWithBudget(value, memory)
		if ok {
			value, ok = normalizeHTMLTextWithResources(value, memory, shouldStop)
		}
		if ok {
			value, ok = rewritePlainTextURLs(value, compactURLs, &links, shouldStop)
		}
		if !ok {
			value = safePrefix
			complete = false
		}
	} else {
		value = safePrefix
	}
	return extractedContent{Text: value, HTMLFallbackUsed: true, Links: links.links, ImageRefs: images.refs,
		ExtractionIncomplete: !complete, HTMLCPULimitExceeded: resources.cpuStopped || errors.Is(z.Err(), xhtml.ErrResourceStopped) && !memory.Exhausted(), HTMLMemoryLimitExceeded: memory.Exhausted()}
}

func sanitizeSenderTextWithBudget(value string, memory *resourceguard.Memory) (string, bool) {
	if !strings.Contains(value, "<") {
		return value, true
	}
	// regexp replacement owns a temporary buffer and its final string. Matching
	// uses fixed scratch; the output cannot be longer than the source.
	if !memory.Reserve(int64(len(value))*3 + 1024) {
		return "", false
	}
	return reservedAnnotation.ReplaceAllString(value, ""), true
}

func fallbackDestination(raw string, base *url.URL) (string, bool) {
	return fallbackDestinationWithBudget(raw, base, nil)
}
func fallbackDestinationWithBudget(raw string, base *url.URL, memory *resourceguard.Memory) (string, bool) {
	u, err := resourceguard.ParseURL(memory, strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(raw) == "" {
		return "", false
	}
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
	if !memory.Reserve(int64(size)*16 + 1024) {
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
