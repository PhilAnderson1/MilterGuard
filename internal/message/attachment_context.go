package message

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Offsets refer only to generated boundaries, never tags found in sender text.
// They let sampling close nested sections without interpreting untrusted markup.
type attachmentSpan struct {
	Start, BodyStart, CloseStart, End int
	Tag                               string
}

type attachmentLinkGroup struct {
	Prefix, Suffix string
	Links          []string
}

type mimePartInfo struct {
	Disposition string
	ParentType  string
}

// Explicit inline disposition and normal alternative/related body roles take
// precedence over a filename. A name on an otherwise unspecified mixed part
// identifies a file, but the extension never selects its parser.
func fileAttachmentInfo(mediaType string, params map[string]string, info mimePartInfo, budget *extractionBudget) (bool, string) {
	if info.Disposition == "" && params["name"] == "" {
		return false, ""
	}
	disposition, fields, _ := resourceguard.ParseMediaType(budget.allocationMemory(), info.Disposition)
	filename := fields["filename"]
	if filename == "" {
		filename = params["name"]
	}
	attached := disposition == "attachment" || (disposition == "" && filename != "" && info.ParentType != "multipart/alternative" && info.ParentType != "multipart/related")
	return attached && (mediaType == "text/plain" || mediaType == "text/html"), filename
}

const maxAttachmentMetadataBytes = 8192
const maxAttachmentFieldBytes = 1024

func attachmentMetadataValue(value string, budget *extractionBudget) string {
	// Bound decoding and sanitization work, including malformed encoded words.
	truncated := len(value) > maxAttachmentFieldBytes
	if truncated {
		value = value[:maxAttachmentFieldBytes]
	}
	budget.allocationMemory().Reserve(int64(len(value))*16 + 128)
	value = decodeHeaderValue(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.ReplaceAll(strings.ReplaceAll(value, "<", "&lt;"), ">", "&gt;")
	if len(value) > maxAttachmentFieldBytes {
		end := maxAttachmentFieldBytes
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		value = value[:end]
		truncated = true
	}
	if truncated {
		value += " [metadata truncated]"
	}
	return value
}

func attachmentPrefix(tag, filename, mediaType, headers string, budget *extractionBudget) string {
	b := newGuardedBuilder(budget.allocationMemory())
	b.WriteString("<" + tag + ">\n")
	if filename != "" {
		b.WriteString("Filename: ")
		b.WriteString(attachmentMetadataValue(filename, budget))
		b.WriteString("\n")
	}
	if mediaType != "" {
		b.WriteString("Content-Type: " + mediaType + "\n")
	}
	if headers != "" {
		b.WriteString("Original headers (unverified claims):\n")
		b.WriteString(headers)
	}
	b.WriteString("\n")
	return b.String()
}

func appendAttachmentSpans(dst, src []attachmentSpan, offset int, budget *extractionBudget) []attachmentSpan {
	for _, span := range src {
		span.Start += offset
		span.BodyStart += offset
		span.CloseStart += offset
		span.End += offset
		dst = resourceguard.Append(budget.allocationMemory(), dst, budget.outputShouldStop, span)
	}
	return dst
}

const incompleteFileMarker = "<attached-file>\n[attachment extraction incomplete]\n</attached-file>"
const incompleteEmailMarker = "<attached-email>\n[attachment extraction incomplete]\n</attached-email>"

// Shared immutable spans keep terminal recovery allocation-free.
var incompleteFileSpans = &[1]attachmentSpan{{0, len("<attached-file>\n"), len(incompleteFileMarker) - len("\n</attached-file>"), len(incompleteFileMarker), "attached-file"}}
var incompleteEmailSpans = &[1]attachmentSpan{{0, len("<attached-email>\n"), len(incompleteEmailMarker) - len("\n</attached-email>"), len(incompleteEmailMarker), "attached-email"}}

func wrapAttachment(content extractedContent, tag, filename, mediaType, headers string, budget *extractionBudget) extractedContent {
	if budget.omitAttachmentContext {
		return content
	}
	wrapped, ok := runExtraction(budget, func() extractedContent {
		prefix := attachmentPrefix(tag, filename, mediaType, headers, budget)
		suffix := "\n</" + tag + ">"
		wrap := func(text string, spans []attachmentSpan) (string, []attachmentSpan) {
			result := joinExtractedText([]string{prefix, text, suffix}, "", budget)
			boundaries := resourceguard.Append(budget.allocationMemory(), []attachmentSpan(nil), nil,
				attachmentSpan{Start: 0, BodyStart: len(prefix), CloseStart: len(prefix) + len(text), End: len(result), Tag: tag})
			return result, appendAttachmentSpans(boundaries, spans, len(prefix), budget)
		}
		stripped := content.StrippedText
		if !content.HasConcealedContent {
			stripped = content.Text
		}
		text, textSpans := wrap(content.Text, content.TextAttachments)
		visible, visibleSpans := text, textSpans
		if !sameStringStorage(content.Text, content.VisibleText) {
			visible, visibleSpans = wrap(content.VisibleText, content.VisibleAttachments)
		}
		strippedText, strippedSpans := text, textSpans
		if content.HasConcealedContent {
			strippedText, strippedSpans = wrap(stripped, content.StrippedAttachments)
		}
		groups := makeAttachmentLinkGroups(content, prefix, suffix, budget)
		content.Text, content.TextAttachments = text, textSpans
		content.VisibleText, content.VisibleAttachments = visible, visibleSpans
		content.StrippedText, content.StrippedAttachments = strippedText, strippedSpans
		content.AttachmentLinks, content.Links = groups, nil
		content.Attachment = true
		return content
	})
	if ok {
		return wrapped
	}
	// An exhausted budget must never expose retained child text without its
	// provenance. Constant markers need no additional extraction allocation.
	marker, spans := incompleteFileMarker, incompleteFileSpans
	if tag == "attached-email" {
		marker, spans = incompleteEmailMarker, incompleteEmailSpans
	}
	content.Text, content.VisibleText, content.StrippedText = marker, marker, marker
	content.TextAttachments, content.VisibleAttachments, content.StrippedAttachments = spans[:], spans[:], spans[:]
	content.Links, content.AttachmentLinks = nil, nil
	content.Attachment, content.ExtractionIncomplete = true, true
	return content
}

func makeAttachmentLinkGroups(content extractedContent, prefix, suffix string, budget *extractionBudget) []attachmentLinkGroup {
	var groups []attachmentLinkGroup
	if len(content.Links) > 0 {
		groups = resourceguard.Append(budget.allocationMemory(), groups, nil, attachmentLinkGroup{prefix, suffix, content.Links})
	}
	for _, group := range content.AttachmentLinks {
		group.Prefix = joinExtractedText([]string{prefix, group.Prefix}, "", budget)
		group.Suffix = joinExtractedText([]string{group.Suffix, suffix}, "", budget)
		groups = resourceguard.Append(budget.allocationMemory(), groups, budget.outputShouldStop, group)
	}
	return groups
}

// sampleAttachmentBody preserves generated boundaries even if sender text
// contains convincing copies of their tags. Metadata is admitted atomically.
func sampleAttachmentBody(body string, maxChars int, spans []attachmentSpan) string {
	if len(spans) == 0 {
		return truncateOverlongBody(body, maxChars)
	}
	if maxChars < 1 {
		return ""
	}
	const notice = "\n[processed email body truncated; the remainder was omitted]"
	allowance := maxChars
	for {
		cut := runeByteOffsets(body, allowance)[0]
		// Never keep a partial opening, metadata block, or closing tag.
		for _, span := range spans {
			if cut > span.Start && cut < span.BodyStart {
				cut = span.Start
			}
			if cut >= span.CloseStart && cut < span.End {
				cut = span.CloseStart
			}
		}
		var closing strings.Builder
		for i := len(spans) - 1; i >= 0; i-- {
			span := spans[i]
			if cut >= span.BodyStart && cut <= span.CloseStart {
				closing.WriteString("\n</" + span.Tag + ">")
			}
		}
		suffix := notice + closing.String()
		if utf8.RuneCountInString(body[:cut])+utf8.RuneCountInString(suffix) <= maxChars || allowance == 0 {
			if allowance == 0 {
				return notice
			}
			return body[:cut] + suffix
		}
		excess := utf8.RuneCountInString(body[:cut]) + utf8.RuneCountInString(suffix) - maxChars
		allowance = max(0, min(allowance-1, utf8.RuneCountInString(body[:cut])-excess))
	}
}

func writeAttachmentLinks(b *strings.Builder, groups []attachmentLinkGroup, body string) {
	remaining, chars := maxExtractedLinks, 0
	wrote := false
	for _, group := range groups {
		if remaining == 0 {
			break
		}
		links := boundedLinksMissingFromBody(group.Links, body)
		opened := false
		for _, link := range links {
			count := utf8.RuneCountInString(link)
			if remaining == 0 || chars+count > maxExtractedLinkChars {
				continue
			}
			if !wrote {
				b.WriteString("\nEXTRACTED ATTACHMENT LINKS (retained independently of body sampling):\n")
				wrote = true
			}
			if !opened {
				b.WriteString(group.Prefix)
				opened = true
			}
			b.WriteString("- " + sanitize(link) + "\n")
			remaining--
			chars += count
		}
		if opened {
			b.WriteString(group.Suffix)
			b.WriteString("\n")
		}
	}
}
