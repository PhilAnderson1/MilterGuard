package message

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/charset"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
)

const (
	maxMIMEParts = 256
	maxHTMLParts = 32
)

type extractionBudget struct {
	parts                int
	htmlParts            int
	htmlBytesRemaining   int
	cssBytesRemaining    int
	memoryBytesRemaining int64
	shouldFallback       func() bool
	fallbackShouldStop   func() bool
	forceFallback        bool
	cpuLimitExceeded     bool
	compactURLs          bool
}

func newExtractionBudget() *extractionBudget {
	return newExtractionBudgetWithControl(HTMLProcessingControl{})
}

func newExtractionBudgetWithControl(control HTMLProcessingControl) *extractionBudget {
	limits := htmlextract.DefaultLimits()
	return &extractionBudget{
		htmlBytesRemaining:   limits.InputBytes,
		cssBytesRemaining:    limits.CSSBytes,
		memoryBytesRemaining: limits.MemoryBytes,
		shouldFallback:       control.ShouldFallback,
		fallbackShouldStop:   control.FallbackShouldStop,
		forceFallback:        control.ForceFallback,
		compactURLs:          !control.DisableURLCompaction,
	}
}

func (b *extractionBudget) useFallback() bool {
	if b.cpuLimitExceeded {
		return true
	}
	if b.forceFallback || (b.shouldFallback != nil && b.shouldFallback()) {
		b.cpuLimitExceeded = true
		return true
	}
	return false
}

func (b *extractionBudget) takePart() bool {
	if b.parts >= maxMIMEParts {
		return false
	}
	b.parts++
	return true
}

func (b *extractionBudget) htmlLimits(bytes int) (htmlextract.Limits, bool) {
	if b.htmlParts > maxHTMLParts || bytes > b.htmlBytesRemaining || b.cssBytesRemaining <= 0 || b.memoryBytesRemaining <= 0 {
		b.htmlBytesRemaining = 0
		return htmlextract.Limits{}, false
	}
	b.htmlBytesRemaining -= bytes
	limits := htmlextract.DefaultLimits()
	limits.CSSBytes = b.cssBytesRemaining
	limits.MemoryBytes = b.memoryBytesRemaining
	return limits, true
}

func (b *extractionBudget) consumeHTML(usage htmlextract.ResourceUsage) {
	b.cssBytesRemaining = remainingInt(b.cssBytesRemaining, usage.CSSBytes)
	b.memoryBytesRemaining = remainingInt64(b.memoryBytesRemaining, usage.MemoryBytes)
}

func remainingInt64(remaining, used int64) int64 {
	if used >= remaining {
		return 0
	}
	return remaining - used
}

func remainingInt(remaining, used int) int {
	if used >= remaining {
		return 0
	}
	return remaining - used
}

type extractedContent struct {
	Text                  string
	VisibleText           string
	ConfidentVisibleChars int
	StrippedText          string
	Links                 []string
	ImageRefs             []string
	Images                []extractedImage
	HTML                  bool
	MIMEIncomplete        bool
	TransferIncomplete    bool
	ExtractionIncomplete  bool
	HTMLFallbackUsed      bool
	HTMLCPULimitExceeded  bool
	CSSIncomplete         bool
	HasConcealedContent   bool
	HTMLComments          htmlCommentStats
}

type extractedImage struct {
	ContentID string
	Data      []byte
}

func extractMIME(contentType, encoding, contentID string, data []byte, depth int) extractedContent {
	return extractMIMEWithBudget(contentType, encoding, contentID, data, depth, newExtractionBudget())
}

func extractMIMEWithBudget(contentType, encoding, contentID string, data []byte, depth int, budget *extractionBudget) extractedContent {
	if depth > 8 {
		return extractedContent{Text: "[MIME nesting limit reached]", MIMEIncomplete: true}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	mediaType = strings.ToLower(mediaType)
	decoded, transferIncomplete := decodeTransferRecovering(encoding, data)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]", MIMEIncomplete: true, TransferIncomplete: transferIncomplete}
		}
		reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []extractedContent
		var alternativeHTML, alternativePlain extractedContent
		var mimeIncomplete, nestedTransferIncomplete, processingStopped bool
		for {
			if budget.useFallback() {
				mimeIncomplete = true
				processingStopped = true
				break
			}
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				mimeIncomplete = true
				break
			}
			if !budget.takePart() {
				mimeIncomplete = true
				break
			}
			// The complete message body has already been bounded by Message.maxBytes.
			// Do not impose a smaller per-part limit here: doing so would silently
			// discard evidence from otherwise retained messages.
			body, readErr := io.ReadAll(part)
			mimeIncomplete = mimeIncomplete || readErr != nil
			partContentType := part.Header.Get("Content-Type")
			if mediaType == "multipart/digest" && strings.TrimSpace(partContentType) == "" {
				partContentType = "message/rfc822"
			}
			content := extractMIMEWithBudget(partContentType, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-ID"), body, depth+1, budget)
			mimeIncomplete = mimeIncomplete || content.MIMEIncomplete
			nestedTransferIncomplete = nestedTransferIncomplete || content.TransferIncomplete
			if !hasExtractedContent(content) {
				continue
			}
			parts = append(parts, content)
			if mediaType == "multipart/alternative" {
				partMediaType, _, _ := mime.ParseMediaType(partContentType)
				switch {
				case content.HTML:
					// HTML with CID resources is normally wrapped in
					// multipart/related. Preserve that complete branch rather
					// than selecting the direct text/plain alternative.
					alternativeHTML = content
				case partMediaType == "text/plain":
					alternativePlain = content
				}
			}
		}
		if mediaType == "multipart/alternative" {
			var selected extractedContent
			switch {
			case hasExtractedContent(alternativeHTML):
				selected = alternativeHTML
			case hasExtractedContent(alternativePlain):
				selected = alternativePlain
			case len(parts) > 0:
				selected = parts[len(parts)-1]
			}
			selected.MIMEIncomplete = mimeIncomplete
			selected.ExtractionIncomplete = selected.ExtractionIncomplete || processingStopped
			selected.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
			selected.HTML = selected.HTML || budget.htmlParts > 0
			selected.HTMLCPULimitExceeded = selected.HTMLCPULimitExceeded || budget.cpuLimitExceeded
			return selected
		}
		var combined extractedContent
		var imageRefs imageRefCollector
		links := linkCollector{compactURLs: budget.compactURLs}
		var textParts, visibleTextParts, strippedTextParts []string
		for _, part := range parts {
			if budget.useFallback() {
				processingStopped = true
				break
			}
			textParts = append(textParts, part.Text)
			visibleTextParts = append(visibleTextParts, part.VisibleText)
			stripped := part.StrippedText
			if stripped == "" && !part.HasConcealedContent {
				stripped = part.Text
			}
			if stripped != "" {
				strippedTextParts = append(strippedTextParts, stripped)
			}
			for _, destination := range part.Links {
				links.AddDestination(destination)
			}
			imageRefs.AddAll(part.ImageRefs)
			combined.Images = append(combined.Images, part.Images...)
			combined.HTML = combined.HTML || part.HTML
			combined.ConfidentVisibleChars += part.ConfidentVisibleChars
			combined.HasConcealedContent = combined.HasConcealedContent || part.HasConcealedContent
			combined.ExtractionIncomplete = combined.ExtractionIncomplete || part.ExtractionIncomplete
			combined.HTMLFallbackUsed = combined.HTMLFallbackUsed || part.HTMLFallbackUsed
			combined.HTMLCPULimitExceeded = combined.HTMLCPULimitExceeded || part.HTMLCPULimitExceeded
			combined.CSSIncomplete = combined.CSSIncomplete || part.CSSIncomplete
			combined.HTMLComments.add(part.HTMLComments)
		}
		combined.ImageRefs = imageRefs.refs
		combined.Links = links.links
		combined.Text = strings.Join(textParts, "\n\n")
		combined.StrippedText = strings.Join(strippedTextParts, "\n\n")
		if budget.useFallback() {
			processingStopped = true
		} else {
			combined.VisibleText = strings.Join(visibleTextParts, "\n\n")
		}
		combined.MIMEIncomplete = mimeIncomplete
		combined.ExtractionIncomplete = combined.ExtractionIncomplete || processingStopped
		combined.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
		combined.HTML = combined.HTML || budget.htmlParts > 0
		combined.HTMLCPULimitExceeded = combined.HTMLCPULimitExceeded || budget.cpuLimitExceeded
		return combined
	}
	if mediaType == "message/rfc822" {
		content := extractAttachedMessage(decoded, depth, budget)
		content.TransferIncomplete = content.TransferIncomplete || transferIncomplete
		return content
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		content := extractedContent{Text: "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]", TransferIncomplete: transferIncomplete}
		if strings.HasPrefix(mediaType, "image/") {
			content.Images = []extractedImage{{ContentID: normalizeContentID(contentID), Data: decoded}}
		}
		return content
	}
	if mediaType == "text/html" {
		text := decodeHTMLCharset(params["charset"], decoded)
		content := htmlToTextWithBudget(text, budget)
		content.HTML = true
		content.TransferIncomplete = transferIncomplete
		return content
	}
	text := decodeCharset(params["charset"], decoded)
	if budget.useFallback() {
		return extractedContent{
			Text: text, VisibleText: text, ConfidentVisibleChars: confidentTextCharacters(text),
			TransferIncomplete: transferIncomplete, ExtractionIncomplete: true, HTMLCPULimitExceeded: true,
		}
	}
	links := linkCollector{compactURLs: budget.compactURLs}
	promptText := rewritePlainTextURLs(text, budget.compactURLs, &links)
	return extractedContent{
		Text: promptText, VisibleText: text,
		ConfidentVisibleChars: confidentTextCharacters(text),
		Links:                 links.links, TransferIncomplete: transferIncomplete,
	}
}

func extractAttachedMessage(data []byte, depth int, budget *extractionBudget) extractedContent {
	attached, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return extractedContent{Text: "[attached message could not be parsed]"}
	}
	body, err := io.ReadAll(attached.Body)
	if err != nil {
		return extractedContent{Text: "[attached message body could not be read]"}
	}
	return extractMIMEWithBudget(
		attached.Header.Get("Content-Type"),
		attached.Header.Get("Content-Transfer-Encoding"),
		attached.Header.Get("Content-ID"),
		body,
		depth+1,
		budget,
	)
}

// decodeCharset converts MIME text bodies to UTF-8 after their transfer
// encoding has been decoded. Unknown labels and malformed encoded text retain
// the original content so that a bad charset declaration cannot erase the
// message body.
func decodeCharset(label string, data []byte) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return string(data)
	}
	if utf8.Valid(data) {
		if _, canonical := charset.Lookup(label); canonical == "utf-8" {
			return string(data)
		}
	}
	reader, err := charset.NewReaderLabel(label, bytes.NewReader(data))
	if err != nil {
		return string(data)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(data)
	}
	return string(decoded)
}

// decodeHTMLCharset keeps a usable MIME declaration authoritative. Without
// one, HTML's own BOM or early meta declaration can identify its encoding;
// this does not parse the document or change the HTML extractor.
func decodeHTMLCharset(label string, data []byte) string {
	if encoding, canonical := charset.Lookup(strings.TrimSpace(label)); encoding != nil {
		if canonical == "utf-8" && utf8.Valid(data) {
			return strings.TrimPrefix(string(data), "\ufeff")
		}
		return strings.TrimPrefix(decodeCharset(label, data), "\ufeff")
	}
	reader, err := charset.NewReader(bytes.NewReader(data), "text/html")
	if err != nil {
		return string(data)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(data)
	}
	return strings.TrimPrefix(string(decoded), "\ufeff")
}

func hasExtractedContent(content extractedContent) bool {
	return strings.TrimSpace(content.Text) != "" || len(content.Links) > 0 || len(content.ImageRefs) > 0 || len(content.Images) > 0
}

func normalizeContentID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '<' && value[len(value)-1] == '>' {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	return strings.ToLower(value)
}

// decodeTransferRecovering is deliberately recovery-oriented: message extraction keeps
// readable evidence from malformed encodings and accepts omitted Base64
// padding. Attachment inspection uses a separate strict decoder so incomplete
// data cannot be reported as successfully scanned.
func decodeTransferRecovering(encoding string, data []byte) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		if err == nil {
			return decoded, false
		}
		// Some senders omit the final MIME padding. RawStdEncoding accepts that
		// specific variation without ignoring arbitrary corrupt characters.
		if unpadded, rawErr := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(data))); rawErr == nil {
			return unpadded, false
		}
		if len(decoded) > 0 {
			return decoded, true
		}
		return data, true
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data)))
		if err == nil || len(decoded) > 0 {
			return decoded, err != nil
		}
		return data, true
	case "", "7bit", "8bit", "binary":
		return data, false
	default:
		return data, len(data) > 0
	}
}
