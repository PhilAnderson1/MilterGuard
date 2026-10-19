package message

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/charset"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

const (
	maxMIMEParts = 256
	maxHTMLParts = 32
)

type extractionBudget struct {
	parts                     int
	htmlParts                 int
	htmlBytesRemaining        int
	decodedTextBytesRemaining int64
	cssBytesRemaining         int
	memoryBytesRemaining      int64
	memoryBytesLimit          int64
	shouldFallback            func() bool
	fallbackShouldStop        func() bool
	cpuLimitExceeded          bool
	fallbackActive            bool
	fallbackStopped           bool
	memoryLimitExceeded       bool
	onMemoryLimit             func()
	stopOnMemoryLimit         bool
	compactURLs               bool
}

func newExtractionBudget() *extractionBudget {
	return newExtractionBudgetWithControl(HTMLProcessingControl{})
}

func newExtractionBudgetWithControl(control HTMLProcessingControl) *extractionBudget {
	limits := htmlextract.DefaultLimits()
	if control.MemoryBytes > 0 {
		limits.MemoryBytes = control.MemoryBytes
	}
	return &extractionBudget{
		htmlBytesRemaining:        limits.InputBytes,
		decodedTextBytesRemaining: int64(limits.InputBytes),
		cssBytesRemaining:         limits.CSSBytes,
		memoryBytesRemaining:      limits.MemoryBytes,
		memoryBytesLimit:          limits.MemoryBytes,
		shouldFallback:            control.ShouldFallback,
		fallbackShouldStop:        control.FallbackShouldStop,
		compactURLs:               !control.DisableURLCompaction,
		onMemoryLimit:             control.MemoryLimitExceeded,
		stopOnMemoryLimit:         control.StopOnMemoryLimit,
	}
}

func (b *extractionBudget) setDecodedTextByteLimit(bytes int64) {
	if bytes < 0 {
		bytes = 0
	}
	b.decodedTextBytesRemaining = bytes
}

func (b *extractionBudget) useFallback() bool {
	if b.fallbackActive || b.cpuLimitExceeded || b.memoryStopped() {
		return true
	}
	if b.shouldFallback != nil && b.shouldFallback() {
		b.cpuLimitExceeded = true
		return true
	}
	return false
}

// Output and decoding use the active stage. Once fallback starts, the primary
// allowance is never sampled again, including for later MIME parts.
func (b *extractionBudget) outputShouldStop() bool {
	if b.memoryStopped() {
		return true
	}
	if b.fallbackActive || b.cpuLimitExceeded {
		return b.fallbackStop()
	}
	return b.useFallback()
}

func (b *extractionBudget) fallbackStop() bool {
	b.fallbackActive = true
	if b.memoryStopped() || b.fallbackStopped {
		return true
	}
	if b.fallbackShouldStop != nil && b.fallbackShouldStop() {
		b.fallbackStopped = true
		b.cpuLimitExceeded = true
		return true
	}
	return false
}

func (b *extractionBudget) decodingShouldStop() bool {
	if b.fallbackActive {
		return b.fallbackStop()
	}
	if b.memoryStopped() {
		return true
	}
	if !b.useFallback() {
		return false
	}
	if b.fallbackShouldStop == nil {
		return true
	}
	return b.fallbackStop()
}

func (b *extractionBudget) memoryStopped() bool {
	return b.memoryLimitExceeded && b.stopOnMemoryLimit
}

func (b *extractionBudget) noteMemoryLimit() {
	if b.memoryLimitExceeded {
		return
	}
	b.memoryLimitExceeded = true
	if b.onMemoryLimit != nil {
		b.onMemoryLimit()
	}
}

func (b *extractionBudget) consumeMemory(memory *resourceguard.Memory) {
	b.memoryBytesRemaining = remainingInt64(b.memoryBytesRemaining, memory.Used())
	if memory.Exhausted() {
		b.noteMemoryLimit()
	}
}

func (b *extractionBudget) takePart() bool {
	if b.parts >= maxMIMEParts {
		return false
	}
	b.parts++
	return true
}

func (b *extractionBudget) htmlLimits(bytes int) (htmlextract.Limits, bool) {
	if b.memoryBytesRemaining <= 0 {
		b.noteMemoryLimit()
	}
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
	if usage.MemoryLimitExceeded {
		b.noteMemoryLimit()
	}
	b.cssBytesRemaining = remainingInt(b.cssBytesRemaining, usage.CSSBytes)
	b.memoryBytesRemaining = remainingInt64(b.memoryBytesRemaining, usage.MemoryBytes)
}

func (b *extractionBudget) reserveOutputMemory(bytes int64) bool {
	if bytes <= 0 {
		return true
	}
	if bytes > b.memoryBytesRemaining {
		b.memoryBytesRemaining = 0
		b.noteMemoryLimit()
		return false
	}
	b.memoryBytesRemaining -= bytes
	return true
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
	Text                    string
	VisibleText             string
	ConfidentVisibleChars   int
	StrippedText            string
	Links                   []string
	ImageRefs               []string
	Images                  []extractedImage
	HTML                    bool
	MIMEIncomplete          bool
	TransferIncomplete      bool
	ExtractionIncomplete    bool
	HTMLFallbackUsed        bool
	HTMLCPULimitExceeded    bool
	HTMLMemoryLimitExceeded bool
	CSSIncomplete           bool
	HasConcealedContent     bool
	HTMLComments            htmlCommentStats
}

// incomplete reports missing or undecodable evidence, not visibility uncertainty.
func (c extractedContent) incomplete() bool {
	return c.MIMEIncomplete || c.TransferIncomplete || c.ExtractionIncomplete
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
	// Opaque attachments contribute only a marker. Validate their encoding
	// without allocating a decoded body that no consumer will use.
	if mediaType != "text/plain" && mediaType != "text/html" && mediaType != "message/rfc822" && !strings.HasPrefix(mediaType, "multipart/") && !strings.HasPrefix(mediaType, "image/") {
		incomplete, complete := validateOpaqueTransfer(encoding, data, budget.outputShouldStop)
		return extractedContent{Text: attachmentMarker(mediaType, params["name"]), TransferIncomplete: incomplete, ExtractionIncomplete: !complete, HTMLCPULimitExceeded: budget.cpuLimitExceeded}
	}
	decoded, transferIncomplete := decodeTransferRecoveringWithStop(encoding, data, budget.decodingShouldStop)
	if decoded == nil && transferIncomplete && budget.cpuLimitExceeded {
		return stoppedMIMEContent()
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]", MIMEIncomplete: true, TransferIncomplete: transferIncomplete}
		}
		reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []extractedContent
		var alternativeHTML, alternativePlain extractedContent
		var mimeIncomplete, nestedTransferIncomplete, processingStopped bool
		var nestedExtractionIncomplete bool
		for {
			if budget.outputShouldStop() {
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
			nestedExtractionIncomplete = nestedExtractionIncomplete || content.ExtractionIncomplete
			if !hasExtractedContent(content) {
				if mediaType != "multipart/alternative" {
					parts = append(parts, content)
				}
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
			// Choosing an alternative is intentional, but failures encountered
			// while extracting any branch remain evidence limitations.
			selected.MIMEIncomplete = mimeIncomplete
			selected.ExtractionIncomplete = selected.ExtractionIncomplete || processingStopped || nestedExtractionIncomplete
			selected.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
			selected.HTML = selected.HTML || budget.htmlParts > 0
			selected.HTMLCPULimitExceeded = selected.HTMLCPULimitExceeded || budget.cpuLimitExceeded
			return selected
		}
		var combined extractedContent
		var imageRefs imageRefCollector
		links := linkCollector{compactURLs: budget.compactURLs, shouldStop: budget.outputShouldStop}
		var textParts, visibleTextParts, strippedTextParts []string
		visibleMatchesText := true
		for _, part := range parts {
			if budget.outputShouldStop() {
				processingStopped = true
				break
			}
			combined.HTML = combined.HTML || part.HTML
			combined.ConfidentVisibleChars += part.ConfidentVisibleChars
			combined.HasConcealedContent = combined.HasConcealedContent || part.HasConcealedContent
			combined.ExtractionIncomplete = combined.ExtractionIncomplete || part.ExtractionIncomplete
			combined.HTMLFallbackUsed = combined.HTMLFallbackUsed || part.HTMLFallbackUsed
			combined.HTMLCPULimitExceeded = combined.HTMLCPULimitExceeded || part.HTMLCPULimitExceeded
			combined.CSSIncomplete = combined.CSSIncomplete || part.CSSIncomplete
			combined.HTMLComments.add(part.HTMLComments)
			if !hasExtractedContent(part) {
				continue
			}
			visibleMatchesText = visibleMatchesText && sameStringStorage(part.Text, part.VisibleText)
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
		}
		combined.ImageRefs = imageRefs.refs
		combined.Links = links.links
		var complete bool
		combined.Text, complete = joinExtractedText(textParts, "\n\n", budget)
		processingStopped = processingStopped || !complete
		if complete {
			if !combined.HasConcealedContent {
				combined.StrippedText = combined.Text
			} else {
				combined.StrippedText, complete = joinExtractedText(strippedTextParts, "\n\n", budget)
				processingStopped = processingStopped || !complete
			}
		}
		if !complete {
			processingStopped = true
		} else if budget.outputShouldStop() {
			processingStopped = true
		} else if visibleMatchesText {
			combined.VisibleText = combined.Text
		} else {
			combined.VisibleText, complete = joinExtractedText(visibleTextParts, "\n\n", budget)
			processingStopped = processingStopped || !complete
		}
		combined.MIMEIncomplete = mimeIncomplete
		combined.ExtractionIncomplete = combined.ExtractionIncomplete || processingStopped || nestedExtractionIncomplete
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
		content := extractedContent{Text: attachmentMarker(mediaType, params["name"]), TransferIncomplete: transferIncomplete}
		if strings.HasPrefix(mediaType, "image/") {
			content.Images = []extractedImage{{ContentID: normalizeContentID(contentID), Data: decoded}}
		}
		return content
	}
	if mediaType == "text/html" {
		text := decodeHTMLCharsetWithStop(params["charset"], decoded, budget.htmlBytesRemaining, budget.decodingShouldStop)
		if text == "" && len(decoded) > 0 && budget.cpuLimitExceeded {
			return stoppedMIMEContent()
		}
		content := htmlToTextWithBudget(text, budget)
		content.HTML = true
		content.TransferIncomplete = transferIncomplete
		return content
	}
	text, complete := decodeCharsetWithStop(params["charset"], decoded, budget.decodedTextBytesRemaining, budget.decodingShouldStop)
	if text == "" && len(decoded) > 0 && budget.cpuLimitExceeded {
		return stoppedMIMEContent()
	}
	budget.decodedTextBytesRemaining -= int64(len(text))
	if budget.outputShouldStop() {
		return extractedContent{
			Text: text, VisibleText: text, ConfidentVisibleChars: confidentTextCharacters(text),
			TransferIncomplete: transferIncomplete, ExtractionIncomplete: true, HTMLCPULimitExceeded: budget.cpuLimitExceeded,
		}
	}
	links := linkCollector{compactURLs: budget.compactURLs, shouldStop: budget.outputShouldStop}
	promptText, urlsComplete := rewritePlainTextURLs(text, budget.compactURLs, &links, budget.outputShouldStop)
	return extractedContent{
		Text: promptText, VisibleText: text,
		ConfidentVisibleChars: confidentTextCharacters(text),
		Links:                 links.links, TransferIncomplete: transferIncomplete, ExtractionIncomplete: !complete || !urlsComplete,
		HTMLCPULimitExceeded: budget.cpuLimitExceeded,
	}
}

// sameStringStorage proves equality without scanning or maintaining duplicate
// state. Extracted strings are immutable, including guarded-builder views.
func sameStringStorage(a, b string) bool {
	return len(a) == len(b) && (len(a) == 0 || unsafe.StringData(a) == unsafe.StringData(b))
}

func joinExtractedText(parts []string, separator string, budget *extractionBudget) (string, bool) {
	if len(parts) == 0 {
		return "", true
	}
	if len(parts) == 1 {
		return parts[0], true
	}
	// strings.Join is one indivisible copy. Check immediately before it so a
	// limit crossed by the preceding combine phase cannot start another full
	// output pass.
	if budget.outputShouldStop() {
		return "", false
	}
	total := int64(len(separator)) * int64(len(parts)-1)
	const maxInt64 = int64(^uint64(0) >> 1)
	for _, part := range parts {
		if int64(len(part)) > maxInt64-total {
			budget.memoryBytesRemaining = 0
			budget.noteMemoryLimit()
			return "", false
		}
		total += int64(len(part))
	}
	if !budget.reserveOutputMemory(total) {
		return "", false
	}
	return strings.Join(parts, separator), true
}

func extractAttachedMessage(data []byte, depth int, budget *extractionBudget) extractedContent {
	attached, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return extractedContent{Text: "[attached message could not be parsed]", MIMEIncomplete: true}
	}
	body, err := io.ReadAll(attached.Body)
	if err != nil {
		return extractedContent{Text: "[attached message body could not be read]", MIMEIncomplete: true}
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
// message body. The boolean reports whether the complete decoded value fit in
// maxBytes; truncation always ends at a UTF-8 boundary.
func decodeCharset(label string, data []byte, maxBytes int64) (string, bool) {
	return decodeCharsetWithStop(label, data, maxBytes, nil)
}

func decodeCharsetWithStop(label string, data []byte, maxBytes int64, shouldStop func() bool) (string, bool) {
	control := decodeControl{shouldStop: shouldStop}
	if maxBytes < 0 {
		maxBytes = 0
	}
	bounded := func(value []byte) (string, bool) {
		text := string(value)
		if !utf8.ValidString(text) {
			text = strings.ToValidUTF8(text, "�")
		}
		if int64(len(text)) <= maxBytes {
			return text, true
		}
		end := int(maxBytes)
		for end > 0 && !utf8.RuneStart(text[end]) {
			end--
		}
		return text[:end], false
	}
	label = strings.TrimSpace(label)
	if label == "" {
		return bounded(data)
	}
	if utf8.Valid(data) {
		if _, canonical := charset.Lookup(label); canonical == "utf-8" {
			return bounded(data)
		}
	}
	reader, err := charset.NewReaderLabel(label, newDecodeReader(bytes.NewReader(data), control.check))
	if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
		return "", false
	}
	if err != nil {
		return bounded(data)
	}
	decoded, err := io.ReadAll(newDecodeReader(io.LimitReader(reader, maxBytes+1), control.check))
	if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
		return "", false
	}
	if err != nil {
		return bounded(data)
	}
	return bounded(decoded)
}

// decodeHTMLCharset keeps a usable MIME declaration authoritative. Without
// one, HTML's own BOM or early meta declaration can identify its encoding;
// this does not parse the document or change the HTML extractor.
func decodeHTMLCharset(label string, data []byte, maxBytes int) string {
	return decodeHTMLCharsetWithStop(label, data, maxBytes, nil)
}

func decodeHTMLCharsetWithStop(label string, data []byte, maxBytes int, shouldStop func() bool) string {
	control := decodeControl{shouldStop: shouldStop}
	if maxBytes < 0 {
		maxBytes = 0
	}
	// Retain one byte beyond the allowance so htmlLimits can distinguish an
	// oversized decoded body from one which exactly fits. Allow room for a
	// UTF-8 BOM while reading; it is removed before enforcing the bound.
	outputLimit := maxBytes + 1
	readLimit := int64(outputLimit + len("\ufeff"))
	bounded := func(value []byte) string {
		value = bytes.TrimPrefix(value, []byte("\ufeff"))
		if len(value) > outputLimit {
			return string(value[:outputLimit])
		}
		return string(value)
	}
	if encoding, canonical := charset.Lookup(strings.TrimSpace(label)); encoding != nil {
		if canonical == "utf-8" && utf8.Valid(data) {
			return bounded(data)
		}
		reader, err := charset.NewReaderLabel(label, newDecodeReader(bytes.NewReader(data), control.check))
		if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
			return ""
		}
		if err != nil {
			return bounded(data)
		}
		decoded, err := io.ReadAll(newDecodeReader(io.LimitReader(reader, readLimit), control.check))
		if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
			return ""
		}
		if err != nil {
			return bounded(data)
		}
		return bounded(decoded)
	}
	reader, err := charset.NewReader(newDecodeReader(bytes.NewReader(data), control.check), "text/html")
	if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
		return ""
	}
	if err != nil {
		return bounded(data)
	}
	decoded, err := io.ReadAll(newDecodeReader(io.LimitReader(reader, readLimit), control.check))
	if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
		return ""
	}
	if err != nil {
		return bounded(data)
	}
	return bounded(decoded)
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
	return decodeTransferRecoveringWithStop(encoding, data, nil)
}

func decodeTransferRecoveringWithStop(encoding string, data []byte, shouldStop func() bool) ([]byte, bool) {
	control := decodeControl{shouldStop: shouldStop}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := io.ReadAll(newDecodeReader(base64.NewDecoder(base64.StdEncoding, newDecodeReader(bytes.NewReader(data), control.check)), control.check))
		if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
			return nil, true
		}
		if err == nil {
			return decoded, false
		}
		// Some senders omit the final MIME padding. RawStdEncoding accepts that
		// specific variation without ignoring arbitrary corrupt characters.
		unpadded, rawErr := io.ReadAll(newDecodeReader(base64.NewDecoder(base64.RawStdEncoding, newDecodeReader(bytes.NewReader(data), control.check)), control.check))
		if control.stopped || errors.Is(rawErr, resourceguard.ErrStopped) {
			return nil, true
		}
		if rawErr == nil {
			return unpadded, false
		}
		if len(decoded) > 0 {
			return decoded, true
		}
		return data, true
	case "quoted-printable":
		decoded, err := io.ReadAll(newDecodeReader(quotedprintable.NewReader(newDecodeReader(bytes.NewReader(data), control.check)), control.check))
		if control.stopped || errors.Is(err, resourceguard.ErrStopped) {
			return nil, true
		}
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

// validateOpaqueTransfer preserves recovery decoder diagnostics, including
// unpadded Base64, while bounding temporary decoded storage and sampling CPU
// controls between reads. It returns transfer incompleteness and work completion.
func validateOpaqueTransfer(encoding string, data []byte, shouldStop func() bool) (bool, bool) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding != "base64" && encoding != "quoted-printable" {
		switch encoding {
		case "", "7bit", "8bit", "binary":
			return false, true
		default:
			return len(data) > 0, true
		}
	}
	var buf [32 << 10]byte
	consume := func(reader io.Reader) (error, bool) {
		for {
			if shouldStop != nil && shouldStop() {
				return nil, false
			}
			_, err := reader.Read(buf[:])
			if err == io.EOF {
				return nil, true
			}
			if err != nil {
				return err, true
			}
		}
	}
	if encoding == "quoted-printable" {
		err, complete := consume(quotedprintable.NewReader(bytes.NewReader(data)))
		return err != nil, complete
	}
	err, complete := consume(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
	if !complete || err == nil {
		return false, complete
	}
	err, complete = consume(base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(data)))
	return err != nil, complete
}

func attachmentMarker(mediaType, name string) string {
	return "[attachment: " + sanitize(name) + "; type=" + mediaType + "]"
}
