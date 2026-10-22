package message

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime/multipart"
	"mime/quotedprintable"
	"net/url"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/charset"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

const (
	maxMIMEParts = 256
	maxHTMLParts = 32
)

type extractionBudget struct {
	extractionProgress

	primaryMemory *resourceguard.Memory
	stageStop     func()

	checkPrimary     func()
	checkFallback    func()
	terminal         termination.Failure
	memoryBytesLimit int64

	onCPULimit             func(fallback bool)
	cpuLimitExceeded       bool
	fallback               *fallbackResources
	allowFallback          func() bool
	fallbackMemoryExceeded bool
	onFallbackMemoryLimit  func()
	memoryLimitExceeded    bool
	onMemoryLimit          func()
	stopOnMemoryLimit      bool
	compactURLs            bool
	countingStop           func()
	countingSampler        resourceguard.StopSampler
}

// extractionProgress contains the traversal allowances that must rewind when
// an interrupted MIME operation is replayed under the fallback stage.
type extractionProgress struct {
	parts                     int
	htmlParts                 int
	htmlBytesRemaining        int
	decodedTextBytesRemaining int64
	cssBytesRemaining         int
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
		extractionProgress: extractionProgress{
			htmlBytesRemaining:        limits.InputBytes,
			decodedTextBytesRemaining: int64(limits.InputBytes),
			cssBytesRemaining:         limits.CSSBytes,
		},
		primaryMemory:    resourceguard.NewMemory(limits.MemoryBytes),
		checkPrimary:     control.CheckPrimary,
		onCPULimit:       control.CPULimitExceeded,
		checkFallback:    control.CheckFallback,
		memoryBytesLimit: limits.MemoryBytes,

		compactURLs:           !control.DisableURLCompaction,
		onMemoryLimit:         control.MemoryLimitExceeded,
		allowFallback:         control.BeginFallback,
		onFallbackMemoryLimit: control.FallbackMemoryLimitExceeded,
		stopOnMemoryLimit:     control.StopOnMemoryLimit,
	}
}

func (b *extractionBudget) setDecodedTextByteLimit(bytes int64) {
	if bytes < 0 {
		bytes = 0
	}
	b.decodedTextBytesRemaining = bytes
}

// Output and decoding use the active stage. Once fallback starts, the primary
// allowance is never sampled again, including for later MIME parts.
func (b *extractionBudget) outputShouldStop() { b.checkStage() }

func (b *extractionBudget) decodingShouldStop() { b.checkStage() }

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

// consumeMemory transfers admitted child usage during normal return or unwind.
// The child limit is the primary remainder; primary charges wait for this transfer.
func (b *extractionBudget) consumeMemory(memory *resourceguard.Memory) {
	if memory != b.primaryMemory {
		b.primaryMemory.RecordUsage(memory.Charged())
	}
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
	remaining := b.remainingMemory()
	if remaining <= 0 {
		// Starting HTML analysis requires storage. Reject at the owner so this
		// cannot become an ordinary structural-limit result or an inline retry.
		b.primaryMemory.Reserve(1)
	}
	if b.htmlParts > maxHTMLParts || bytes > b.htmlBytesRemaining || b.cssBytesRemaining <= 0 {
		b.htmlBytesRemaining = 0
		return htmlextract.Limits{}, false
	}
	b.htmlBytesRemaining -= bytes
	limits := htmlextract.DefaultLimits()
	limits.CSSBytes = b.cssBytesRemaining
	limits.MemoryBytes = remaining
	return limits, true
}

// consumeHTML publishes usage bounded by htmlLimits, including during unwind.
// No primary charges may intervene between admitting those limits and this call.
func (b *extractionBudget) consumeHTML(usage htmlextract.AnalysisUsage) {
	if usage.MemoryLimitExceeded {
		b.noteMemoryLimit()
	}
	b.cssBytesRemaining = remainingInt(b.cssBytesRemaining, usage.CSSBytes)
	b.primaryMemory.RecordUsage(usage.MemoryBytes)
}

func (b *extractionBudget) reserveOutputMemory(bytes int64) { b.allocationMemory().Reserve(bytes) }

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
	Text                            string
	VisibleText                     string
	ConfidentVisibleChars           int
	StrippedText                    string
	Links                           []string
	ImageRefs                       []string
	Images                          []extractedImage
	HTML                            bool
	MIMEIncomplete                  bool
	TransferIncomplete              bool
	ExtractionIncomplete            bool
	HTMLFallbackUsed                bool
	HTMLCPULimitExceeded            bool
	HTMLMemoryLimitExceeded         bool
	HTMLPrimaryMemoryLimitExceeded  bool
	HTMLFallbackMemoryLimitExceeded bool
	CSSIncomplete                   bool
	HasConcealedContent             bool
	HTMLComments                    htmlCommentStats
}

// incomplete reports missing or undecodable evidence, not visibility uncertainty.
func (c extractedContent) incomplete() bool {
	return c.MIMEIncomplete || c.TransferIncomplete || c.ExtractionIncomplete
}

type extractedImage struct {
	ContentID string
	Data      []byte
}

func extractMIMEWithBudget(contentType, encoding, contentID string, data []byte, depth int, budget *extractionBudget) extractedContent {
	var retained extractedContent
	// Replay restores traversal/output allowances, never allocation ledgers or
	// terminal outcomes.
	progress := budget.extractionProgress
	retry := false
	result, complete := runExtraction(budget, func() extractedContent {
		if retry {
			budget.extractionProgress = progress
		}
		retry = true
		return extractMIMEOnce(contentType, encoding, contentID, data, depth, budget, &retained)
	})
	if !complete {
		retained.ExtractionIncomplete = true
		retained.MIMEIncomplete = true
		result = retained
	}
	result.HTMLCPULimitExceeded = result.HTMLCPULimitExceeded || budget.cpuLimitExceeded
	result.HTMLPrimaryMemoryLimitExceeded = budget.memoryLimitExceeded
	result.HTMLFallbackMemoryLimitExceeded = budget.fallbackMemoryExceeded
	result.HTMLMemoryLimitExceeded = result.HTMLMemoryLimitExceeded || budget.memoryLimitExceeded || budget.fallbackMemoryExceeded
	return result
}

func extractMIMEOnce(contentType, encoding, contentID string, data []byte, depth int, budget *extractionBudget, retained *extractedContent) extractedContent {
	if depth > 8 {
		return extractedContent{Text: "[MIME nesting limit reached]", MIMEIncomplete: true}
	}
	mediaType, params, err := resourceguard.ParseMediaType(budget.allocationMemory(), contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	mediaType = strings.ToLower(mediaType)
	// Opaque attachments contribute only a marker. Validate their encoding
	// without allocating a decoded body that no consumer will use.
	if mediaType != "text/plain" && mediaType != "text/html" && mediaType != "message/rfc822" && !strings.HasPrefix(mediaType, "multipart/") && !strings.HasPrefix(mediaType, "image/") {
		incomplete := validateOpaqueTransfer(encoding, data, budget.outputShouldStop)
		return extractedContent{Text: attachmentMarker(mediaType, params["name"]), TransferIncomplete: incomplete, HTMLCPULimitExceeded: budget.cpuLimitExceeded}
	}
	decoded, transferIncomplete := decodeTransferRecoveringWithResources(encoding, data, budget.decodingShouldStop, budget.allocationMemory)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]", MIMEIncomplete: true, TransferIncomplete: transferIncomplete}
		}
		reader := multipart.NewReader(newDecodeReader(bytes.NewReader(decoded), budget.stageStop), boundary)

		partIndex := 0
		var parts []extractedContent
		var alternativeHTML, alternativePlain extractedContent
		var mimeIncomplete, nestedTransferIncomplete, processingStopped bool
		var nestedExtractionIncomplete bool
		for {
			if budget.parts >= maxMIMEParts {
				mimeIncomplete = true
				break
			}
			var part *multipart.Part
			var body []byte
			var readErr error
			{
				read, complete := readRestartableMIMEPart(&reader, decoded, boundary, partIndex, budget)
				if !complete {
					mimeIncomplete = true
					processingStopped = true
					break
				}
				part, body, readErr = read.part, read.body, read.err
				if part == nil {
					if readErr != io.EOF {
						mimeIncomplete = true
					}
					break
				}
			}

			budget.takePart()
			partIndex++
			mimeIncomplete = mimeIncomplete || readErr != nil

			partContentType := part.Header.Get("Content-Type")
			if mediaType == "multipart/digest" && strings.TrimSpace(partContentType) == "" {
				partContentType = "message/rfc822"
			}
			content := extractMIMEWithBudget(partContentType, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-ID"), body, depth+1, budget)
			mimeIncomplete = mimeIncomplete || content.MIMEIncomplete
			nestedTransferIncomplete = nestedTransferIncomplete || content.TransferIncomplete
			nestedExtractionIncomplete = nestedExtractionIncomplete || content.ExtractionIncomplete
			if retained != nil && hasExtractedContent(content) {
				*retained = content
			}
			if budget.terminal.Code != termination.None {
				if !hasExtractedContent(content) {
					content = retainedMIMEPart(parts)
				}
				content.ExtractionIncomplete = true
				content.MIMEIncomplete = true
				return content
			}
			if !hasExtractedContent(content) {
				if mediaType != "multipart/alternative" {
					var ok bool
					parts, ok = appendMIMEPart(budget, parts, content)
					if !ok {
						mimeIncomplete = true
						processingStopped = true
						break
					}
				}
				continue
			}
			var ok bool
			parts, ok = appendMIMEPart(budget, parts, content)
			if !ok {
				mimeIncomplete = true
				processingStopped = true
				if len(parts) == 0 {
					alternativePlain = content
				}
				break
			}
			if mediaType == "multipart/alternative" {
				partMediaType, _, _ := resourceguard.ParseMediaType(budget.allocationMemory(), partContentType)
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
		if budget.terminal.Code != termination.None {
			content := retainedMIMEPart(parts)
			content.ExtractionIncomplete = true
			content.MIMEIncomplete = true
			return content
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
		assemble := func() extractedContent {
			var combined extractedContent
			if len(parts) == 0 && hasExtractedContent(alternativePlain) {
				combined = alternativePlain
			}
			imageRefs := imageRefCollector{memory: budget.allocationMemory()}
			links := linkCollector{compactURLs: budget.compactURLs, memory: budget.allocationMemory(), shouldStop: budget.outputShouldStop}
			var textParts, visibleTextParts, strippedTextParts []string
			visibleMatchesText := true
			for _, part := range parts {
				budget.outputShouldStop()

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
				textParts = resourceguard.Append(budget.allocationMemory(), textParts, nil, part.Text)

				visibleTextParts = resourceguard.Append(budget.allocationMemory(), visibleTextParts, nil, part.VisibleText)

				stripped := part.StrippedText
				if stripped == "" && !part.HasConcealedContent {
					stripped = part.Text
				}
				if stripped != "" {
					strippedTextParts = resourceguard.Append(budget.allocationMemory(), strippedTextParts, nil, stripped)
				}
				for _, destination := range part.Links {
					links.AddDestination(destination)
				}
				imageRefs.AddAll(part.ImageRefs)
				combined.Images = resourceguard.Append(budget.allocationMemory(), combined.Images, nil, part.Images...)
			}
			combined.ImageRefs = imageRefs.refs
			combined.Links = links.links
			if len(textParts) > 0 {
				combined.Text = joinExtractedText(textParts, "\n\n", budget)
			}
			if len(textParts) > 0 || !processingStopped {
				if !combined.HasConcealedContent {
					combined.StrippedText = combined.Text
				} else {
					combined.StrippedText = joinExtractedText(strippedTextParts, "\n\n", budget)
				}
				budget.outputShouldStop()
				if visibleMatchesText {
					combined.VisibleText = combined.Text
				} else {
					combined.VisibleText = joinExtractedText(visibleTextParts, "\n\n", budget)
				}
			}
			combined.MIMEIncomplete = mimeIncomplete
			combined.ExtractionIncomplete = combined.ExtractionIncomplete || processingStopped || nestedExtractionIncomplete
			combined.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
			combined.HTML = combined.HTML || budget.htmlParts > 0
			combined.HTMLCPULimitExceeded = combined.HTMLCPULimitExceeded || budget.cpuLimitExceeded
			return combined
		}

		combined, complete := runExtraction(budget, assemble)
		if !complete {
			combined = retainedMIMEPart(parts)
			combined.ExtractionIncomplete = true
			combined.MIMEIncomplete = true
		}
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
		text := decodeHTMLCharsetWithResources(params["charset"], decoded, budget.htmlBytesRemaining, budget.decodingShouldStop, budget.allocationMemory)
		content := htmlToTextWithBudget(text, budget)
		content.HTML = true
		content.TransferIncomplete = transferIncomplete
		return content
	}
	text, complete := decodeCharsetWithResources(params["charset"], decoded, budget.decodedTextBytesRemaining, budget.decodingShouldStop, budget.allocationMemory)
	budget.decodedTextBytesRemaining -= int64(len(text))

	budget.outputShouldStop()

	links := linkCollector{compactURLs: budget.compactURLs, memory: budget.allocationMemory(), shouldStop: budget.outputShouldStop}
	promptText := rewritePlainTextURLs(text, budget.compactURLs, &links, budget.allocationMemory(), budget.outputShouldStop)
	confidentChars := budget.confidentCharacters(text)
	return extractedContent{
		Text: promptText, VisibleText: text,
		ConfidentVisibleChars: confidentChars,
		Links:                 links.links, TransferIncomplete: transferIncomplete, ExtractionIncomplete: !complete,
		HTMLMemoryLimitExceeded: budget.memoryLimitExceeded || budget.fallbackMemoryExceeded,
		HTMLCPULimitExceeded:    budget.cpuLimitExceeded,
	}
}

// sameStringStorage proves equality without scanning or maintaining duplicate
// state. Extracted strings are immutable, including guarded-builder views.
func sameStringStorage(a, b string) bool {
	return len(a) == len(b) && (len(a) == 0 || unsafe.StringData(a) == unsafe.StringData(b))
}

func joinExtractedText(parts []string, separator string, budget *extractionBudget) string {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		return parts[0]
	}

	// strings.Join is one indivisible copy. Check immediately before it so a
	// limit crossed by the preceding combine phase cannot start another full
	// output pass.
	budget.outputShouldStop()

	total := int64(len(separator)) * int64(len(parts)-1)
	const maxInt64 = int64(^uint64(0) >> 1)
	for _, part := range parts {
		if int64(len(part)) > maxInt64-total {
			budget.reserveOutputMemory(maxInt64)
		}
		total += int64(len(part))
	}
	budget.reserveOutputMemory(total)
	return strings.Join(parts, separator)
}

// decodeCharsetWithResources converts MIME text bodies to UTF-8 after their
// transfer encoding has been decoded. Unknown labels and malformed encoded
// text retain the original content so that a bad charset declaration cannot
// erase the message body. The boolean reports whether the complete decoded
// value fit in maxBytes; truncation always ends at a UTF-8 boundary.
func decodeCharsetWithResources(label string, data []byte, maxBytes int64, shouldStop func(), memory func() *resourceguard.Memory) (string, bool) {
	control := decodeControl{shouldStop: shouldStop, memory: memory}
	if maxBytes < 0 {
		maxBytes = 0
	}
	bounded := func(value []byte) (string, bool) {
		text := control.copyString(value)
		if !utf8.ValidString(text) {
			control.allocationMemory().Reserve(int64(len(text)) * 3)

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
	if err != nil {
		return bounded(data)
	}
	decoded, err := control.readAll(newDecodeReader(io.LimitReader(reader, maxBytes+1), control.check))
	if err != nil {
		return bounded(data)
	}
	return bounded(decoded)
}

// decodeHTMLCharsetWithResources keeps a usable MIME declaration authoritative.
// Without one, HTML's own BOM or early meta declaration can identify its
// encoding; this does not parse the document or change the HTML extractor.
func decodeHTMLCharsetWithResources(label string, data []byte, maxBytes int, shouldStop func(), memory func() *resourceguard.Memory) string {
	control := decodeControl{shouldStop: shouldStop, memory: memory}
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
			return control.copyString(value[:outputLimit])
		}
		return control.copyString(value)
	}

	if encoding, canonical := charset.Lookup(strings.TrimSpace(label)); encoding != nil {
		if canonical == "utf-8" && utf8.Valid(data) {
			return bounded(data)
		}
		reader, err := charset.NewReaderLabel(label, newDecodeReader(bytes.NewReader(data), control.check))
		if err != nil {
			return bounded(data)
		}
		decoded, err := control.readAll(newDecodeReader(io.LimitReader(reader, readLimit), control.check))
		if err != nil {
			return bounded(data)
		}
		return bounded(decoded)
	}

	reader, err := charset.NewReader(newDecodeReader(bytes.NewReader(data), control.check), "text/html")
	if err != nil {
		return bounded(data)
	}
	decoded, err := control.readAll(newDecodeReader(io.LimitReader(reader, readLimit), control.check))
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

// decodeTransferRecoveringWithResources keeps readable evidence from malformed
// encodings and accepts omitted Base64 padding. Attachment inspection uses a
// separate strict decoder so incomplete data cannot be reported as successfully
// scanned.
func decodeTransferRecoveringWithResources(encoding string, data []byte, shouldStop func(), memory func() *resourceguard.Memory) ([]byte, bool) {
	control := decodeControl{shouldStop: shouldStop, memory: memory}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := control.readAll(newDecodeReader(base64.NewDecoder(base64.StdEncoding, newDecodeReader(bytes.NewReader(data), control.check)), control.check))
		if err == nil {
			return decoded, false
		}
		// Some senders omit the final MIME padding. RawStdEncoding accepts that
		// specific variation without ignoring arbitrary corrupt characters.
		unpadded, rawErr := control.readAll(newDecodeReader(base64.NewDecoder(base64.RawStdEncoding, newDecodeReader(bytes.NewReader(data), control.check)), control.check))
		if rawErr == nil {
			return unpadded, false
		}
		if len(decoded) > 0 {
			return decoded, true
		}
		return data, true
	case "quoted-printable":
		decoded, err := control.readAll(newDecodeReader(quotedprintable.NewReader(newDecodeReader(bytes.NewReader(data), control.check)), control.check))
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
// controls between reads. It returns transfer incompleteness; resource termination unwinds.
func validateOpaqueTransfer(encoding string, data []byte, shouldStop func()) bool {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	if encoding != "base64" && encoding != "quoted-printable" {
		switch encoding {
		case "", "7bit", "8bit", "binary":
			return false
		default:
			return len(data) > 0
		}
	}
	var buf [32 << 10]byte
	consume := func(reader io.Reader) error {
		for {
			if shouldStop != nil {
				shouldStop()
			}

			_, err := reader.Read(buf[:])
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}
	if encoding == "quoted-printable" {
		err := consume(quotedprintable.NewReader(bytes.NewReader(data)))
		return err != nil
	}
	err := consume(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
	if err == nil {
		return false
	}
	err = consume(base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(data)))
	return err != nil
}

func attachmentMarker(mediaType, name string) string {
	return "[attachment: " + sanitize(name) + "; type=" + mediaType + "]"
}
