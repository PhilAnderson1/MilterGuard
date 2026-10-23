package message

import (
	"bytes"
	"mime/multipart"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// multipartBodyFromFirstBoundary removes an irrelevant MIME preamble before
// handing the body to mime/multipart. The standard reader rejects a preamble
// line longer than its internal buffer before it can find the boundary.
// Returning a suffix of source is allocation-free.
func multipartBodyFromFirstBoundary(source []byte, boundary string, check func()) []byte {
	lineStart := true
	for offset := 0; offset < len(source); offset++ {
		if offset%resourceguard.WorkChunk == 0 && check != nil {
			check()
		}
		if lineStart && multipartBoundaryLine(source[offset:], boundary) {
			return source[offset:]
		}
		lineStart = source[offset] == '\n'
	}
	return source
}

func multipartBoundaryLine(line []byte, boundary string) bool {
	if len(line) < len(boundary)+2 || line[0] != '-' || line[1] != '-' {
		return false
	}
	for i := range len(boundary) {
		if line[i+2] != boundary[i] {
			return false
		}
	}
	offset := len(boundary) + 2
	final := len(line)-offset >= 2 && line[offset] == '-' && line[offset+1] == '-'
	if final {
		offset += 2
	}
	for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
		offset++
	}
	if offset == len(line) {
		return final
	}
	return line[offset] == '\n' || line[offset] == '\r' && offset+1 < len(line) && line[offset+1] == '\n'
}

type mimePartRead struct {
	part *multipart.Part
	body []byte
	err  error
}

// Restart only the interrupted part. Replaying multipart framing skips completed
// parts without extracting them again. All replay reads spend fallback CPU.
func readRestartableMIMEPart(reader **multipart.Reader, source []byte, boundary string, index int, budget *extractionBudget) (mimePartRead, bool) {
	retry := false
	return runExtraction(budget, func() mimePartRead {
		if retry {
			*reader = multipart.NewReader(newDecodeReader(bytes.NewReader(source), budget.stageStop), boundary)
			for i := 0; i < index; i++ {

				if _, err := (*reader).NextPart(); err != nil {
					return mimePartRead{err: err}
				}

			}
		}
		retry = true
		budget.checkStage()
		part, err := (*reader).NextPart()
		if err != nil {
			return mimePartRead{err: err}
		}
		decoder := decodeControl{shouldStop: budget.stageStop, memory: budget.allocationMemory}
		body, err := decoder.readAll(part)
		return mimePartRead{part: part, body: body, err: err}
	})
}

// Keep a complete result on terminal fallback failure. Combining more evidence
// would require work under an exhausted allowance.
func retainedMIMEPart(parts []extractedContent) extractedContent {
	for i := len(parts) - 1; i >= 0; i-- {
		if hasExtractedContent(parts[i]) {
			return parts[i]
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return extractedContent{}
}

// Preserve evidence-quality signals from completed siblings even when a
// terminal resource failure permits retaining only one part's content.
func retainMIMEPartFlags(content *extractedContent, parts []extractedContent) {
	for i := range parts {
		content.HTMLFallbackUsed = content.HTMLFallbackUsed || parts[i].HTMLFallbackUsed
		content.CSSIncomplete = content.CSSIncomplete || parts[i].CSSIncomplete
		content.HasConcealedContent = content.HasConcealedContent || parts[i].HasConcealedContent
	}
}

// Retaining a completed part is a separate restartable allocation operation.
// If primary admission fails here, fallback grows the collection without
// decoding or extracting any completed part again.
func appendMIMEPart(budget *extractionBudget, parts []extractedContent, content extractedContent) ([]extractedContent, bool) {
	result, ok := runExtraction(budget, func() []extractedContent {
		grown := resourceguard.Append(budget.allocationMemory(), parts, nil, content)
		return grown
	})
	if !ok {
		return parts, false
	}
	return result, true
}
