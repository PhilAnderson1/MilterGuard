package message

import (
	"bytes"
	"mime/multipart"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

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
