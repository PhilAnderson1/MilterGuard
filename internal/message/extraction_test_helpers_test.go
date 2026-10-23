package message

import (
	"regexp"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

var reservedAnnotation = regexp.MustCompile(`(?is)</?\s*(?:invisible|visibility-varies-by-viewport-size|visibility-uncertain|hidden-content-stripped|quoted-content)\b[^>]*>`)

func htmlToText(source string) extractedContent {
	return htmlToTextWithBudget(source, newExtractionBudget())
}

func extractMIME(contentType, encoding, contentID string, data []byte, depth int) extractedContent {
	return extractMIMEWithBudget(contentType, encoding, contentID, data, depth, newExtractionBudget())
}

func normalizeHTMLText(value string) string {
	return normalizeHTMLTextGuarded(value, nil)
}

func normalizeHTMLTextGuarded(value string, memory *resourceguard.Memory) string {
	return normalizeHTMLTextWithResources(value, memory, nil)
}

func decodeCharset(label string, data []byte, maxBytes int64) (string, bool) {
	return decodeCharsetWithResources(label, data, maxBytes, nil, nil)
}

func decodeCharsetWithStop(label string, data []byte, maxBytes int64, stop func()) (string, bool) {
	return decodeCharsetWithResources(label, data, maxBytes, stop, nil)
}

func decodeHTMLCharset(label string, data []byte, maxBytes int) string {
	return decodeHTMLCharsetWithResources(label, data, maxBytes, nil, nil)
}

func decodeHTMLCharsetWithStop(label string, data []byte, maxBytes int, stop func()) string {
	return decodeHTMLCharsetWithResources(label, data, maxBytes, stop, nil)
}

func decodeTransferRecovering(encoding string, data []byte) ([]byte, bool) {
	return decodeTransferRecoveringWithResources(encoding, data, nil, nil)
}

func decodeTransferRecoveringWithStop(encoding string, data []byte, stop func()) ([]byte, bool) {
	return decodeTransferRecoveringWithResources(encoding, data, stop, nil)
}

func newExtractionBudget() *extractionBudget {
	return newExtractionBudgetWithControl(HTMLProcessingControl{})
}
