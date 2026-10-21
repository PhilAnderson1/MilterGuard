package message

import "github.com/PhilAnderson1/MilterGuard/internal/resourceguard"

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
