package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"

func parseColor(s string) (string, valueStatus) {
	c, status := readColour(s)
	if status != valueResolved {
		return s, status
	}
	return colourString(c), valueResolved
}

// backgroundFallbackColour returns the colour from the final comma-separated
// background layer. Colour functions nested inside gradients are deliberately
// ignored. CSS permits a background colour only in the final layer.
func backgroundFallbackColour(value string) (string, valueStatus, bool) {
	tokens, status := lexValue(value, nil)
	if status != valueResolved {
		return value, valueUnsupported, true
	}
	return backgroundFallbackColourTokens(tokens)
}

func labelBit(label string) visibilityLabel {
	switch label {
	case "concealed":
		return labelConcealed
	case "unknown":
		return labelUnknown
	default:
		return labelVisible
	}
}

func (s *sheet) candidates(n *html.Node) []selectorRef {
	refs, _ := s.collectCandidates(n, nil)
	return refs
}
