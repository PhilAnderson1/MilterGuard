package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

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
	return backgroundFallbackColourTokens(tokens, nil)
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
	refs := s.collectCandidates(n, nil)
	return refs
}

func concealmentReasonStrings(mask concealmentReason) []string {
	var out []string
	for i, name := range [...]string{"display-none", "visibility-hidden", "visibility-collapse", "opacity", "font-size", "colour-distance", "empty-clip", "content-visibility-hidden"} {
		if mask&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// Test guards sample every call unless a test explicitly selects an interval.
func testCPUGuard(value cpuGuard) *cpuGuard {
	g := &value
	g.sampler = resourceguard.NewStopSampler(1, g.checkpoint)
	return g
}
