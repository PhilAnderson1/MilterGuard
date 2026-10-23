package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func number(s string) (float64, bool) { return numberWithBudget(s, nil) }

func tokenText(ts []valueToken) string { return tokenTextWithBudget(ts, nil) }

func asciiLower(s string) string { return asciiLowerWithBudget(s, nil) }

func normalizeCSSKeyword(s string) string {
	return asciiLower(trimCSSWhitespace(s))
}

func readColour(s string) (RGBA, valueStatus) { return readColourWithBudget(s, nil) }

func colourString(c RGBA) string { return colourStringWithBudget(c, nil) }

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
	active := &s.runtime.activeAncestors
	active.reset(s.index.count, nil)
	active.enabled = s.hasAncestorSelectorIndex()
	var ancestors []*html.Node
	for ancestor := n.Parent; ancestor != nil; ancestor = ancestor.Parent {
		if ancestor.Type == html.ElementNode {
			ancestors = append(ancestors, ancestor)
		}
	}
	for i := len(ancestors) - 1; i >= 0; i-- {
		s.activateAncestorBuckets(ancestors[i], nil)
	}
	refs := s.collectCandidates(n, nil)
	active.enabled = false
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

func legacyDeclarationsWithBudget(n *html.Node, budget *cpuGuard) []declaration {
	return legacyDeclarationsWithBody(n, nil, budget)
}

func substituteTokens(ts []valueToken, lookup func(string) variableValue, budget *cpuGuard, depth int) variableValue {
	return substituteIndexedTokens(ts, nil, lookup, budget, depth)
}

func planSelectorList(source string, nextSequence *int, memory *resourceguard.Memory, remainingBranches int) ([]selectorPlan, int, bool) {
	plans, branches, exceeded := planSelectorListWithStop(source, nextSequence, memory, remainingBranches, nil)
	return plans, branches, exceeded
}

func resolveLayoutProperty(property int, value string) (Value, valueStatus) {
	return resolveLayoutPropertyWithBudget(property, value, nil)
}

func marginShorthandValues(value string) ([4]string, bool, bool) {
	return marginShorthandValuesWithBudget(value, nil)
}

func relevantDeclarationProperty(prop string) bool {
	return relevantNormalizedDeclarationProperty(normalizeDeclarationProperty(prop))
}

func normalizeDeclarationProperty(prop string) string {
	return normalizeDeclarationPropertyWithBudget(prop, nil)
}
