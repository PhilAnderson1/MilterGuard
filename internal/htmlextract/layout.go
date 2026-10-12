package htmlextract

import "strings"

const extremeOffscreenPixels = -1000

// layoutVisibilityUncertain recognizes a deliberately narrow set of common
// hiding patterns without attempting layout. These combinations are evidence
// that visibility depends on geometry, not proof that the subtree is hidden.
func layoutVisibilityUncertain(wins *[layoutProperties]layoutCandidate, style Style, parent, root Style, vars *variableScope, budget *expressionBudget) bool {
	// Resolve only declarations that can complete a hiding pattern. Width is
	// extremely common in email, but is irrelevant unless overflow clips it;
	// likewise offsets are irrelevant on a statically positioned element.
	overflowValue, overflowSet := resolvedLayoutCandidate(wins[overflow-properties], parent, root, vars, budget)
	clippedOverflow := overflowSet && (overflowValue.Text == "hidden" || overflowValue.Text == "clip")
	zeroBox := false
	if clippedOverflow {
		for _, property := range [...]int{width, height, maxHeight} {
			value, set := resolvedLayoutCandidate(wins[property-properties], parent, root, vars, budget)
			zeroBox = zeroBox || set && zeroLayoutLength(value)
		}
	}

	positioned := style[position].Known && (style[position].Text == "absolute" || style[position].Text == "fixed")
	extremeOffset := false
	if positioned {
		for _, property := range [...]int{left, top} {
			value, set := resolvedLayoutCandidate(wins[property-properties], parent, root, vars, budget)
			extremeOffset = extremeOffset || set && extremeNegativeOffset(value)
		}
	}

	indentValue, indentSet := resolvedLayoutCandidate(wins[textIndent-properties], parent, root, vars, budget)
	extremeIndent := indentSet && extremeNegativeOffset(indentValue)
	if budget.exhausted {
		return true
	}
	return clippedOverflow && zeroBox || positioned && extremeOffset || extremeIndent
}

func resolvedLayoutCandidate(candidate layoutCandidate, parent, root Style, vars *variableScope, budget *expressionBudget) (Value, bool) {
	if !candidate.set {
		return Value{}, false
	}
	// An uncertain selector or media condition marks its declarations
	// unsupported for ordinary resolution. Parse the underlying value here so
	// a potentially active hiding combination still makes visibility uncertain
	// across the aggregate viewing cases.
	declaration := *candidate.d
	declaration.unsupported = false
	value, status := resolvedDeclaration(declaration, parent, root, vars, budget)
	return value, status == 1 && value.Known
}

func zeroLayoutLength(value Value) bool {
	return value.Known && value.Number == 0 && value.Text != "auto" && value.Text != "none"
}

func extremeNegativeOffset(value Value) bool {
	return value.Known && strings.HasSuffix(value.Text, "px") && value.Number <= extremeOffscreenPixels
}
