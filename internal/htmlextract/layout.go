package htmlextract

import "strings"

const extremeOffscreenPixels = -1000

// layoutVisibilityUncertain recognizes a deliberately narrow set of common
// hiding patterns without attempting layout. These combinations are evidence
// that visibility depends on geometry, not proof that the subtree is hidden.
func layoutVisibilityUncertain(wins *[layoutProperties]layoutCandidate, style Style, parent, root Style, vars *variableScope, budget *expressionBudget) bool {
	// Keep cascade-origin uncertainty separate from value parsing. We still
	// inspect an uncertain declaration below because it may itself describe a
	// hiding pattern, but it must not turn an earlier definite concealment into
	// a trusted reveal merely by winning the layout slot.
	for i := range wins {
		if wins[i].set && wins[i].uncertainOrigin {
			return true
		}
	}
	// Resolve only declarations that can complete a hiding pattern. Width is
	// extremely common in email, but is irrelevant unless overflow clips it;
	// likewise offsets are irrelevant on a statically positioned element.
	overflowResult := resolveLayoutCandidate(wins[overflow-properties], parent, root, vars, budget)
	clipX, clipY := overflowClippingAxes(overflowResult)
	zeroX := zeroLayoutCandidate(resolveLayoutCandidate(wins[width-properties], parent, root, vars, budget)) ||
		zeroLayoutCandidate(resolveLayoutCandidate(wins[maxWidth-properties], parent, root, vars, budget))
	zeroY := zeroLayoutCandidate(resolveLayoutCandidate(wins[height-properties], parent, root, vars, budget)) ||
		zeroLayoutCandidate(resolveLayoutCandidate(wins[maxHeight-properties], parent, root, vars, budget))
	zeroBox := clipX && zeroX || clipY && zeroY

	positioned := style[position].Known && (style[position].Text == "absolute" || style[position].Text == "fixed")
	extremeOffset := false
	if positioned {
		for _, property := range [...]int{left, top, right, bottom} {
			extremeOffset = extremeOffset || extremeNegativeOffset(resolveLayoutCandidate(wins[property-properties], parent, root, vars, budget))
		}
	}

	extremeIndent := extremeNegativeOffset(resolveLayoutCandidate(wins[textIndent-properties], parent, root, vars, budget))
	extremeMargin := false
	for _, property := range [...]int{marginTop, marginRight, marginBottom, marginLeft} {
		extremeMargin = extremeMargin || extremeOrUnresolvedMargin(resolveLayoutCandidate(wins[property-properties], parent, root, vars, budget))
	}
	tinyZoom := nearZeroZoom(resolveLayoutCandidate(wins[zoom-properties], parent, root, vars, budget))
	if budget.exhausted {
		return true
	}
	return zeroBox || positioned && extremeOffset || extremeIndent || extremeMargin || tinyZoom
}

type layoutResult struct {
	value  Value
	status int
	set    bool
}

func resolveLayoutCandidate(candidate layoutCandidate, parent, root Style, vars *variableScope, budget *expressionBudget) layoutResult {
	if !candidate.set {
		return layoutResult{}
	}
	// Unsupported layout values are parsed here so a potentially active hiding
	// combination still makes visibility uncertain. Cascade-origin uncertainty
	// is retained separately on layoutCandidate and checked by the caller.
	declaration := candidate.d
	declaration.unsupported = false
	value, status := resolvedDeclaration(declaration, parent, root, vars, budget)
	return layoutResult{value: value, status: status, set: true}
}

func overflowClippingAxes(result layoutResult) (x, y bool) {
	if !result.set {
		return false, false
	}
	if result.status != 1 || !result.value.Known {
		// An unresolved but potentially valid overflow value might select a
		// clipping mode. It matters only when paired with a zero dimension.
		return true, true
	}
	parts := strings.Fields(result.value.Text)
	if len(parts) == 1 {
		parts = append(parts, parts[0])
	}
	if len(parts) != 2 {
		return false, false
	}
	clips := func(value string) bool { return value == "hidden" || value == "clip" }
	return clips(parts[0]), clips(parts[1])
}

func zeroLayoutCandidate(result layoutResult) bool {
	if !result.set || result.status != 1 || !result.value.Known || result.value.Text == "auto" || result.value.Text == "none" {
		return false
	}
	if result.value.Number == 0 {
		return true
	}
	// A clipped box no larger than one CSS pixel cannot expose readable glyphs
	// and may quantize to zero in the client. Keep the boundary conservative:
	// percentages and contextual units are not comparable without layout.
	return result.value.Number > 0 && result.value.Number <= 1 && strings.HasSuffix(result.value.Text, "px")
}

func extremeNegativeOffset(result layoutResult) bool {
	if !result.set || result.status == 0 {
		return false
	}
	if strings.HasSuffix(result.value.Text, "px") {
		return result.value.Number <= extremeOffscreenPixels
	}
	if result.status == 2 && strings.Contains(result.value.Text, "calc(") {
		// Calculation evaluation for layout lengths requires unit algebra and
		// layout context. An unresolved calculated offset can be extremely
		// negative, so it cannot establish trusted visibility.
		return true
	}
	if result.status != 2 || result.value.Number >= 0 {
		return false
	}
	if strings.HasSuffix(result.value.Text, "%") {
		return result.value.Number <= -100
	}
	// Relative and physical units cannot be converted without layout context.
	// Only very large negative magnitudes are concealment evidence.
	return result.value.Number <= -100
}

func extremeOrUnresolvedMargin(result layoutResult) bool {
	if extremeNegativeOffset(result) {
		return true
	}
	// A margin function may resolve to one or more extreme negative values, but
	// doing so requires variable substitution or CSS length algebra. Preserve
	// that uncertainty rather than treating it as a trusted visible layout.
	return result.set && result.status == 2
}

func nearZeroZoom(result layoutResult) bool {
	if !result.set {
		return false
	}
	if result.status != 1 || !result.value.Known {
		// An unresolved zoom can collapse readable content to effectively zero.
		return true
	}
	return result.value.Number <= .01
}
