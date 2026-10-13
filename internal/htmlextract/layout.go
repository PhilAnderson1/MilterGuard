package htmlextract

import (
	"math"
	"strings"
)

const extremeOffscreenPixels = 1000

// layoutVisibilityUncertain recognizes a deliberately narrow set of common
// hiding patterns without attempting layout. These combinations are evidence
// that visibility depends on geometry, not proof that the subtree is hidden.
func layoutVisibilityUncertain(wins *[layoutProperties]layoutCandidate, style *Style, context evaluationContext) bool {
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
	clipX := overflowClips(resolveLayoutCandidate(&wins[overflowX-properties], context))
	clipY := overflowClips(resolveLayoutCandidate(&wins[overflowY-properties], context))
	zeroX := clipX && (zeroLayoutCandidate(resolveLayoutCandidate(&wins[width-properties], context)) ||
		zeroLayoutCandidate(resolveLayoutCandidate(&wins[maxWidth-properties], context)))
	zeroY := clipY && (zeroLayoutCandidate(resolveLayoutCandidate(&wins[height-properties], context)) ||
		zeroLayoutCandidate(resolveLayoutCandidate(&wins[maxHeight-properties], context)))
	zeroBox := clipX && zeroX || clipY && zeroY

	positioned := style[position].Known && (style[position].Text == "absolute" || style[position].Text == "fixed")
	extremeOffset := false
	if positioned {
		for _, property := range [...]int{left, top, right, bottom} {
			extremeOffset = extremeOffset || extremeOffsetMagnitude(resolveLayoutCandidate(&wins[property-properties], context))
		}
	}

	extremeIndent := extremeOffsetMagnitude(resolveLayoutCandidate(&wins[textIndent-properties], context))
	extremeMargin := false
	for _, property := range [...]int{marginTop, marginRight, marginBottom, marginLeft} {
		extremeMargin = extremeMargin || extremeOrUnresolvedMargin(resolveLayoutCandidate(&wins[property-properties], context))
	}
	tinyZoom := nearZeroZoom(resolveLayoutCandidate(&wins[zoom-properties], context))
	if context.budget.exhausted {
		return true
	}
	return zeroBox || positioned && extremeOffset || extremeIndent || extremeMargin || tinyZoom
}

type layoutResult struct {
	value  Value
	status valueStatus
	set    bool
}

func resolveLayoutCandidate(candidate *layoutCandidate, context evaluationContext) layoutResult {
	if !candidate.set {
		return layoutResult{}
	}
	// Unsupported layout values are parsed here so a potentially active hiding
	// combination still makes visibility uncertain. Cascade-origin uncertainty
	// is retained separately on layoutCandidate and checked by the caller.
	value, status := resolvedDeclaration(candidate.d, candidate.property, candidate.uncertainOrigin, context, true)
	return layoutResult{value: value, status: status, set: true}
}

func overflowClips(result layoutResult) bool {
	if !result.set {
		return false
	}
	if result.status != valueResolved || !result.value.Known {
		// An unresolved but potentially valid overflow value might select a
		// clipping mode. It matters only when paired with a zero dimension.
		return true
	}
	return result.value.Text == "hidden" || result.value.Text == "clip"
}

func zeroLayoutCandidate(result layoutResult) bool {
	if !result.set || result.status == valueInvalid || result.value.Text == "auto" || result.value.Text == "none" {
		return false
	}
	// CSS math can resolve a dimension to zero using viewport, percentage or
	// other contextual units that this extractor deliberately does not lay out.
	// It is concealment evidence only when overflow clips the same axis; callers
	// enforce that condition before consulting this result.
	if result.status == valueUnsupported && isMath(result.value.Text) {
		return true
	}
	if result.status != valueResolved || !result.value.Known {
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

func extremeOffsetMagnitude(result layoutResult) bool {
	if !result.set || result.status == valueInvalid {
		return false
	}
	if strings.HasSuffix(result.value.Text, "px") {
		return math.Abs(result.value.Number) >= extremeOffscreenPixels
	}
	if result.status == valueUnsupported && isMath(result.value.Text) {
		// Calculation evaluation for layout lengths requires unit algebra and
		// layout context. An unresolved calculated offset can have an extreme
		// magnitude in either direction, so it cannot establish visibility.
		return true
	}
	if result.status != valueUnsupported {
		return false
	}
	if strings.HasSuffix(result.value.Text, "%") {
		return math.Abs(result.value.Number) >= 100
	}
	// Relative and physical units cannot be converted without layout context.
	// Only very large magnitudes are concealment evidence.
	return math.Abs(result.value.Number) >= 100
}

func extremeOrUnresolvedMargin(result layoutResult) bool {
	if extremeOffsetMagnitude(result) {
		return true
	}
	// A margin function may resolve to one or more extreme negative values, but
	// doing so requires variable substitution or CSS length algebra. Preserve
	// that uncertainty rather than treating it as a trusted visible layout.
	return result.set && result.status == valueUnsupported
}

func nearZeroZoom(result layoutResult) bool {
	if !result.set {
		return false
	}
	if result.status != valueResolved || !result.value.Known {
		// An unresolved zoom can collapse readable content to effectively zero.
		return true
	}
	return result.value.Number <= .01
}
