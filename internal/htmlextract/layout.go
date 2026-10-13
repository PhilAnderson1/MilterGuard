package htmlextract

import (
	"math"
	"strings"

	"golang.org/x/net/html"
)

// Email reading panes can be substantially narrower than a desktop browser.
// Offsets at this magnitude can place ordinary-sized text wholly outside a
// plausible pane, but are not definitive without layout, so they produce
// visibility uncertainty rather than an invisible classification.
const extremeOffscreenPixels = 250
const extremeMarginPixels = 1000
const extremeNegativeSpacingPixels = 8

// layoutVisibilityUncertain recognizes a deliberately narrow set of common
// hiding patterns without attempting layout. These combinations are evidence
// that visibility depends on geometry, not proof that the subtree is hidden.
func layoutVisibilityUncertain(wins *[layoutProperties]layoutCandidate, style *Style, context evaluationContext) bool {
	uncertain, _ := layoutVisibility(wins, style, context, nil)
	return uncertain
}

func layoutVisibility(wins *[layoutProperties]layoutCandidate, style *Style, context evaluationContext, node *html.Node) (bool, bool) {
	// Resolve only declarations that can complete a hiding pattern. Width is
	// extremely common in email, but is irrelevant unless overflow clips it;
	// likewise offsets are irrelevant on a statically positioned element.
	overflowXResult := resolveLayoutCandidate(&wins[overflowX-properties], context)
	overflowYResult := resolveLayoutCandidate(&wins[overflowY-properties], context)
	clipX := overflowClips(overflowXResult)
	clipY := overflowClips(overflowYResult)
	isImage := node != nil && node.Namespace == "" && node.Data == "img"
	var widthResult, heightResult, maxWidthResult, maxHeightResult layoutResult
	if clipX || wins[overflowX-properties].uncertainOrigin || isImage {
		widthResult = resolveLayoutCandidate(&wins[width-properties], context)
	}
	if clipX || wins[overflowX-properties].uncertainOrigin {
		maxWidthResult = resolveLayoutCandidate(&wins[maxWidth-properties], context)
	}
	if clipY || wins[overflowY-properties].uncertainOrigin || isImage {
		heightResult = resolveLayoutCandidate(&wins[height-properties], context)
	}
	if clipY || wins[overflowY-properties].uncertainOrigin {
		maxHeightResult = resolveLayoutCandidate(&wins[maxHeight-properties], context)
	}
	zeroWidth := zeroLayoutCandidate(widthResult) || zeroLayoutCandidate(maxWidthResult)
	zeroHeight := zeroLayoutCandidate(heightResult) || zeroLayoutCandidate(maxHeightResult)
	zeroX := clipX && zeroWidth
	zeroY := clipY && zeroHeight
	zeroBox := clipX && zeroX || clipY && zeroY
	tinyWidth := tinyImageDimension(widthResult)
	tinyHeight := tinyImageDimension(heightResult)
	elementConcealed := isImage &&
		(tinyWidth && !wins[width-properties].uncertainOrigin || tinyHeight && !wins[height-properties].uncertainOrigin)

	// A client-dependent winner matters only when the property can participate
	// in a hiding pattern. Responsive email templates commonly put harmless
	// width declarations in MSO conditional styles; treating width alone as a
	// visibility question makes every descendant uncertain. Keep uncertainty
	// for paired clipping/positioning patterns and for properties which can move
	// or collapse content by themselves.
	uncertainOrigin :=
		(wins[overflowX-properties].uncertainOrigin && zeroWidth) ||
			(wins[overflowY-properties].uncertainOrigin && zeroHeight) ||
			((wins[width-properties].uncertainOrigin || wins[maxWidth-properties].uncertainOrigin) && clipX) ||
			((wins[height-properties].uncertainOrigin || wins[maxHeight-properties].uncertainOrigin) && clipY) ||
			(isImage && (tinyWidth && wins[width-properties].uncertainOrigin || tinyHeight && wins[height-properties].uncertainOrigin))

	positioned := style[position].Known && (style[position].Text == "absolute" || style[position].Text == "fixed")
	extremeOffset := false
	if positioned {
		for _, property := range [...]int{left, top, right, bottom} {
			extremeOffset = extremeOffset || extremeOffsetMagnitude(resolveLayoutCandidate(&wins[property-properties], context))
		}
	}
	if positioned {
		for _, property := range [...]int{left, top, right, bottom} {
			uncertainOrigin = uncertainOrigin || wins[property-properties].uncertainOrigin
		}
	}

	extremeIndent := extremeOffsetMagnitude(resolveLayoutCandidate(&wins[textIndent-properties], context))
	extremeSpacing := extremeNegativeSpacing(resolveLayoutCandidate(&wins[letterSpacing-properties], context)) ||
		extremeNegativeSpacing(resolveLayoutCandidate(&wins[wordSpacing-properties], context))
	extremeMargin := false
	for _, property := range [...]int{marginTop, marginRight, marginBottom, marginLeft} {
		extremeMargin = extremeMargin || extremeOrUnresolvedMargin(resolveLayoutCandidate(&wins[property-properties], context))
		uncertainOrigin = uncertainOrigin || wins[property-properties].uncertainOrigin
	}
	uncertainOrigin = uncertainOrigin || wins[textIndent-properties].uncertainOrigin ||
		wins[letterSpacing-properties].uncertainOrigin || wins[wordSpacing-properties].uncertainOrigin ||
		wins[zoom-properties].uncertainOrigin
	tinyZoom := nearZeroZoom(resolveLayoutCandidate(&wins[zoom-properties], context))
	if context.budget.exhausted {
		return true, false
	}
	uncertain := uncertainOrigin || zeroBox || positioned && extremeOffset || extremeIndent || extremeSpacing || extremeMargin || tinyZoom
	return uncertain, elementConcealed
}

func tinyImageDimension(result layoutResult) bool {
	if !result.set || result.status != valueResolved || !result.value.Known || result.value.Text == "auto" || result.value.Text == "none" {
		return false
	}
	if result.value.Number == 0 {
		return true
	}
	return result.value.Number > 0 && result.value.Number <= 1 && strings.HasSuffix(result.value.Text, "px")
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
	return extremeMagnitude(result, extremeOffscreenPixels)
}

func extremeMagnitude(result layoutResult, pixelThreshold float64) bool {
	if !result.set || result.status == valueInvalid {
		return false
	}
	if strings.HasSuffix(result.value.Text, "px") {
		return math.Abs(result.value.Number) >= pixelThreshold
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
	if extremeMagnitude(result, extremeMarginPixels) {
		return true
	}
	// A margin function may resolve to one or more extreme negative values, but
	// doing so requires variable substitution or CSS length algebra. Preserve
	// that uncertainty rather than treating it as a trusted visible layout.
	return result.set && result.status == valueUnsupported
}

func extremeNegativeSpacing(result layoutResult) bool {
	if !result.set || result.status == valueInvalid || result.value.Text == "normal" {
		return false
	}
	if result.status == valueUnsupported && isMath(result.value.Text) {
		// Resolving calculated spacing requires unit algebra and font/layout
		// context. It can collapse a text run, so retain uncertainty.
		return true
	}
	if result.value.Number >= 0 {
		return false
	}
	if strings.HasSuffix(result.value.Text, "px") {
		return result.value.Number <= -extremeNegativeSpacingPixels
	}
	if result.status != valueUnsupported {
		return false
	}
	if strings.HasSuffix(result.value.Text, "%") {
		return result.value.Number <= -50
	}
	// Half a font-relative or physical unit is already far outside ordinary
	// email typography. The actual pixel size needs client font metrics.
	return result.value.Number <= -.5
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
