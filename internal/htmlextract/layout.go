package htmlextract

import (
	"math"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// Email reading panes can be substantially narrower than a desktop browser.
// Offsets at this magnitude can place ordinary-sized text wholly outside a
// plausible pane, but are not definitive without layout, so they produce
// visibility uncertainty rather than an invisible classification.
const extremeOffscreenPixels = 250
const extremeMarginPixels = 1000
const extremeNegativeSpacingPixels = 8

type layoutVisibilityResult struct {
	uncertain, elementConcealed bool
	fontScaleUncertain          bool
	textLayout                  [3]bool
	textLayoutSet               [3]bool
	clipsX, clipsY              bool
	offsetX, offsetY            bool
}

func layoutVisibility(wins *[layoutProperties]layoutCandidate, style *Style, context evaluationContext, node *html.Node) layoutVisibilityResult {
	// Resolve only declarations that can complete a hiding pattern. Width is
	// extremely common in email, but is irrelevant unless overflow clips it;
	// likewise offsets are irrelevant on a statically positioned element.
	overflowXResult := resolveLayoutCandidate(&wins[overflowX-properties], context)
	overflowYResult := resolveLayoutCandidate(&wins[overflowY-properties], context)
	overflowXResult, overflowYResult = computedOverflow(overflowXResult, overflowYResult)
	clipX := overflowClips(overflowXResult)
	clipY := overflowClips(overflowYResult)
	clipsX := overflowDefinitelyClips(overflowXResult)
	clipsY := overflowDefinitelyClips(overflowYResult)
	if style[display].Known && style[display].Text == "contents" {
		// A display:contents element has no principal box to establish an
		// overflow clipping boundary.
		clipX, clipY, clipsX, clipsY = false, false, false, false
	}
	logicalClip := false
	for _, p := range [...]int{overflowInline, overflowBlock} {
		v := resolveLayoutCandidate(&wins[p-properties], context)
		logicalClip = logicalClip || overflowClips(v) || wins[p-properties].uncertainOrigin
	}
	if style[display].Known && style[display].Text == "contents" {
		logicalClip = false
	}
	// Without a writing-mode model either logical axis can clip a zero dimension.
	clipX, clipY = clipX || logicalClip, clipY || logicalClip
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
	// Until writing-mode/direction and logical/physical conflicts are resolved,
	// either logical dimension can be the clipped axis. Do not silently ignore it.
	if clipX || clipY {
		for _, p := range [...]int{inlineSize, blockSize, maxInlineSize, maxBlockSize} {
			v := resolveLayoutCandidate(&wins[p-properties], context)
			zeroBox = zeroBox || zeroLayoutCandidate(v) || wins[p-properties].uncertainOrigin
		}
	}
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
		wins[overflowX-properties].uncertainOrigin && zeroWidth ||
			wins[overflowY-properties].uncertainOrigin && zeroHeight ||
			(wins[width-properties].uncertainOrigin || wins[maxWidth-properties].uncertainOrigin) && clipX ||
			(wins[height-properties].uncertainOrigin || wins[maxHeight-properties].uncertainOrigin) && clipY ||
			isImage && (tinyWidth && wins[width-properties].uncertainOrigin || tinyHeight && wins[height-properties].uncertainOrigin)

	positioned := style[position].Known && (style[position].Text == "absolute" || style[position].Text == "fixed" || style[position].Text == "relative")
	positionedWithinClip := style[position].Known &&
		(style[position].Text == "relative" || style[position].Text == "absolute" ||
			style[position].Text == "fixed" || style[position].Text == "sticky")
	offsetProperties := [...]int{left, top, right, bottom}
	var offsetResults [4]layoutResult
	if positionedWithinClip {
		for i, property := range offsetProperties {
			offsetResults[i] = resolveLayoutCandidate(&wins[property-properties], context)
		}
	}
	extremeOffset := false
	if positioned {
		for _, p := range [...]int{insetInlineStart, insetInlineEnd, insetBlockStart, insetBlockEnd} {
			extremeOffset = extremeOffset || extremeOffsetMagnitude(resolveLayoutCandidate(&wins[p-properties], context)) || wins[p-properties].uncertainOrigin
		}
		for _, result := range offsetResults {
			extremeOffset = extremeOffset || extremeOffsetMagnitude(result)
		}
	}
	if positioned {
		for _, property := range [...]int{left, top, right, bottom} {
			uncertainOrigin = uncertainOrigin || wins[property-properties].uncertainOrigin
		}
	}

	var textLayout, textLayoutSet [3]bool
	for i, p := range [...]int{textIndent, letterSpacing, wordSpacing} {
		v := resolveLayoutCandidate(&wins[p-properties], context)
		textLayoutSet[i] = v.set && v.value.Text != "inherit" && v.value.Text != "unset"
		if i == 0 {
			textLayout[i] = extremeOffsetMagnitude(v)
		} else {
			textLayout[i] = extremeNegativeSpacing(v)
		}
		textLayout[i] = textLayout[i] || wins[p-properties].uncertainOrigin
	}
	zeroLineHeight := clipY && style[lineHeight].Text != "normal" &&
		(!style[lineHeight].Known || style[lineHeight].Number == 0)
	marginRoot := context.root
	if node != nil && node.Namespace == "" && node.Data == "html" {
		marginRoot = style
	}
	extremeMargin := false
	for _, property := range [...]int{marginTop, marginRight, marginBottom, marginLeft, marginInlineStart, marginInlineEnd, marginBlockStart, marginBlockEnd} {
		extremeMargin = extremeMargin || extremeOrUnresolvedMargin(resolveLayoutCandidate(&wins[property-properties], context), style, marginRoot)
		uncertainOrigin = uncertainOrigin || wins[property-properties].uncertainOrigin
	}
	uncertainOrigin = uncertainOrigin || wins[zoom-properties].uncertainOrigin
	zoomResult := resolveLayoutCandidate(&wins[zoom-properties], context)
	tinyZoom := nearZeroZoom(zoomResult)
	scaleUncertain := zoomResult.set && (zoomResult.status != valueResolved || !zoomResult.value.Known || zoomResult.value.Number != 1)
	offsetX := positionedWithinClip && (nonzeroOffset(offsetResults[0]) || nonzeroOffset(offsetResults[2]))
	offsetY := positionedWithinClip && (nonzeroOffset(offsetResults[1]) || nonzeroOffset(offsetResults[3]))

	uncertain := uncertainOrigin || zeroBox || zeroLineHeight || positioned && extremeOffset || extremeMargin || tinyZoom
	return layoutVisibilityResult{
		textLayout: textLayout, textLayoutSet: textLayoutSet,
		uncertain: uncertain, elementConcealed: elementConcealed, fontScaleUncertain: scaleUncertain,
		clipsX: clipsX, clipsY: clipsY, offsetX: offsetX, offsetY: offsetY,
	}
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
	value, status := resolvedDeclaration(candidate.d, candidate.property, context, declarationResolution{
		uncertainOrigin:  candidate.uncertainOrigin,
		allowUnsupported: true,
	})
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
	return clippingOverflow(result.value.Text)
}

func overflowDefinitelyClips(result layoutResult) bool {
	return result.set && result.status == valueResolved && result.value.Known &&
		clippingOverflow(result.value.Text)
}

func nonzeroOffset(result layoutResult) bool {
	if !result.set || result.status == valueInvalid || result.value.Text == "auto" {
		return false
	}
	if result.status != valueResolved || !result.value.Known {
		return true
	}
	return result.value.Number != 0
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

func extremeOrUnresolvedMargin(result layoutResult, style, root *Style) bool {
	// Margin em units refer to this element's computed font, not its parent's.
	// Compare numerically: no formatted pixel string or new allocation is needed.
	if result.set && result.status == valueUnsupported {
		_, unit, found := splitLength(result.value.Text)
		if found && (unit.suffix == "em" || unit.suffix == "rem" || unit.suffix == "ex") {
			font := style[fontSize]
			if unit.suffix == "rem" {
				font = root[fontSize]
			}
			if font.Known {
				pixels := result.value.Number * font.Number
				if unit.suffix == "ex" {
					// Email policy: allow ordinary font metrics up to 2em per ex.
					// This is a generous heuristic, not a universal CSS bound.
					pixels *= 2
				}
				return math.IsNaN(pixels) || math.IsInf(pixels, 0) || math.Abs(pixels) >= extremeMarginPixels
			}
		}
	}
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

func clippingOverflow(value string) bool {
	return value == "hidden" || value == "clip" || value == "auto" || value == "scroll"
}

// visible/clip compute to auto/hidden when the opposite axis establishes a
// scroll container. Include the implicit initial visible value.
func computedOverflow(x, y layoutResult) (layoutResult, layoutResult) {
	compute := func(own, other layoutResult) layoutResult {
		if !other.set || other.status != valueResolved || !other.value.Known {
			return own
		}
		v := other.value.Text
		if v == "visible" || v == "clip" {
			return own
		}
		if !own.set || own.status == valueResolved && own.value.Known && own.value.Text == "visible" {
			return layoutResult{set: true, status: valueResolved, value: Value{Text: "auto", Known: true}}
		}
		if own.status == valueResolved && own.value.Known && own.value.Text == "clip" {
			own.value.Text = "hidden"
		}
		return own
	}
	return compute(x, y), compute(y, x)
}
