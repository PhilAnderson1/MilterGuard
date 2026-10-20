package htmlextract

import (
	"math"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// RGBA is unassociated, encoded sRGB with all channels in [0,1]. Source-over
// composition uses encoded sRGB; only the final distance converts to linear RGB.
type RGBA struct {
	R float64 `json:"r"`
	G float64 `json:"g"`
	B float64 `json:"b"`
	A float64 `json:"a"`
}

const colourThreshold = .005

// backgroundDeclarations supports colour-only/none shorthand (optionally both),
// plus CSS-wide keywords. It resets image as well as colour. Other syntax wins
// as unresolved for both components; a later colour alone cannot reset an image.
func backgroundDeclarations(value string, important bool, order int, budget *cpuGuard) []declaration {
	tokens, status := lexValue(value, budget)
	return backgroundDeclarationsTokens(value, tokens, status, important, order, budget)
}

func backgroundDeclarationsTokens(value string, tokens []valueToken, tokenStatus valueStatus, important bool, order int, budget *cpuGuard) []declaration {
	colourValue, image, clipValue := "transparent", "none", "border-box"
	unsupported := false
	imageColourStatus := valueResolved
	switch value {
	case "inherit", "initial", "unset", "revert", "revert-layer":
		colourValue = value
		image = value
		clipValue = value
	default:
		if tokenStatus != valueResolved {
			return declarationList(budget, declaration{prop: background, value: value, important: important, order: order, unsupported: true}, declaration{prop: backgroundImage, value: value, important: important, order: order, unsupported: true}, declaration{prop: backgroundClip, value: value, important: important, order: order, unsupported: true})
		}
		// Tokenize to remove a standalone none, preserving spaces inside rgb().
		var stack []css.TokenType
		haveColour := false
		haveNone := false
		var b strings.Builder
		for _, valueToken := range tokens {
			budget.check()

			tt, s := valueToken.kind, asciiLowerWithBudget(valueToken.raw, budget)
			if isClosingToken(tt) && len(stack) == 0 {
				return nil
			}
			stack, _ = advanceDelimiters(stack, tt, budget)
			if len(stack) == 0 && tt == css.IdentToken && s == "none" {
				if haveNone {
					unsupported = true
				}
				haveNone = true
				continue
			}

			writeBudgetedString(&b, s, budget)
		}
		token := trimCSSWhitespace(b.String())
		if token != "" {
			haveColour = true
			colourValue = token
			_, status := readColourWithBudget(token, budget)
			if token == "currentcolor" {
				status = valueResolved
			}
			if backgroundImageSyntaxWithBudget(token, budget) {
				// Images paint over the final layer's explicit colour. Preserve
				// that fallback rather than assuming every image shorthand resets
				// the colour to transparent.
				var valid bool
				colourValue, status, valid = backgroundFallbackColourTokens(tokens, budget)
				if !valid {
					return nil
				}
				imageColourStatus = status
				image = token
				unsupported = true
			}
			if status == valueInvalid && !strings.ContainsAny(token, " /,") && !strings.Contains(token, "(") {
				return nil
			}
			unsupported = unsupported || status != valueResolved
		}
		if !haveColour && !haveNone {
			return nil
		}
		if unsupported && !backgroundImageSyntaxWithBudget(token, budget) {
			colourValue = value
			image = value
		}
	}
	colourUnsupported, imageUnsupported := unsupported, unsupported
	if backgroundImageSyntaxWithBudget(value, budget) {
		colourUnsupported = imageColourStatus != valueResolved
		imageUnsupported = true
	}
	return declarationList(budget, declaration{prop: background, value: colourValue, important: important, order: order, unsupported: colourUnsupported}, declaration{prop: backgroundImage, value: image, important: important, order: order, unsupported: imageUnsupported}, declaration{prop: backgroundClip, value: clipValue, important: important, order: order, unsupported: unsupported && !simpleGradientBackground(value, budget)})
}

func backgroundFallbackColourTokens(tokens []valueToken, budget *cpuGuard) (string, valueStatus, bool) {
	finalStart := 0
	var stack []css.TokenType
	for i, token := range tokens {
		budget.check()

		if token.kind == css.CommaToken && len(stack) == 0 {
			finalStart = i + 1
		}
		stack, _ = advanceDelimiters(stack, token.kind, budget)
	}
	// A colour in any non-final layer makes the shorthand invalid.
	if finalStart > 0 {

		if _, _, count := backgroundLayerColour(tokens[:finalStart-1], budget); count != 0 {
			return "", valueInvalid, false
		}

	}
	colour, colourStatus, count := backgroundLayerColour(tokens[finalStart:], budget)
	if count > 1 {
		return "", valueInvalid, false
	}
	if count == 0 {
		return "transparent", valueResolved, true
	}
	return colour, colourStatus, true
}

func backgroundLayerColour(tokens []valueToken, budget *cpuGuard) (string, valueStatus, int) {
	var colour string
	colourStatus, count := valueInvalid, 0
	for i := 0; i < len(tokens); i++ {
		budget.check()

		token := tokens[i]
		candidate := ""
		switch token.kind {
		case css.FunctionToken:
			end := closing(tokens, i, budget)
			name := asciiLowerWithBudget(cssUnescapeWithBudget(strings.TrimSuffix(token.raw, "("), budget), budget)
			if isColourFunction(name) {
				last := end + 1
				if last > len(tokens) {
					last = len(tokens)
				}
				candidate = asciiLowerWithBudget(tokenTextWithBudget(tokens[i:last], budget), budget)
			}
			i = end
		case css.IdentToken, css.HashToken:
			candidate = asciiLowerWithBudget(cssUnescapeWithBudget(token.raw, budget), budget)
		}
		if candidate == "" {
			continue
		}
		_, candidateStatus := readColourWithBudget(candidate, budget)
		if candidate == "currentcolor" {
			candidateStatus = valueResolved
		}
		if candidateStatus == valueInvalid {
			continue
		}
		colour, colourStatus = candidate, candidateStatus
		count++
	}
	return colour, colourStatus, count
}

func isColourFunction(name string) bool {
	switch name {
	case "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch", "color", "color-mix", "device-cmyk", "light-dark":
		return true
	}
	return false
}

func countUnsupportedColourFunctions(tokens []valueToken) int {
	return countUnsupportedColourFunctionsWithBudget(tokens, nil)
}
func countUnsupportedColourFunctionsWithBudget(tokens []valueToken, budget *cpuGuard) int {
	count := 0
	for _, token := range tokens {
		budget.check()

		if token.kind == css.FunctionToken && isUnsupportedColourFunctionWithBudget(token.raw, budget) {
			count++
		}
	}
	return count
}

func isUnsupportedColourFunction(raw string) bool {
	return isUnsupportedColourFunctionWithBudget(raw, nil)
}
func isUnsupportedColourFunctionWithBudget(raw string, budget *cpuGuard) bool {
	name := asciiLowerWithBudget(cssUnescapeWithBudget(strings.TrimSuffix(raw, "("), budget), budget)
	switch name {
	case "lab", "lch", "oklab", "oklch", "color", "color-mix", "device-cmyk", "light-dark":
		return true
	}
	return false
}

func backgroundImageSyntax(value string) bool { return backgroundImageSyntaxWithBudget(value, nil) }
func backgroundImageSyntaxWithBudget(value string, budget *cpuGuard) bool {
	return containsASCIIFoldWithBudget(value, "url(", budget) || containsASCIIFoldWithBudget(value, "gradient(", budget) || containsASCIIFoldWithBudget(value, "image-set(", budget) || containsASCIIFoldWithBudget(value, "cross-fade(", budget)
}

func legacyDimension(value string) (string, bool) { return legacyDimensionWithBudget(value, nil) }
func legacyDimensionWithBudget(value string, budget *cpuGuard) (string, bool) {
	value = strings.TrimSpace(value)
	percentage := strings.HasSuffix(value, "%")
	if percentage {
		value = strings.TrimSuffix(value, "%")
	}
	if value == "" {
		return "", false
	}
	for i := range value {
		if i%stringWorkChunk == 0 && len(value) > stringWorkChunk {
			budget.checkpoint()
		}

		if value[i] < '0' || value[i] > '9' {
			return "", false
		}
	}
	if percentage {
		return concatString(value, "%", budget), true
	}
	return concatString(value, "px", budget), true
}

// Presentational hints precede all author rules, with specificity zero. Full
// HTML legacy colour-error recovery is deliberately not guessed: unfamiliar
// legacy spellings are unresolved, and cannot prove colour concealment.
func legacyDeclarations(n *html.Node) []declaration { return legacyDeclarationsWithBudget(n, nil) }
func legacyDeclarationsWithBudget(n *html.Node, budget *cpuGuard) []declaration {
	return legacyDeclarationsWithBody(n, nil, budget)
}

func legacyDeclarationsWithBody(n, body *html.Node, budget *cpuGuard) []declaration {
	if n.Namespace != "" {
		return nil
	}
	// At most hidden, background colour, two dimensions and background image.
	var hints [6]declaration
	count := 0
	addDeclaration := func(d declaration) { hints[count] = d; count++ }
	if hasAttr(n, "hidden") && equalASCIIFold(strings.TrimSpace(attr(n, "hidden")), "until-found") {
		// Hidden-until-found retains a generated box but does not paint its
		// contents. Model the browser's presentational content-visibility hint
		// separately from display so display:block cannot reveal the text.
		addDeclaration(declaration{prop: contentVisibility, value: "hidden", order: -2, unsupported: true})
	} else if hasAttr(n, "hidden") {
		// The hidden presentational default participates below author CSS, so an
		// explicit author display declaration can restore the element.
		addDeclaration(declaration{prop: display, value: "none", order: -2, unsupported: true})
	}

	add := func(prop int, value string) {
		value = asciiLowerWithBudget(strings.TrimSpace(value), budget)
		if value == "" || value == "transparent" {
			return
		}
		if len(value) == 6 && !strings.HasPrefix(value, "#") {
			hex := concatString("#", value, budget)

			if _, status := readColourWithBudget(hex, budget); status == valueResolved {
				value = hex
			}

		}
		_, status := readColourWithBudget(value, budget)
		addDeclaration(declaration{prop: prop, value: value, order: -1, unsupported: status != valueResolved})
	}
	switch n.Data {
	case "body", "table", "tr", "td", "th":
		add(background, attr(n, "bgcolor"))
	}
	if n.Data == "body" {
		add(color, attr(n, "text"))
	}
	if (n.Data == "a" || n.Data == "area") && hasAttr(n, "href") && body != nil {
		link, visited := attr(body, "link"), attr(body, "vlink")
		if link != "" || visited != "" {
			if equalASCIIFold(link, visited) {
				add(color, link)
			} else {
				addDeclaration(declaration{prop: color, value: "legacy-link-colours", order: -1, unsupported: true})
			}
		}
	}
	if n.Data == "font" {
		add(color, attr(n, "color"))
	}
	addDimension := func(prop int, name string) {

		if value, ok := legacyDimensionWithBudget(attr(n, name), budget); ok {
			addDeclaration(declaration{prop: prop, value: value, order: -1})
		}

	}
	// These obsolete attributes remain common in table-based email and are
	// interpreted as low-priority presentational hints. Retaining them lets the
	// layout checks recognize small clipping boxes while author CSS can still
	// override them through the ordinary cascade.
	switch n.Data {
	case "table", "td", "th", "img":
		addDimension(width, "width")
		addDimension(height, "height")
	}
	// Legacy tiled background images remain unknown; author CSS can override.
	switch n.Data {
	case "body", "table", "td", "th":
		{
			v := attr(n, "background")
			if v != "" {
				addDeclaration(declaration{prop: backgroundImage, value: concatString("legacy-image:", v, budget), order: -1, unsupported: true})
			}
		}
	}
	if count == 0 {
		return nil
	}
	result := resourceguard.MakeSlice[declaration](budget.allocationMemory(), count, count)

	copy(result, hints[:count])
	return result
}

// Source-over, unassociated channels. Group opacity scales the composite alpha
// AFTER child content and the group's own background have been combined.
func over(src, dst RGBA) RGBA {
	a := src.A + dst.A*(1-src.A)
	if a == 0 {
		return RGBA{}
	}
	return RGBA{(src.R*src.A + dst.R*dst.A*(1-src.A)) / a, (src.G*src.A + dst.G*dst.A*(1-src.A)) / a, (src.B*src.A + dst.B*dst.A*(1-src.A)) / a, a}
}
func linearChannel(v float64) float64 {
	if v <= .04045 {
		return v / 12.92
	}
	return math.Pow((v+.055)/1.055, 2.4)
}

// Oklab D65, updated 2021-01-25 linear-sRGB matrices from Björn Ottosson's
// public-domain reference: https://bottosson.github.io/posts/oklab/ .
func oklab(c RGBA) [3]float64 {
	r, g, b := linearChannel(c.R), linearChannel(c.G), linearChannel(c.B)
	l := math.Cbrt(.4122214708*r + .5363325363*g + .0514459929*b)
	m := math.Cbrt(.2119034982*r + .6806995451*g + .1073969566*b)
	s := math.Cbrt(.0883024619*r + .2817188376*g + .6299787005*b)
	return [3]float64{.2104542553*l + .7936177850*m - .0040720468*s, 1.9779984951*l - 2.4285922050*m + .4505937099*s, .0259040371*l + .7827717662*m - .8086757660*s}
}
func labDistance(a, b [3]float64) float64 {
	x, y, z := a[0]-b[0], a[1]-b[1], a[2]-b[2]
	return math.Sqrt(x*x + y*y + z*z)
}
func colourConcealed(distance float64) bool { return distance <= colourThreshold }

type paintLayer struct {
	background                     RGBA
	backgroundKnown, imageKnown    bool
	opacity                        float64
	opacityKnown, compositionKnown bool
	enhancementKnown               bool
	glyphKnown, shadowKnown        bool
	displayNone                    bool
}

// colourNeutral reports whether inserting this layer anywhere in the paint
// stack leaves evaluateColour's result unchanged. Unknown images,
// composition effects and enhancements are deliberately non-neutral because
// they can turn an otherwise usable or concealed result into uncertainty.
func (p paintLayer) colourNeutral() bool {
	return p.backgroundKnown && p.background.A == 0 && p.imageKnown &&
		p.opacityKnown && p.opacity == 1 && p.compositionKnown && p.enhancementKnown
}

// propagateHTMLBodyBackground applies the special HTML canvas rule. When the
// root has no background, the first body child's background is used on the
// canvas as though it belonged to the root, while the body's used background
// becomes transparent. Moving the paint between these groups matters when the
// root or body has opacity or another compositing effect.
func propagateHTMLBodyBackground(layers []paintLayer) {
	if len(layers) < 2 {
		return
	}
	root := &layers[len(layers)-2]
	body := &layers[len(layers)-1]
	if root.displayNone || body.displayNone || !root.backgroundKnown || root.background.A != 0 || !root.imageKnown {
		return
	}
	root.background = body.background
	root.backgroundKnown = body.backgroundKnown
	root.imageKnown = body.imageKnown
	body.background = RGBA{}
	body.backgroundKnown = true
	body.imageKnown = true
}

func layer(s *Style) paintLayer {
	return layerWithClipOverride(s, false)
}

func layerWithClipOverride(s *Style, ignoreClipPath bool) paintLayer {
	known := s[display].Known && s[display].Text != "contents" && (s[clip].Text == "auto" || s[position].Text == "static") && (ignoreClipPath || s[clipPath].Text == "none")
	// Positioning does not alter the base glyph/background pixels used by this
	// contrast test. Text shadows can only add painted pixels, so they matter
	// when the base result would otherwise look concealed, not when it already
	// has clear contrast.
	for _, p := range []int{filter, blend, backdropFilter, backgroundBlend, maskImage, backgroundClip, transform, scale, translate, rotate} {
		known = known && s[p].Known
	}
	return paintLayer{
		background:       s[background].RGBA,
		backgroundKnown:  s[background].Known,
		imageKnown:       s[backgroundImage].Known,
		opacity:          s[opacity].Number,
		opacityKnown:     s[opacity].Known,
		compositionKnown: known,
		enhancementKnown: s[position].Known && s[position].Text == "static",
		glyphKnown:       s[textFill].Known && s[textStroke].Known,
		shadowKnown:      s[textShadow].Known,
		displayNone:      s[display].Known && s[display].Text == "none",
	}
}

type colourResult struct {
	foreground, background RGBA
	distance               float64
	known                  bool
	uncertainty            string
}
type colourInspection struct {
	Foreground  *RGBA
	Background  *RGBA
	Distance    *float64
	Known       bool
	Concealed   bool
	Uncertainty string
}

func (c colourResult) inspection() colourInspection {
	out := colourInspection{Known: c.known, Uncertainty: c.uncertainty}
	if c.known {
		out.Foreground = &c.foreground
		out.Background = &c.background
		out.Distance = &c.distance
		out.Concealed = colourConcealed(c.distance)
	}
	return out
}

// Compute a solid fully covered glyph pixel and an otherwise identical pixel
// with no glyph. Paint groups are folded from inside to outside. An opaque white default
// canvas is supplied after known layers; unresolved layers remain unknown. No sibling/layout/image
// sampling, antialiasing, blending or filter model is implied.
func evaluateColour(foreground Value, layers []paintLayer, work *cpuGuard) colourResult {
	work.check()

	if !foreground.Known {
		return colourResult{uncertainty: "unresolved foreground"}
	}
	ink, ground := foreground.RGBA, RGBA{}
	uncertainEnhancement := false
	if len(layers) > 0 {
		owner := layers[len(layers)-1]
		if !owner.glyphKnown {
			return colourResult{uncertainty: "unsupported glyph effect"}
		}
		uncertainEnhancement = !owner.shadowKnown
	}
	unresolvedGroundImage := false
	for i := len(layers) - 1; i >= 0; i-- {
		work.check()

		p := layers[i]
		if !p.compositionKnown {
			return colourResult{uncertainty: "unsupported composition effect"}
		}
		if !p.enhancementKnown {
			uncertainEnhancement = true
		}
		if !p.opacityKnown {
			return colourResult{uncertainty: "unresolved group opacity"}
		}
		// Resolve the solid fallback independently from an image layer. Images
		// and gradients are not fetched or sampled. If one contributes beneath
		// the text, the fallback colour cannot establish either visibility or
		// concealment because the image paints over it.
		if (!p.backgroundKnown || !p.imageKnown) && (ink.A < 1 || ground.A < 1) {
			if p.backgroundKnown && !p.imageKnown {
				unresolvedGroundImage = true
			} else {
				return colourResult{uncertainty: "unresolved background or image"}
			}
		}
		if ink.A < 1 {
			ink = over(ink, p.background)
		}
		if ground.A < 1 {
			ground = over(ground, p.background)
		}
		ink.A *= p.opacity
		ground.A *= p.opacity
	}
	ink = over(ink, RGBA{1, 1, 1, 1})
	ground = over(ground, RGBA{1, 1, 1, 1})
	distance := labDistance(oklab(ink), oklab(ground))
	if unresolvedGroundImage {
		return colourResult{uncertainty: "unsupported background image"}
	}
	if uncertainEnhancement && colourConcealed(distance) {
		return colourResult{uncertainty: "unsupported image or composition effect"}
	}
	return colourResult{foreground: ink, background: ground, distance: distance, known: true}
}

// Recognise a deliberately small, valid image-only shorthand. Its unknown pixels
// do not make the default background-clip uncertain. Other grammar stays guarded.
func simpleGradientBackground(value string, budget *cpuGuard) bool {
	radial := strings.HasPrefix(value, "radial-gradient(")
	if !radial && !strings.HasPrefix(value, "linear-gradient(") {
		return false
	}
	_, body, _ := strings.Cut(value, "(")
	if !strings.HasSuffix(body, ")") {
		return false
	}
	body = body[:len(body)-1]
	stops := 0
	first := true
	for {
		budget.check()

		part, rest, more := strings.Cut(body, ",")
		part = trimCSSWhitespace(part)
		direction := false
		if first {
			if radial {
				direction = part == "circle" || part == "circle at center"
			} else {
				switch part {
				case "to right", "to left", "to top", "to bottom":
					direction = true
				}
				if strings.HasSuffix(part, "deg") {
					_, direction = numberWithBudget(part[:len(part)-3], budget)
				}
			}
		}
		if !direction {
			var scratch [3]string
			fields := splitCSSWhitespace(part, scratch[:])
			if len(fields) < 1 || len(fields) > 2 {
				return false
			}

			if _, status := readColourWithBudget(fields[0], budget); status != valueResolved {
				return false
			}

			if len(fields) == 2 {
				num, unit, found := splitLength(fields[1])
				if !found || unit.suffix != "%" && unit.suffix != "px" {
					return false
				}

				if _, ok := numberWithBudget(num, budget); !ok {
					return false
				}

			}
			stops++
		}
		first = false
		if !more {
			break
		}
		body = rest
	}
	return stops >= 2
}
