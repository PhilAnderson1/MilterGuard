package htmlextract

import (
	"math"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"
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
func backgroundDeclarations(value string, important bool, order int) []declaration {
	colourValue, image := "transparent", "none"
	unsupported := false
	switch value {
	case "inherit", "initial", "unset", "revert", "revert-layer":
		colourValue = value
		image = value
	default:
		// Tokenize to remove a standalone none, preserving spaces inside rgb().
		lexer := css.NewLexer(parse.NewInputString(value))
		depth := 0
		haveColour := false
		haveNone := false
		var b strings.Builder
		for {
			tt, data := lexer.Next()
			if tt == css.ErrorToken {
				break
			}
			s := string(data)
			if tt == css.FunctionToken {
				depth++
			}
			if s == ")" {
				depth--
			}
			if depth == 0 && tt == css.IdentToken && s == "none" {
				if haveNone {
					unsupported = true
				}
				haveNone = true
				continue
			}
			b.Write(data)
		}
		token := strings.TrimSpace(b.String())
		if token != "" {
			haveColour = true
			colourValue = token
			_, status := readColour(token)
			if token == "currentcolor" {
				status = 1
			}
			// An image-only background shorthand resets background-color to
			// transparent. Retain that known fallback while leaving the image
			// itself unresolved; this permits a useful baseline contrast check.
			if backgroundImageSyntax(token) {
				colourValue = "transparent"
				status = 1
				image = token
				unsupported = true
			}
			if status == 0 && !strings.ContainsAny(token, " /,") && !strings.Contains(token, "(") {
				return nil
			}
			unsupported = unsupported || status != 1
		}
		if !haveColour && !haveNone {
			return nil
		}
		if unsupported && !backgroundImageSyntax(token) {
			colourValue = value
			image = value
		}
	}
	colourUnsupported, imageUnsupported := unsupported, unsupported
	if backgroundImageSyntax(value) {
		colourUnsupported = false
		imageUnsupported = true
	}
	return []declaration{{prop: background, value: colourValue, important: important, order: order, unsupported: colourUnsupported}, {prop: backgroundImage, value: image, important: important, order: order, unsupported: imageUnsupported}}
}

func backgroundImageSyntax(value string) bool {
	value = strings.ToLower(value)
	return strings.Contains(value, "url(") || strings.Contains(value, "gradient(") || strings.Contains(value, "image-set(") || strings.Contains(value, "cross-fade(")
}

// Presentational hints precede all author rules, with specificity zero. Full
// HTML legacy colour-error recovery is deliberately not guessed: unfamiliar
// legacy spellings are unresolved, and cannot prove colour concealment.
func legacyDeclarations(n *html.Node) []declaration {
	var result []declaration
	if hasAttr(n, "hidden") && strings.EqualFold(strings.TrimSpace(attr(n, "hidden")), "until-found") {
		// Hidden-until-found retains a generated box but does not paint its
		// contents. Model the browser's presentational content-visibility hint
		// separately from display so display:block cannot reveal the text.
		result = append(result, declaration{prop: contentVisibility, value: "hidden", order: -2})
	} else if hasAttr(n, "hidden") {
		// The hidden presentational default participates below author CSS, so an
		// explicit author display declaration can restore the element.
		result = append(result, declaration{prop: display, value: "none", order: -2})
	}
	add := func(prop int, value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || value == "transparent" {
			return
		}
		if len(value) == 6 && !strings.HasPrefix(value, "#") {
			if _, status := readColour("#" + value); status == 1 {
				value = "#" + value
			}
		}
		_, status := readColour(value)
		result = append(result, declaration{prop: prop, value: value, order: -1, unsupported: status != 1})
	}
	if n.Namespace != "" {
		return nil
	}
	switch n.Data {
	case "body", "table", "tr", "td", "th":
		add(background, attr(n, "bgcolor"))
	}
	if n.Data == "font" {
		add(color, attr(n, "color"))
	}
	// Legacy tiled background images remain unknown; author CSS can override.
	switch n.Data {
	case "body", "table", "td", "th":
		if v := attr(n, "background"); v != "" {
			result = append(result, declaration{prop: backgroundImage, value: "legacy-image:" + v, order: -1, unsupported: true})
		}
	}
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
}

func layer(s Style) paintLayer {
	known := s[display].Known && s[display].Text != "contents" && (s[clip].Text == "auto" || s[position].Text == "static") && s[clipPath].Text == "none"
	// Positioning does not alter the base glyph/background pixels used by this
	// contrast test. Text shadows can only add painted pixels, so they matter
	// when the base result would otherwise look concealed, not when it already
	// has clear contrast.
	for _, p := range []int{filter, blend, backdropFilter, backgroundBlend, maskImage, backgroundClip, textFill, transform, textStroke} {
		known = known && s[p].Known
	}
	return paintLayer{
		background:       s[background].RGBA,
		backgroundKnown:  s[background].Known,
		imageKnown:       s[backgroundImage].Known,
		opacity:          s[opacity].Number,
		opacityKnown:     s[opacity].Known,
		compositionKnown: known,
		enhancementKnown: s[position].Known && s[position].Text == "static" && s[textShadow].Known,
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
func evaluateColour(foreground Value, layers []paintLayer) colourResult {
	if !foreground.Known {
		return colourResult{uncertainty: "unresolved foreground"}
	}
	ink, ground := foreground.RGBA, RGBA{}
	uncertainEnhancement := false
	for i := len(layers) - 1; i >= 0; i-- {
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
		// and gradients are not fetched or sampled, but they do not make clearly
		// contrasting fallback text categorically uncertain. They remain
		// relevant when the fallback would otherwise prove concealment.
		if (!p.backgroundKnown || !p.imageKnown) && (ink.A < 1 || ground.A < 1) {
			if p.backgroundKnown && !p.imageKnown {
				uncertainEnhancement = true
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
	if uncertainEnhancement && colourConcealed(distance) {
		return colourResult{uncertainty: "unsupported image or composition effect"}
	}
	return colourResult{foreground: ink, background: ground, distance: distance, known: true}
}
