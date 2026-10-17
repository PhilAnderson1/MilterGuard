package htmlextract

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

var named = map[string]string{
	"aliceblue":            "#f0f8ff",
	"antiquewhite":         "#faebd7",
	"aqua":                 "#00ffff",
	"aquamarine":           "#7fffd4",
	"azure":                "#f0ffff",
	"beige":                "#f5f5dc",
	"bisque":               "#ffe4c4",
	"black":                "#000000",
	"blanchedalmond":       "#ffebcd",
	"blue":                 "#0000ff",
	"blueviolet":           "#8a2be2",
	"brown":                "#a52a2a",
	"burlywood":            "#deb887",
	"cadetblue":            "#5f9ea0",
	"chartreuse":           "#7fff00",
	"chocolate":            "#d2691e",
	"coral":                "#ff7f50",
	"cornflowerblue":       "#6495ed",
	"cornsilk":             "#fff8dc",
	"crimson":              "#dc143c",
	"cyan":                 "#00ffff",
	"darkblue":             "#00008b",
	"darkcyan":             "#008b8b",
	"darkgoldenrod":        "#b8860b",
	"darkgray":             "#a9a9a9",
	"darkgreen":            "#006400",
	"darkgrey":             "#a9a9a9",
	"darkkhaki":            "#bdb76b",
	"darkmagenta":          "#8b008b",
	"darkolivegreen":       "#556b2f",
	"darkorange":           "#ff8c00",
	"darkorchid":           "#9932cc",
	"darkred":              "#8b0000",
	"darksalmon":           "#e9967a",
	"darkseagreen":         "#8fbc8f",
	"darkslateblue":        "#483d8b",
	"darkslategray":        "#2f4f4f",
	"darkslategrey":        "#2f4f4f",
	"darkturquoise":        "#00ced1",
	"darkviolet":           "#9400d3",
	"deeppink":             "#ff1493",
	"deepskyblue":          "#00bfff",
	"dimgray":              "#696969",
	"dimgrey":              "#696969",
	"dodgerblue":           "#1e90ff",
	"firebrick":            "#b22222",
	"floralwhite":          "#fffaf0",
	"forestgreen":          "#228b22",
	"fuchsia":              "#ff00ff",
	"gainsboro":            "#dcdcdc",
	"ghostwhite":           "#f8f8ff",
	"gold":                 "#ffd700",
	"goldenrod":            "#daa520",
	"gray":                 "#808080",
	"green":                "#008000",
	"greenyellow":          "#adff2f",
	"grey":                 "#808080",
	"honeydew":             "#f0fff0",
	"hotpink":              "#ff69b4",
	"indianred":            "#cd5c5c",
	"indigo":               "#4b0082",
	"ivory":                "#fffff0",
	"khaki":                "#f0e68c",
	"lavender":             "#e6e6fa",
	"lavenderblush":        "#fff0f5",
	"lawngreen":            "#7cfc00",
	"lemonchiffon":         "#fffacd",
	"lightblue":            "#add8e6",
	"lightcoral":           "#f08080",
	"lightcyan":            "#e0ffff",
	"lightgoldenrodyellow": "#fafad2",
	"lightgray":            "#d3d3d3",
	"lightgreen":           "#90ee90",
	"lightgrey":            "#d3d3d3",
	"lightpink":            "#ffb6c1",
	"lightsalmon":          "#ffa07a",
	"lightseagreen":        "#20b2aa",
	"lightskyblue":         "#87cefa",
	"lightslategray":       "#778899",
	"lightslategrey":       "#778899",
	"lightsteelblue":       "#b0c4de",
	"lightyellow":          "#ffffe0",
	"lime":                 "#00ff00",
	"limegreen":            "#32cd32",
	"linen":                "#faf0e6",
	"magenta":              "#ff00ff",
	"maroon":               "#800000",
	"mediumaquamarine":     "#66cdaa",
	"mediumblue":           "#0000cd",
	"mediumorchid":         "#ba55d3",
	"mediumpurple":         "#9370db",
	"mediumseagreen":       "#3cb371",
	"mediumslateblue":      "#7b68ee",
	"mediumspringgreen":    "#00fa9a",
	"mediumturquoise":      "#48d1cc",
	"mediumvioletred":      "#c71585",
	"midnightblue":         "#191970",
	"mintcream":            "#f5fffa",
	"mistyrose":            "#ffe4e1",
	"moccasin":             "#ffe4b5",
	"navajowhite":          "#ffdead",
	"navy":                 "#000080",
	"oldlace":              "#fdf5e6",
	"olive":                "#808000",
	"olivedrab":            "#6b8e23",
	"orange":               "#ffa500",
	"orangered":            "#ff4500",
	"orchid":               "#da70d6",
	"palegoldenrod":        "#eee8aa",
	"palegreen":            "#98fb98",
	"paleturquoise":        "#afeeee",
	"palevioletred":        "#db7093",
	"papayawhip":           "#ffefd5",
	"peachpuff":            "#ffdab9",
	"peru":                 "#cd853f",
	"pink":                 "#ffc0cb",
	"plum":                 "#dda0dd",
	"powderblue":           "#b0e0e6",
	"purple":               "#800080",
	"rebeccapurple":        "#663399",
	"red":                  "#ff0000",
	"rosybrown":            "#bc8f8f",
	"royalblue":            "#4169e1",
	"saddlebrown":          "#8b4513",
	"salmon":               "#fa8072",
	"sandybrown":           "#f4a460",
	"seagreen":             "#2e8b57",
	"seashell":             "#fff5ee",
	"sienna":               "#a0522d",
	"silver":               "#c0c0c0",
	"skyblue":              "#87ceeb",
	"slateblue":            "#6a5acd",
	"slategray":            "#708090",
	"slategrey":            "#708090",
	"snow":                 "#fffafa",
	"springgreen":          "#00ff7f",
	"steelblue":            "#4682b4",
	"tan":                  "#d2b48c",
	"teal":                 "#008080",
	"thistle":              "#d8bfd8",
	"tomato":               "#ff6347",
	"turquoise":            "#40e0d0",
	"violet":               "#ee82ee",
	"wheat":                "#f5deb3",
	"white":                "#ffffff",
	"whitesmoke":           "#f5f5f5",
	"yellow":               "#ffff00",
	"yellowgreen":          "#9acd32",
}

var unsupportedColourNames = map[string]struct{}{
	"accentcolor":      {},
	"accentcolortext":  {},
	"activetext":       {},
	"buttonborder":     {},
	"buttonface":       {},
	"buttontext":       {},
	"canvas":           {},
	"canvastext":       {},
	"field":            {},
	"fieldtext":        {},
	"graytext":         {},
	"highlight":        {},
	"highlighttext":    {},
	"linktext":         {},
	"mark":             {},
	"marktext":         {},
	"selecteditem":     {},
	"selecteditemtext": {},
	"visitedtext":      {},
}

func readColour(s string) (RGBA, valueStatus) {
	if s == "transparent" {
		return RGBA{}, valueResolved
	}
	if v, ok := named[s]; ok {
		s = v
	}
	var c [4]float64
	c[3] = 1
	if strings.HasPrefix(s, "#") {
		h := s[1:]
		if len(h) != 3 && len(h) != 4 && len(h) != 6 && len(h) != 8 {
			return RGBA{}, valueInvalid
		}
		if len(h) <= 4 {
			var b strings.Builder
			for _, v := range h {
				b.WriteRune(v)
				b.WriteRune(v)
			}
			h = b.String()
		}
		for i := 0; i < len(h)/2; i++ {
			v, e := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
			if e != nil {
				return RGBA{}, valueInvalid
			}
			c[i] = float64(v)
			if i == 3 {
				c[i] /= 255
			}
		}
	} else if open := strings.IndexByte(s, '('); open > 0 && strings.HasSuffix(s, ")") {
		name := s[:open]
		body := s[open+1 : len(s)-1]
		switch name {
		case "rgb", "rgba":
			return finiteColourResult(parseRGBFunction(body))
		case "hsl", "hsla":
			return finiteColourResult(parseHSLFunction(body))
		case "hwb":
			return finiteColourResult(parseHWBFunction(body))
		default:
			return RGBA{}, valueUnsupported
		}
	} else {
		if strings.Contains(s, "(") {
			return RGBA{}, valueUnsupported
		}
		// Named colours outside the documented basic set remain unresolved.
		if _, ok := unsupportedColourNames[s]; ok {
			return RGBA{}, valueUnsupported
		}
		return RGBA{}, valueInvalid
	}
	return RGBA{c[0] / 255, c[1] / 255, c[2] / 255, c[3]}, valueResolved
}

func finiteColourResult(c RGBA, status valueStatus) (RGBA, valueStatus) {
	if status == valueResolved && (!finite(c.R) || !finite(c.G) || !finite(c.B) || !finite(c.A)) {
		return RGBA{}, valueUnsupported
	}
	return c, status
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func colourFunctionParts(body string) (channels []string, alpha string, legacy bool, status valueStatus) {
	if strings.Contains(body, "(") || strings.Contains(body, "from") {
		return nil, "", false, valueUnsupported
	}
	if strings.Contains(body, ",") {
		if strings.Contains(body, "/") {
			return nil, "", true, valueInvalid
		}
		parts := strings.Split(body, ",")
		if len(parts) != 3 && len(parts) != 4 {
			return nil, "", true, valueInvalid
		}
		for i := range parts {
			parts[i] = trimCSSWhitespace(parts[i])
			if parts[i] == "" {
				return nil, "", true, valueInvalid
			}
		}
		if len(parts) == 4 {
			alpha = parts[3]
		}
		return parts[:3], alpha, true, valueResolved
	}
	if strings.Count(body, "/") > 1 {
		return nil, "", false, valueInvalid
	}
	parts := strings.SplitN(body, "/", 2)
	channels = splitCSSWhitespace(parts[0])
	if len(channels) != 3 {
		return nil, "", false, valueInvalid
	}
	if len(parts) == 2 {
		alphaParts := splitCSSWhitespace(parts[1])
		if len(alphaParts) != 1 {
			return nil, "", false, valueInvalid
		}
		alpha = alphaParts[0]
	}
	return channels, alpha, false, valueResolved
}

func colourNumber(component string, numberScale, hi float64) (float64, valueStatus) {
	if component == "none" {
		return 0, valueResolved
	}
	if strings.Contains(component, "(") {
		return 0, valueUnsupported
	}
	percentage := strings.HasSuffix(component, "%")
	if percentage {
		component = strings.TrimSuffix(component, "%")
	}
	n, ok := colourComponentNumber(component)
	if !ok {
		return 0, valueInvalid
	}
	if percentage {
		return clamp(n/100*hi, hi), valueResolved
	}
	return clamp(n*numberScale, hi), valueResolved
}

// colourComponentNumber accepts the same syntax as number, but retains
// representational overflow for the caller to clamp to the colour channel's
// finite range. The general number parser remains finite-only because layout
// and arithmetic cannot safely give infinity a contextual meaning.
func colourComponentNumber(component string) (float64, bool) {
	if !validCSSNumber(component) {
		return 0, false
	}
	value, _ := strconv.ParseFloat(component, 64)
	return value, !math.IsNaN(value)
}

func parseAlpha(component string) (float64, valueStatus) {
	if component == "" {
		return 1, valueResolved
	}
	return colourNumber(component, 1, 1)
}

func parseRGBFunction(body string) (RGBA, valueStatus) {
	channels, alphaText, legacy, status := colourFunctionParts(body)
	if status != valueResolved {
		return RGBA{}, status
	}
	if legacy {
		if legacyColourHasMissingComponent(channels, alphaText) {
			return RGBA{}, valueInvalid
		}
		percent := strings.HasSuffix(channels[0], "%")
		for _, channel := range channels[1:] {
			if strings.HasSuffix(channel, "%") != percent {
				return RGBA{}, valueInvalid
			}
		}
	}
	var c [3]float64
	for i, channel := range channels {
		c[i], status = colourNumber(channel, 1, 255)
		if status != valueResolved {
			return RGBA{}, status
		}
	}
	a, status := parseAlpha(alphaText)
	if status != valueResolved {
		return RGBA{}, status
	}
	return RGBA{c[0] / 255, c[1] / 255, c[2] / 255, a}, valueResolved
}

func parseHue(component string) (float64, valueStatus) {
	if component == "none" {
		return 0, valueResolved
	}
	if strings.Contains(component, "(") {
		return 0, valueUnsupported
	}
	factor := 1.0
	switch {
	case strings.HasSuffix(component, "turn"):
		factor = 360
		component = strings.TrimSuffix(component, "turn")
	case strings.HasSuffix(component, "grad"):
		factor = .9
		component = strings.TrimSuffix(component, "grad")
	case strings.HasSuffix(component, "rad"):
		factor = 180 / math.Pi
		component = strings.TrimSuffix(component, "rad")
	case strings.HasSuffix(component, "deg"):
		component = strings.TrimSuffix(component, "deg")
	}
	n, ok := number(component)
	if !ok {
		return 0, valueInvalid
	}
	n = math.Mod(n*factor, 360)
	if !finite(n) {
		// The source number may be finite while conversion to degrees
		// overflows. Clients need not agree on such extreme values, so retain
		// uncertainty rather than accepting a known colour containing NaN.
		return 0, valueUnsupported
	}
	if n < 0 {
		n += 360
	}
	return n, valueResolved
}

func parseHSLFunction(body string) (RGBA, valueStatus) {
	channels, alphaText, legacy, status := colourFunctionParts(body)
	if status != valueResolved {
		return RGBA{}, status
	}
	if legacy && legacyColourHasMissingComponent(channels, alphaText) {
		return RGBA{}, valueInvalid
	}
	h, status := parseHue(channels[0])
	if status != valueResolved {
		return RGBA{}, status
	}
	if legacy && (!strings.HasSuffix(channels[1], "%") || !strings.HasSuffix(channels[2], "%")) {
		return RGBA{}, valueInvalid
	}
	s, status := colourNumber(channels[1], .01, 1)
	if status != valueResolved {
		return RGBA{}, status
	}
	l, status := colourNumber(channels[2], .01, 1)
	if status != valueResolved {
		return RGBA{}, status
	}
	a, status := parseAlpha(alphaText)
	if status != valueResolved {
		return RGBA{}, status
	}

	chroma := (1 - math.Abs(2*l-1)) * s
	x := chroma * (1 - math.Abs(math.Mod(h/60, 2)-1))
	var r, g, b float64
	switch int(h / 60) {
	case 0:
		r, g = chroma, x
	case 1:
		r, g = x, chroma
	case 2:
		g, b = chroma, x
	case 3:
		g, b = x, chroma
	case 4:
		r, b = x, chroma
	default:
		r, b = chroma, x
	}
	m := l - chroma/2
	return RGBA{r + m, g + m, b + m, a}, valueResolved
}

func legacyColourHasMissingComponent(channels []string, alpha string) bool {
	if alpha == "none" {
		return true
	}
	for _, channel := range channels {
		if channel == "none" {
			return true
		}
	}
	return false
}

func parseHWBFunction(body string) (RGBA, valueStatus) {
	channels, alphaText, legacy, status := colourFunctionParts(body)
	if status != valueResolved {
		return RGBA{}, status
	}
	// hwb() has only the modern, whitespace-separated form.
	if legacy {
		return RGBA{}, valueInvalid
	}
	h, status := parseHue(channels[0])
	if status != valueResolved {
		return RGBA{}, status
	}
	for _, component := range channels[1:] {
		if component != "none" && !strings.HasSuffix(component, "%") {
			return RGBA{}, valueInvalid
		}
	}
	w, status := colourNumber(channels[1], .01, 1)
	if status != valueResolved {
		return RGBA{}, status
	}
	bk, status := colourNumber(channels[2], .01, 1)
	if status != valueResolved {
		return RGBA{}, status
	}
	a, status := parseAlpha(alphaText)
	if status != valueResolved {
		return RGBA{}, status
	}
	if w+bk >= 1 {
		gray := w / (w + bk)
		return RGBA{gray, gray, gray, a}, valueResolved
	}

	chroma := 1.0
	x := 1 - math.Abs(math.Mod(h/60, 2)-1)
	var r, g, b float64
	switch int(h / 60) {
	case 0:
		r, g = chroma, x
	case 1:
		r, g = x, chroma
	case 2:
		g, b = chroma, x
	case 3:
		g, b = x, chroma
	case 4:
		r, b = x, chroma
	default:
		r, b = chroma, x
	}
	factor := 1 - w - bk
	return RGBA{r*factor + w, g*factor + w, b*factor + w, a}, valueResolved
}

func colourString(c RGBA) string {
	return fmt.Sprintf("rgba(%g,%g,%g,%g)", c.R*255, c.G*255, c.B*255, c.A)
}
