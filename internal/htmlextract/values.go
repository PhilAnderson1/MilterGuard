package htmlextract

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

type Value struct {
	Text   string  `json:"value"`
	Number float64 `json:"number"`
	Known  bool    `json:"known"`
	RGBA   RGBA    `json:"-"`
}
type Style [properties]Value

var initialStyle = makeInitialStyle()

func makeInitialStyle() Style {
	var s Style
	s[display] = Value{Text: "inline", Known: true}
	s[visibility] = Value{Text: "visible", Known: true}
	s[contentVisibility] = Value{Text: "visible", Known: true}
	s[msoHide] = Value{Text: "none", Known: true}
	s[opacity] = Value{Text: "1", Number: 1, Known: true}
	s[fontSize] = Value{Text: "16px", Number: 16, Known: true}
	s[color] = Value{Text: "rgba(0,0,0,1)", Known: true, RGBA: RGBA{A: 1}}
	s[background] = Value{Text: "rgba(0,0,0,0)", Known: true}
	for _, p := range []int{backgroundImage, filter, backdropFilter, maskImage, textShadow, transform} {
		s[p] = Value{Text: "none", Known: true}
	}
	for _, p := range []int{blend, backgroundBlend} {
		s[p] = Value{Text: "normal", Known: true}
	}
	s[backgroundClip] = Value{Text: "border-box", Known: true}
	s[textFill] = Value{Text: "currentcolor", Known: true}
	s[position] = Value{Text: "static", Known: true}
	s[textStroke] = Value{Text: "0", Known: true}
	s[clip] = Value{Text: "auto", Known: true}
	s[clipPath] = Value{Text: "none", Known: true}
	return s
}

func initial() Style      { return initialStyle }
func inherits(p int) bool { return p == visibility || p == fontSize || p == color }

// number parses the decimal syntax accepted by CSS <number>. strconv.ParseFloat
// alone is too permissive here: it also accepts Go spellings such as hexadecimal
// floats and underscore separators that a browser does not treat as CSS numbers.
func number(s string) (float64, bool) {
	if !validCSSNumber(s) {
		return 0, false
	}
	v, e := strconv.ParseFloat(s, 64)
	return v, e == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}

func validCSSNumber(s string) bool {
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	integerStart := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	hasInteger := i > integerStart
	if i < len(s) && s[i] == '.' {
		i++
		fractionStart := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		// A decimal point is part of a CSS number only when followed by a
		// digit. This deliberately rejects Go's accepted "1." spelling.
		if i == fractionStart {
			return false
		}
	} else if !hasInteger {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		exponentStart := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == exponentStart {
			return false
		}
	}
	return i == len(s)
}

func clamp(v, hi float64) float64 { return math.Min(hi, math.Max(0, v)) }

type valueStatus uint8

const (
	valueInvalid valueStatus = iota
	valueResolved
	valueUnsupported
)

func resolve(p int, s string, parent, root *Style) (Value, valueStatus) {
	s = normalizeCSSKeyword(s)
	if p >= properties {
		return resolveLayoutProperty(p, s)
	}
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		return Value{}, valueInvalid
	}
	def := initialStyle[p]
	switch s {
	case "inherit":
		return parent[p], valueResolved
	case "initial":
		return def, valueResolved
	case "unset":
		if inherits(p) {
			return parent[p], valueResolved
		}
		return def, valueResolved
	case "":
		return Value{}, valueInvalid
	}
	if strings.Contains(s, "var(") || strings.Contains(s, "calc(") || s == "revert" || s == "revert-layer" {
		return Value{Text: s}, valueUnsupported
	}
	if p == clip || p == clipPath {
		return resolveClip(p, s)
	}
	if p != color && p != background && strings.Contains(s, "(") {
		return Value{Text: s}, valueUnsupported
	}
	switch p {
	case display:
		switch s {
		case "none", "inline", "block", "inline-block", "list-item", "table", "table-row", "table-cell", "table-row-group", "table-header-group", "table-footer-group", "table-column", "table-column-group", "table-caption", "flex", "inline-flex", "grid", "inline-grid", "contents", "flow-root":
			return Value{Text: s, Known: true}, valueResolved
		}
		if strings.ContainsAny(s, " ()") || strings.Contains(" run-in ruby ruby-base ruby-text ruby-base-container ruby-text-container math ", " "+s+" ") {
			return Value{Text: s}, valueUnsupported
		}
		return Value{}, valueInvalid
	case visibility:
		if s == "visible" || s == "hidden" || s == "collapse" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{}, valueInvalid
	case contentVisibility:
		if s == "visible" || s == "hidden" || s == "auto" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{}, valueInvalid
	case msoHide:
		if s == "all" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{}, valueInvalid
	case opacity:
		scale := 1.0
		if strings.HasSuffix(s, "%") {
			scale = .01
			s = strings.TrimSuffix(s, "%")
		}
		v, ok := number(s)
		if !ok {
			return Value{}, valueInvalid
		}
		v = clamp(v*scale, 1)
		return Value{Text: strconv.FormatFloat(v, 'g', -1, 64), Number: v, Known: true}, valueResolved
	case fontSize:
		factor := 1.0
		num, unit, hasUnit := splitLength(s)
		known := true
		if hasUnit {
			switch unit.kind {
			case lengthUnitRootFont:
				factor = root[fontSize].Number
				known = root[fontSize].Known
			case lengthUnitAbsolute:
				factor = unit.scale
			case lengthUnitParentFont:
				factor = parent[fontSize].Number
				known = parent[fontSize].Known
			case lengthUnitPercentage:
				factor = parent[fontSize].Number / 100
				known = parent[fontSize].Known
			case lengthUnitContextual:
				v, ok := number(num)
				if !ok {
					return Value{}, valueInvalid
				}
				if v < 0 {
					return Value{}, valueInvalid
				}
				return Value{Text: s}, valueUnsupported
			}
		} else {
			absolute := map[string]float64{
				"xx-small": 9, "x-small": 12, "small": 13, "medium": 16,
				"large": 18, "x-large": 24, "xx-large": 32, "xxx-large": 48,
			}
			if v, ok := absolute[s]; ok {
				return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: true}, valueResolved
			}
			if s == "smaller" || s == "larger" {
				if !parent[fontSize].Known {
					return Value{Text: s}, valueResolved
				}
				factor := .8
				if s == "larger" {
					factor = 1.2
				}
				v := parent[fontSize].Number * factor
				return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: parent[fontSize].Known}, valueResolved
			}
			if v, ok := number(s); ok {
				if v == 0 {
					return Value{Text: "0px", Known: true}, valueResolved
				}
				return Value{}, valueInvalid
			}
			if strings.Contains(s, "(") || s == "math" {
				return Value{Text: s}, valueUnsupported
			}
			return Value{}, valueInvalid
		}
		v, ok := number(num)
		if !ok || v < 0 {
			return Value{}, valueInvalid
		}
		if !known {
			return Value{Text: s}, valueResolved
		}
		v *= factor
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return Value{Text: s}, valueUnsupported
		}
		return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: known}, valueResolved
	case backgroundImage, filter, backdropFilter, maskImage, textShadow, transform:
		if s == "none" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case backgroundClip:
		if s == "border-box" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case textFill:
		if s == "currentcolor" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case position:
		if s == "static" || s == "relative" || s == "absolute" || s == "fixed" || s == "sticky" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case textStroke:
		if s == "0" || s == "0px" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case blend, backgroundBlend:
		if s == "normal" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case color, background:
		if s == "currentcolor" {
			if p == color {
				return parent[color], valueResolved
			}
			return Value{Text: s, Known: true}, valueResolved
		}
		c, status := readColour(s)
		if status != valueResolved {
			return Value{Text: s}, status
		}
		return Value{Text: colourString(c), RGBA: c, Known: true}, status
	}
	return Value{Text: s}, valueUnsupported
}

func resolveLayoutProperty(property int, value string) (Value, valueStatus) {
	if strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'") {
		return Value{}, valueInvalid
	}
	if value == "" {
		return Value{}, valueInvalid
	}
	if value == "inherit" || value == "unset" || value == "revert" || value == "revert-layer" || strings.Contains(value, "var(") || isMath(value) {
		return Value{Text: value}, valueUnsupported
	}
	if value == "initial" {
		switch property {
		case overflowX, overflowY:
			value = "visible"
		case width, height, left, top, right, bottom:
			value = "auto"
		case maxWidth, maxHeight:
			value = "none"
		case textIndent:
			value = "0px"
		case letterSpacing, wordSpacing:
			value = "normal"
		case marginTop, marginRight, marginBottom, marginLeft:
			value = "0px"
		case zoom:
			value = "1"
		}
	}
	if property == zoom {
		if value == "normal" {
			return Value{Text: "1", Number: 1, Known: true}, valueResolved
		}
		scale := 1.0
		numberText := value
		if strings.HasSuffix(numberText, "%") {
			scale = .01
			numberText = strings.TrimSuffix(numberText, "%")
		}
		n, ok := number(numberText)
		if !ok || n < 0 {
			return Value{}, valueInvalid
		}
		n *= scale
		return Value{Text: value, Number: n, Known: true}, valueResolved
	}
	if property == overflowX || property == overflowY {
		parts := splitCSSWhitespace(value)
		if len(parts) != 1 {
			return Value{}, valueInvalid
		}
		for _, part := range parts {
			if part != "visible" && part != "hidden" && part != "clip" && part != "scroll" && part != "auto" {
				return Value{}, valueInvalid
			}
		}
		return Value{Text: strings.Join(parts, " "), Known: true}, valueResolved
	}
	if (property == letterSpacing || property == wordSpacing) && value == "normal" {
		return Value{Text: value, Known: true}, valueResolved
	}
	return resolveLayoutLength(property, value)
}

func resolveLayoutLength(property int, value string) (Value, valueStatus) {
	if (property == width || property == height || property == left || property == top || property == right || property == bottom ||
		property == marginTop || property == marginRight || property == marginBottom || property == marginLeft) && value == "auto" {
		return Value{Text: value, Known: true}, valueResolved
	}
	if (property == maxWidth || property == maxHeight) && value == "none" {
		return Value{Text: value, Known: true}, valueResolved
	}
	numberText, unit, hasUnit := splitLength(value)
	n, ok := number(numberText)
	if !ok {
		// A syntactically valid number can overflow float64. It remains a valid
		// contextual length for visibility purposes rather than becoming an
		// invalid declaration that silently restores trusted visibility.
		if hasUnit && validCSSNumber(numberText) {
			if !layoutPropertyAllowsNegative(property) && strings.HasPrefix(numberText, "-") {
				return Value{}, valueInvalid
			}
			saturated := math.MaxFloat64
			if strings.HasPrefix(numberText, "-") {
				saturated = -saturated
			}
			return Value{Text: value, Number: saturated}, valueUnsupported
		}
		return Value{}, valueInvalid
	}
	if !layoutPropertyAllowsNegative(property) && n < 0 {
		return Value{}, valueInvalid
	}
	// Unitless zero and zero in any length unit are independent of layout.
	// Literal pixel lengths are also directly comparable. Other non-zero
	// lengths require dimensions or font metrics, but retain their numeric
	// component so the layout detector can recognize extreme negative values.
	if !hasUnit && n != 0 {
		return Value{}, valueInvalid
	}
	if n != 0 && (!hasUnit || unit.suffix != "px") {
		return Value{Text: value, Number: n}, valueUnsupported
	}
	return Value{Text: value, Number: n, Known: true}, valueResolved
}

func layoutPropertyAllowsNegative(property int) bool {
	switch property {
	case left, top, right, bottom, textIndent, letterSpacing, wordSpacing,
		marginTop, marginRight, marginBottom, marginLeft:
		return true
	default:
		return false
	}
}

var named = map[string]string{"black": "#000000", "silver": "#c0c0c0", "gray": "#808080", "grey": "#808080", "white": "#ffffff", "maroon": "#800000", "red": "#ff0000", "purple": "#800080", "fuchsia": "#ff00ff", "magenta": "#ff00ff", "green": "#008000", "lime": "#00ff00", "olive": "#808000", "yellow": "#ffff00", "navy": "#000080", "blue": "#0000ff", "teal": "#008080", "aqua": "#00ffff", "cyan": "#00ffff", "orange": "#ffa500", "rebeccapurple": "#663399"}

const unsupportedColourNameList = `
canvas canvastext linktext visitedtext activetext buttonface buttontext
buttonborder field fieldtext highlight highlighttext selecteditem
selecteditemtext mark marktext graytext accentcolor accentcolortext
aliceblue antiquewhite aquamarine azure beige bisque blanchedalmond
blueviolet brown burlywood cadetblue chartreuse chocolate coral
cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod
darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen
darkorange darkorchid darkred darksalmon darkseagreen darkslateblue
darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue
dimgray dimgrey dodgerblue firebrick floralwhite forestgreen gainsboro
ghostwhite gold goldenrod greenyellow grey honeydew hotpink indianred indigo
ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue
lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey
lightpink lightsalmon lightseagreen lightskyblue lightslategray
lightslategrey lightsteelblue lightyellow limegreen linen magenta
mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen
mediumslateblue mediumspringgreen mediumturquoise mediumvioletred
midnightblue mintcream mistyrose moccasin navajowhite oldlace olivedrab
orangered orchid palegoldenrod palegreen paleturquoise palevioletred
papayawhip peachpuff peru pink plum powderblue rosybrown royalblue
saddlebrown salmon sandybrown seagreen seashell sienna skyblue slateblue
slategray slategrey snow springgreen steelblue tan thistle tomato turquoise
violet wheat whitesmoke yellowgreen`

var unsupportedColourNames = func() map[string]struct{} {
	names := strings.Fields(unsupportedColourNameList)
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}()

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
	if component == "none" || strings.Contains(component, "(") {
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
	if component == "none" || strings.Contains(component, "(") {
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

func colourString(c RGBA) string {
	return fmt.Sprintf("rgba(%g,%g,%g,%g)", c.R*255, c.G*255, c.B*255, c.A)
}
