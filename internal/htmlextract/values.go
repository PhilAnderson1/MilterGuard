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
func number(s string) (float64, bool) {
	v, e := strconv.ParseFloat(s, 64)
	return v, e == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}
func clamp(v, hi float64) float64 { return math.Min(hi, math.Max(0, v)) }

// status: 0 known-invalid; 1 resolved; 2 potentially valid but unsupported.
func resolve(p int, s string, parent, root Style) (Value, int) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		return Value{}, 0
	}
	def := initialStyle[p]
	switch s {
	case "inherit":
		return parent[p], 1
	case "initial":
		return def, 1
	case "unset":
		if inherits(p) {
			return parent[p], 1
		}
		return def, 1
	case "":
		return Value{}, 0
	}
	if strings.Contains(s, "var(") || strings.Contains(s, "calc(") || s == "revert" || s == "revert-layer" {
		return Value{Text: s}, 2
	}
	if p == clip || p == clipPath {
		return resolveClip(p, s)
	}
	if p != color && p != background && strings.Contains(s, "(") {
		return Value{Text: s}, 2
	}
	switch p {
	case display:
		switch s {
		case "none", "inline", "block", "inline-block", "list-item", "table", "table-row", "table-cell", "table-row-group", "table-header-group", "table-footer-group", "table-column", "table-column-group", "table-caption", "flex", "inline-flex", "grid", "inline-grid", "contents", "flow-root":
			return Value{Text: s, Known: true}, 1
		}
		if strings.ContainsAny(s, " ()") || strings.Contains(" run-in ruby ruby-base ruby-text ruby-base-container ruby-text-container math ", " "+s+" ") {
			return Value{Text: s}, 2
		}
		return Value{}, 0
	case visibility:
		if s == "visible" || s == "hidden" || s == "collapse" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{}, 0
	case contentVisibility:
		if s == "visible" || s == "hidden" || s == "auto" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{}, 0
	case opacity:
		scale := 1.0
		if strings.HasSuffix(s, "%") {
			scale = .01
			s = strings.TrimSuffix(s, "%")
		}
		v, ok := number(s)
		if !ok {
			return Value{}, 0
		}
		v = clamp(v*scale, 1)
		return Value{Text: strconv.FormatFloat(v, 'g', -1, 64), Number: v, Known: true}, 1
	case fontSize:
		factor := 1.0
		num := s
		known := true
		switch {
		case strings.HasSuffix(s, "rem"):
			num = s[:len(s)-3]
			factor = root[fontSize].Number
			known = root[fontSize].Known
		case strings.HasSuffix(s, "px"):
			num = s[:len(s)-2]
		case strings.HasSuffix(s, "pt"):
			num = s[:len(s)-2]
			factor = 96.0 / 72
		case strings.HasSuffix(s, "em"):
			num = s[:len(s)-2]
			factor = parent[fontSize].Number
			known = parent[fontSize].Known
		case strings.HasSuffix(s, "%"):
			num = s[:len(s)-1]
			factor = parent[fontSize].Number / 100
			known = parent[fontSize].Known
		default:
			absolute := map[string]float64{
				"xx-small": 9, "x-small": 12, "small": 13, "medium": 16,
				"large": 18, "x-large": 24, "xx-large": 32, "xxx-large": 48,
			}
			if v, ok := absolute[s]; ok {
				return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: true}, 1
			}
			if s == "smaller" || s == "larger" {
				factor := .8
				if s == "larger" {
					factor = 1.2
				}
				v := parent[fontSize].Number * factor
				return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: parent[fontSize].Known}, 1
			}
			if v, ok := number(s); ok {
				if v == 0 {
					return Value{Text: "0px", Known: true}, 1
				}
				return Value{}, 0
			}
			if strings.Contains(s, "(") || s == "math" {
				return Value{Text: s}, 2
			}
			// Other CSS length units may be valid, but are outside scope.
			for _, unit := range []string{"ex", "ch", "lh", "rlh", "cap", "rcap", "ic", "ric", "rex", "rch", "vw", "vh", "vi", "vb", "vmin", "vmax", "svw", "svh", "lvw", "lvh", "dvw", "dvh", "cm", "mm", "q", "in", "pc"} {
				if strings.HasSuffix(s, unit) {
					if v, ok := number(strings.TrimSuffix(s, unit)); ok {
						if v < 0 {
							return Value{}, 0
						}
						return Value{Text: s}, 2
					}
				}
			}
			return Value{}, 0
		}
		v, ok := number(num)
		if !ok || v < 0 {
			return Value{}, 0
		}
		v *= factor
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return Value{Text: s}, 2
		}
		return Value{Text: fmt.Sprintf("%gpx", v), Number: v, Known: known}, 1
	case backgroundImage, filter, backdropFilter, maskImage, textShadow, transform:
		if s == "none" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case backgroundClip:
		if s == "border-box" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case textFill:
		if s == "currentcolor" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case position:
		if s == "static" || s == "relative" || s == "absolute" || s == "fixed" || s == "sticky" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case textStroke:
		if s == "0" || s == "0px" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case blend, backgroundBlend:
		if s == "normal" {
			return Value{Text: s, Known: true}, 1
		}
		return Value{Text: s}, 2
	case color, background:
		if s == "currentcolor" {
			if p == color {
				return parent[color], 1
			}
			return Value{Text: s, Known: true}, 1
		}
		c, status := readColour(s)
		if status != 1 {
			return Value{Text: s}, status
		}
		return Value{Text: colourString(c), RGBA: c, Known: true}, status
	}
	return Value{Text: s}, 2
}

var named = map[string]string{"black": "#000000", "silver": "#c0c0c0", "gray": "#808080", "white": "#ffffff", "maroon": "#800000", "red": "#ff0000", "purple": "#800080", "fuchsia": "#ff00ff", "green": "#008000", "lime": "#00ff00", "olive": "#808000", "yellow": "#ffff00", "navy": "#000080", "blue": "#0000ff", "teal": "#008080", "aqua": "#00ffff", "orange": "#ffa500", "rebeccapurple": "#663399"}

func readColour(s string) (RGBA, int) {
	if s == "transparent" {
		return RGBA{}, 1
	}
	if v, ok := named[s]; ok {
		s = v
	}
	var c [4]float64
	c[3] = 1
	if strings.HasPrefix(s, "#") {
		h := s[1:]
		if len(h) != 3 && len(h) != 4 && len(h) != 6 && len(h) != 8 {
			return RGBA{}, 0
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
				return RGBA{}, 0
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
			return parseRGBFunction(body)
		case "hsl", "hsla":
			return parseHSLFunction(body)
		default:
			return RGBA{}, 2
		}
	} else {
		if strings.Contains(s, "(") || strings.Contains(" canvas canvastext linktext visitedtext activetext buttonface buttontext buttonborder field fieldtext highlight highlighttext selecteditem selecteditemtext mark marktext graytext accentcolor accentcolortext ", " "+s+" ") {
			return RGBA{}, 2
		}
		// Named colours outside the documented basic set remain unresolved.
		if strings.Contains(" aliceblue antiquewhite aquamarine azure beige bisque blanchedalmond blueviolet brown burlywood cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue dimgray dimgrey dodgerblue firebrick floralwhite forestgreen gainsboro ghostwhite gold goldenrod greenyellow grey honeydew hotpink indianred indigo ivory khaki lavender lavenderblush lawngreen lemonchiffon lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow limegreen linen magenta mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite oldlace olivedrab orangered orchid palegoldenrod palegreen paleturquoise palevioletred papayawhip peachpuff peru pink plum powderblue rosybrown royalblue saddlebrown salmon sandybrown seagreen seashell sienna skyblue slateblue slategray slategrey snow springgreen steelblue tan thistle tomato turquoise violet wheat whitesmoke yellowgreen ", " "+s+" ") {
			return RGBA{}, 2
		}
		return RGBA{}, 0
	}
	return RGBA{c[0] / 255, c[1] / 255, c[2] / 255, c[3]}, 1
}

func colourFunctionParts(body string) (channels []string, alpha string, legacy bool, status int) {
	if strings.Contains(body, "(") || strings.Contains(strings.ToLower(body), "from") {
		return nil, "", false, 2
	}
	if strings.Contains(body, ",") {
		if strings.Contains(body, "/") {
			return nil, "", true, 0
		}
		parts := strings.Split(body, ",")
		if len(parts) != 3 && len(parts) != 4 {
			return nil, "", true, 0
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
			if parts[i] == "" {
				return nil, "", true, 0
			}
		}
		if len(parts) == 4 {
			alpha = parts[3]
		}
		return parts[:3], alpha, true, 1
	}
	if strings.Count(body, "/") > 1 {
		return nil, "", false, 0
	}
	parts := strings.SplitN(body, "/", 2)
	channels = strings.Fields(parts[0])
	if len(channels) != 3 {
		return nil, "", false, 0
	}
	if len(parts) == 2 {
		alphaParts := strings.Fields(parts[1])
		if len(alphaParts) != 1 {
			return nil, "", false, 0
		}
		alpha = alphaParts[0]
	}
	return channels, alpha, false, 1
}

func colourNumber(component string, numberScale, hi float64) (float64, int) {
	if component == "none" || strings.Contains(component, "(") {
		return 0, 2
	}
	percentage := strings.HasSuffix(component, "%")
	if percentage {
		component = strings.TrimSuffix(component, "%")
	}
	n, ok := number(component)
	if !ok {
		return 0, 0
	}
	if percentage {
		return clamp(n/100*hi, hi), 1
	}
	return clamp(n*numberScale, hi), 1
}

func parseAlpha(component string) (float64, int) {
	if component == "" {
		return 1, 1
	}
	return colourNumber(component, 1, 1)
}

func parseRGBFunction(body string) (RGBA, int) {
	channels, alphaText, legacy, status := colourFunctionParts(body)
	if status != 1 {
		return RGBA{}, status
	}
	if legacy {
		percent := strings.HasSuffix(channels[0], "%")
		for _, channel := range channels[1:] {
			if strings.HasSuffix(channel, "%") != percent {
				return RGBA{}, 0
			}
		}
	}
	var c [3]float64
	for i, channel := range channels {
		c[i], status = colourNumber(channel, 1, 255)
		if status != 1 {
			return RGBA{}, status
		}
	}
	a, status := parseAlpha(alphaText)
	if status != 1 {
		return RGBA{}, status
	}
	return RGBA{c[0] / 255, c[1] / 255, c[2] / 255, a}, 1
}

func parseHue(component string) (float64, int) {
	if component == "none" || strings.Contains(component, "(") {
		return 0, 2
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
		return 0, 0
	}
	n = math.Mod(n*factor, 360)
	if n < 0 {
		n += 360
	}
	return n, 1
}

func parseHSLFunction(body string) (RGBA, int) {
	channels, alphaText, legacy, status := colourFunctionParts(body)
	if status != 1 {
		return RGBA{}, status
	}
	h, status := parseHue(channels[0])
	if status != 1 {
		return RGBA{}, status
	}
	if legacy && (!strings.HasSuffix(channels[1], "%") || !strings.HasSuffix(channels[2], "%")) {
		return RGBA{}, 0
	}
	s, status := colourNumber(channels[1], .01, 1)
	if status != 1 {
		return RGBA{}, status
	}
	l, status := colourNumber(channels[2], .01, 1)
	if status != 1 {
		return RGBA{}, status
	}
	a, status := parseAlpha(alphaText)
	if status != 1 {
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
	return RGBA{r + m, g + m, b + m, a}, 1
}

func colourString(c RGBA) string {
	return fmt.Sprintf("rgba(%g,%g,%g,%g)", c.R*255, c.G*255, c.B*255, c.A)
}
func parseColor(s string) (string, int) {
	c, status := readColour(s)
	if status != 1 {
		return s, status
	}
	return colourString(c), 1
}
