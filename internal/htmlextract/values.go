package htmlextract

import (
	"math"
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
	for _, p := range []int{backgroundImage, filter, backdropFilter, maskImage, textShadow, transform, scale, translate, rotate, fontSizeAdjust} {
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
	s[lineHeight] = Value{Text: "normal", Known: true}
	return s
}

func initial() Style { return initialStyle }
func inherits(p int) bool {
	return p == fontSizeAdjust || p == visibility || p == fontSize || p == lineHeight || p == color || p == textShadow || p == textFill || p == textStroke
}

// number parses the decimal syntax accepted by CSS <number>. strconv.ParseFloat
// alone is too permissive here: it also accepts Go spellings such as hexadecimal
// floats and underscore separators that a browser does not treat as CSS numbers.
func number(s string) (float64, bool) { return numberWithBudget(s, nil) }

func clamp(v, hi float64) float64 { return math.Min(hi, math.Max(0, v)) }

type valueStatus uint8

const (
	valueInvalid valueStatus = iota
	valueResolved
	valueUnsupported
)

func resolve(p int, s string, parent, root *Style) (Value, valueStatus) {
	return resolveWithBudget(p, s, parent, root, nil)
}

func resolveWithBudget(p int, s string, parent, root *Style, budget *cpuGuard) (Value, valueStatus) {
	var normalized bool
	s, normalized = normalizeCSSKeywordWithBudget(s, budget)
	if !normalized {
		return Value{}, valueUnsupported
	}
	if p >= properties {
		return resolveLayoutPropertyWithBudget(p, s, budget)
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
		return resolveClip(p, s, budget)
	}
	if p != color && p != background && strings.Contains(s, "(") {
		return Value{Text: s}, valueUnsupported
	}
	switch p {
	case display:
		switch s {
		case "none", "inline", "block", "inline-block", "list-item", "table", "table-row", "table-cell", "table-row-group", "table-header-group", "table-footer-group", "table-column", "table-column-group", "table-caption", "flex", "inline-flex", "grid", "inline-grid", "contents", "flow-root":
			return Value{Text: s, Known: true}, valueResolved
		case "run-in", "ruby", "ruby-base", "ruby-text", "ruby-base-container", "ruby-text-container", "math":
			return Value{Text: s}, valueUnsupported
		}
		if strings.ContainsAny(s, " ()") {
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
		v, ok := numberWithBudget(s, budget)
		if !ok {
			return Value{}, valueInvalid
		}
		v = clamp(v*scale, 1)
		return Value{Text: numberStringWithBudget(v, "", budget), Number: v, Known: true}, valueResolved
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
				v, ok := numberWithBudget(num, budget)
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
				return Value{Text: numberStringWithBudget(v, "px", budget), Number: v, Known: true}, valueResolved
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
				return Value{Text: numberStringWithBudget(v, "px", budget), Number: v, Known: parent[fontSize].Known}, valueResolved
			}
			if v, ok := numberWithBudget(s, budget); ok {
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
		v, ok := numberWithBudget(num, budget)
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
		return Value{Text: numberStringWithBudget(v, "px", budget), Number: v, Known: known}, valueResolved
	case lineHeight:
		return resolveLineHeightWithBudget(s, budget)
	case filter, backdropFilter:
		if s == "none" {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{}, valueInvalid
	case scale, translate, rotate, fontSizeAdjust:
		if s == "none" || p == scale && (s == "1" || s == "100%") || p == translate && (s == "0" || s == "0px") || p == rotate && (s == "0" || s == "0deg") {
			return Value{Text: s, Known: true}, valueResolved
		}
		return Value{Text: s}, valueUnsupported
	case backgroundImage, maskImage, textShadow, transform:
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
		c, status := readColourWithBudget(s, budget)
		if status != valueResolved {
			return Value{Text: s}, status
		}
		return Value{Text: colourStringWithBudget(c, budget), RGBA: c, Known: true}, status
	}
	return Value{Text: s}, valueUnsupported
}

func resolveLayoutProperty(property int, value string) (Value, valueStatus) {
	return resolveLayoutPropertyWithBudget(property, value, nil)
}
func resolveLayoutPropertyWithBudget(property int, value string, budget *cpuGuard) (Value, valueStatus) {
	switch property {
	case overflowInline, overflowBlock:
		property = overflowX
	case inlineSize, blockSize:
		property = width
	case maxInlineSize, maxBlockSize:
		property = maxWidth
	case insetInlineStart, insetInlineEnd, insetBlockStart, insetBlockEnd:
		property = left
	case marginInlineStart, marginInlineEnd, marginBlockStart, marginBlockEnd:
		property = marginLeft
	}

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
		n, ok := numberWithBudget(numberText, budget)
		if !ok || n < 0 {
			return Value{}, valueInvalid
		}
		n *= scale
		return Value{Text: value, Number: n, Known: true}, valueResolved
	}
	if property == overflowX || property == overflowY {
		var scratch [1]string
		parts := splitCSSWhitespace(value, scratch[:])
		if len(parts) != 1 {
			return Value{}, valueInvalid
		}
		for _, part := range parts {
			if part != "visible" && part != "hidden" && part != "clip" && part != "scroll" && part != "auto" {
				return Value{}, valueInvalid
			}
		}
		return Value{Text: parts[0], Known: true}, valueResolved
	}
	if (property == letterSpacing || property == wordSpacing) && value == "normal" {
		return Value{Text: value, Known: true}, valueResolved
	}
	return resolveLayoutLengthWithBudget(property, value, budget)
}

func resolveLineHeightWithBudget(value string, budget *cpuGuard) (Value, valueStatus) {
	if value == "normal" {
		return Value{Text: value, Known: true}, valueResolved
	}
	numberText, unit, hasUnit := splitLength(value)
	n, ok := numberWithBudget(numberText, budget)
	if !ok || n < 0 {
		return Value{}, valueInvalid
	}
	if !hasUnit || n == 0 {
		return Value{Text: value, Number: n, Known: true}, valueResolved
	}
	return Value{Text: value, Number: n, Known: unit.kind == lengthUnitAbsolute && unit.suffix == "px"}, valueResolved
}

func resolveLayoutLengthWithBudget(property int, value string, budget *cpuGuard) (Value, valueStatus) {
	if (property == width || property == height || property == left || property == top || property == right || property == bottom ||
		property == marginTop || property == marginRight || property == marginBottom || property == marginLeft) && value == "auto" {
		return Value{Text: value, Known: true}, valueResolved
	}
	if (property == maxWidth || property == maxHeight) && value == "none" {
		return Value{Text: value, Known: true}, valueResolved
	}
	numberText, unit, hasUnit := splitLength(value)
	n, ok := parseCSSNumber(numberText, budget)
	if !ok || math.IsInf(n, 0) {
		// A syntactically valid number can overflow float64. It remains a valid
		// contextual length for visibility purposes rather than becoming an
		// invalid declaration that silently restores trusted visibility.
		if hasUnit && ok {
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
