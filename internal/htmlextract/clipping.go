package htmlextract

import (
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// Empty basic shapes do not require box dimensions. Nonempty shapes are not
// evidence of visibility: their relationship to text needs layout.
func resolveClip(p int, s string, budget *cpuGuard) (Value, valueStatus) {
	if p == clipPath && s == "none" || p == clip && s == "auto" {
		return Value{Text: s, Known: true}, valueResolved
	}
	ts, status := lexValue(s, budget)
	if status != valueResolved {
		return Value{Text: s}, status
	}
	ts = significant(ts, budget)
	if p == clipPath {
		if len(ts) == 1 && ts[0].kind == css.IdentToken {
			switch s {
			case "margin-box", "border-box", "padding-box", "content-box", "fill-box", "stroke-box", "view-box":
			default:
				return Value{}, valueInvalid
			}
		}
		if len(ts) == 3 && ts[0].kind == css.FunctionToken && ts[2].kind == css.RightParenthesisToken {
			f := asciiLowerWithBudget(ts[0].raw, budget)
			arg := ts[1].raw
			if f == "circle(" && (arg == "0" || arg == "0px" || arg == "0%") || f == "inset(" && arg == "50%" {
				return Value{Text: s, Number: 1, Known: true}, valueResolved
			}
		}
		return Value{Text: s}, valueUnsupported
	}
	if len(ts) >= 2 && ts[0].raw == "rect(" && ts[len(ts)-1].kind == css.RightParenthesisToken {
		args := ts[1 : len(ts)-1]
		var scratch [4]valueToken
		parts := scratch[:0]
		if len(args) == 7 {
			for i, t := range args {
				if i%2 == 1 {
					if t.kind != css.CommaToken {
						return Value{}, valueInvalid
					}
				} else {
					parts = append(parts, t)
				}
			}
		} else if len(args) == 4 {
			parts = args
		} else {
			return Value{}, valueInvalid
		}
		var v [4]float64
		for i, t := range parts {
			if t.kind != css.DimensionToken && !(t.kind == css.NumberToken && t.raw == "0") {
				return Value{Text: s}, valueUnsupported
			}
			x := t.raw
			if x != "0" && !strings.HasSuffix(x, "px") {
				return Value{Text: s}, valueUnsupported
			}
			n, ok := numberWithBudget(strings.TrimSuffix(x, "px"), budget)
			if !ok {
				return Value{}, valueInvalid
			}
			v[i] = n
		}
		if v[0] >= v[2] || v[3] >= v[1] {
			return Value{Text: s, Number: 1, Known: true}, valueResolved
		}
	}
	return Value{Text: s}, valueUnsupported
}

type clipResult struct {
	empty, known, inlineUncertain, clientDependent bool
}

func emptyClip(st *Style, n *html.Node, displayDeclared bool) clipResult {
	if n.Namespace != "" || !st[display].Known {
		return clipResult{}
	}
	if st[display].Text == "contents" {
		// display:contents generates no principal box on which clip or
		// clip-path could operate. Its child boxes therefore inherit no clipping
		// uncertainty from these declarations.
		return clipResult{known: true}
	}
	inlineClipPathUncertain := st[clipPath].Text != "none" && nonReplacedInlineBox(n, st, displayDeclared)
	known := st[clipPath].Known && !inlineClipPathUncertain
	clipPathEmpty := false
	if inlineClipPathUncertain {
		// The specification applies clip-path to inline boxes, but email-client
		// implementations can differ. Do not claim either concealment or
		// visibility; continue to evaluate the independent legacy clip property.
	} else if st[clipPath].Known && st[clipPath].Number == 1 {
		clipPathEmpty = true
	}
	pos := st[position]
	if pos.Known && (pos.Text == "static" || pos.Text == "relative" || pos.Text == "sticky") {
		return clipResult{empty: clipPathEmpty, known: known, inlineUncertain: inlineClipPathUncertain, clientDependent: clipPathEmpty}
	}
	if pos.Known && (pos.Text == "absolute" || pos.Text == "fixed") {
		if st[clip].Known && st[clip].Number == 1 {
			return clipResult{empty: true, known: true, inlineUncertain: inlineClipPathUncertain}
		}
		return clipResult{empty: clipPathEmpty, known: known && st[clip].Known, inlineUncertain: inlineClipPathUncertain, clientDependent: clipPathEmpty}
	}
	return clipResult{empty: clipPathEmpty, known: known && st[clip].Known && st[clip].Text == "auto", inlineUncertain: inlineClipPathUncertain, clientDependent: clipPathEmpty}
}

// nonReplacedInlineBox identifies boxes for which email-client clip-path
// behavior cannot safely be assumed. CSS's initial display value is inline,
// but the user-agent stylesheet gives many HTML elements a non-inline display,
// so an undeclared value must also consider the element's normal box type.
func nonReplacedInlineBox(n *html.Node, st *Style, displayDeclared bool) bool {
	if st[display].Text != "inline" || st[position].Text == "absolute" || st[position].Text == "fixed" || replacedHTMLElement(n.Data) {
		return false
	}
	return displayDeclared || !defaultNonInlineHTMLElement(n.Data)
}

func replacedHTMLElement(name string) bool {
	switch name {
	case "audio", "button", "canvas", "embed", "iframe", "img", "input", "object", "select", "textarea", "video":
		return true
	default:
		return false
	}
}

func defaultNonInlineHTMLElement(name string) bool {
	switch name {
	case "address", "article", "aside", "blockquote", "body", "caption", "center", "col", "colgroup", "dd", "details", "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "html", "legend", "li", "listing", "main", "menu", "nav", "ol", "p", "plaintext", "pre", "search", "section", "summary", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul", "xmp":
		return true
	default:
		return false
	}
}
