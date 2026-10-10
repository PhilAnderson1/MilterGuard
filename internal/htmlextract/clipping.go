package htmlextract

import (
	"github.com/tdewolff/parse/v2/css"
	"strings"
)

// Empty basic shapes do not require box dimensions. Nonempty shapes are not
// evidence of visibility: their relationship to text needs layout.
func resolveClip(p int, s string) (Value, int) {
	if p == clipPath && s == "none" || p == clip && s == "auto" {
		return Value{Text: s, Known: true}, 1
	}
	ts, status := lexValue(s)
	if status != 1 {
		return Value{Text: s}, status
	}
	ts = significant(ts)
	if p == clipPath {
		if len(ts) == 3 && ts[0].kind == css.FunctionToken && ts[2].kind == css.RightParenthesisToken {
			f := strings.ToLower(ts[0].raw)
			arg := ts[1].raw
			if f == "circle(" && (arg == "0" || arg == "0px" || arg == "0%") || f == "inset(" && arg == "50%" {
				return Value{Text: s, Number: 1, Known: true}, 1
			}
		}
		return Value{Text: s}, 2
	}
	if len(ts) >= 2 && ts[0].raw == "rect(" && ts[len(ts)-1].kind == css.RightParenthesisToken {
		args := ts[1 : len(ts)-1]
		var parts []valueToken
		if len(args) == 7 {
			for i, t := range args {
				if i%2 == 1 {
					if t.kind != css.CommaToken {
						return Value{}, 0
					}
				} else {
					parts = append(parts, t)
				}
			}
		} else if len(args) == 4 {
			parts = args
		} else {
			return Value{}, 0
		}
		var v [4]float64
		for i, t := range parts {
			if t.kind != css.DimensionToken && !(t.kind == css.NumberToken && t.raw == "0") {
				return Value{Text: s}, 2
			}
			x := t.raw
			if x != "0" && !strings.HasSuffix(x, "px") {
				return Value{Text: s}, 2
			}
			n, ok := number(strings.TrimSuffix(x, "px"))
			if !ok {
				return Value{}, 0
			}
			v[i] = n
		}
		if v[0] >= v[2] || v[3] >= v[1] {
			return Value{Text: s, Number: 1, Known: true}, 1
		}
	}
	return Value{Text: s}, 2
}
func emptyClip(st Style, namespace string) (empty, known bool) {
	known = st[clipPath].Known
	if namespace != "" || !st[display].Known || st[display].Text == "contents" {
		return false, false
	}
	if st[clipPath].Known && st[clipPath].Number == 1 {
		return true, true
	}
	pos := st[position]
	if pos.Known && (pos.Text == "static" || pos.Text == "relative" || pos.Text == "sticky") {
		return false, known
	}
	if pos.Known && (pos.Text == "absolute" || pos.Text == "fixed") {
		if st[clip].Known && st[clip].Number == 1 {
			return true, true
		}
		return false, known && st[clip].Known
	}
	return false, known && st[clip].Known && st[clip].Text == "auto"
}
