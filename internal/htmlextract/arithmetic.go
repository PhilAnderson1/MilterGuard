package htmlextract

import (
	"github.com/tdewolff/parse/v2/css"
	"math"
	"strconv"
	"strings"
)

type quantity struct {
	n      float64
	length bool
}
type mathParser struct {
	ts                      []valueToken
	at, depth, prop, status int
	parent, root            Style
}

func isMath(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, f := range []string{"calc(", "min(", "max(", "clamp("} {
		if strings.HasPrefix(s, f) {
			return true
		}
	}
	return false
}
func evalMath(prop int, src string, parent, root Style, budget *expressionBudget) (Value, int) {
	ts, status := lexValue(src)
	if status != 1 {
		return Value{Text: src}, status
	}
	if !budget.charge(len(ts)) {
		return Value{Text: src}, 2
	}
	// Binary + and - require whitespace on both sides (comments alone do not suffice).
	for i, t := range ts {
		if t.kind == css.DelimToken && (t.raw == "+" || t.raw == "-") {
			if i == 0 || i+1 == len(ts) || ts[i-1].kind != css.WhitespaceToken || ts[i+1].kind != css.WhitespaceToken {
				return Value{}, 0
			}
		}
	}
	p := mathParser{ts: significant(ts), status: 1, prop: prop, parent: parent, root: root}
	q := p.expr(0)
	if p.at != len(p.ts) && p.status == 1 {
		p.status = 0
	}
	if p.status != 1 {
		return Value{Text: src}, p.status
	}
	if prop == fontSize && !q.length || prop == opacity && q.length {
		return Value{}, 0
	}
	if math.IsNaN(q.n) || math.IsInf(q.n, 0) {
		return Value{Text: src}, 2
	}
	q.n = math.Max(0, q.n)
	if prop == opacity {
		q.n = math.Min(1, q.n)
	}
	txt := strconv.FormatFloat(q.n, 'g', -1, 64)
	if prop == fontSize {
		txt += "px"
	}
	return Value{Text: txt, Number: q.n, Known: true}, 1
}
func (p *mathParser) expr(min int) quantity {
	left := p.atom()
	for p.status == 1 && p.at < len(p.ts) {
		t := p.ts[p.at]
		priority := 0
		if t.kind == css.DelimToken {
			switch t.raw {
			case "+", "-":
				priority = 1
			case "*", "/":
				priority = 2
			}
		}
		if priority == 0 || priority < min {
			break
		}
		p.at++
		right := p.expr(priority + 1)
		switch t.raw {
		case "+", "-":
			if left.length != right.length {
				p.status = 0
				break
			}
			if t.raw == "+" {
				left.n += right.n
			} else {
				left.n -= right.n
			}
		case "*":
			if left.length && right.length {
				p.status = 2
				break
			}
			left = quantity{left.n * right.n, left.length || right.length}
		case "/":
			if right.n == 0 {
				p.status = 2
				break
			}
			if right.length {
				p.status = 2
				break
			}
			left.n /= right.n
		}
		if math.IsNaN(left.n) || math.IsInf(left.n, 0) {
			p.status = 2
		}
	}
	return left
}
func (p *mathParser) atom() quantity {
	if p.at >= len(p.ts) {
		p.status = 0
		return quantity{}
	}
	if p.depth >= maxExpressionDepth {
		p.status = 2
		return quantity{}
	}
	t := p.ts[p.at]
	p.at++
	if t.kind == css.FunctionToken || t.kind == css.LeftParenthesisToken {
		name := strings.ToLower(t.raw)
		if t.kind == css.LeftParenthesisToken {
			name = "calc("
		}
		if name != "calc(" && name != "min(" && name != "max(" && name != "clamp(" {
			p.status = 2
			return quantity{}
		}
		p.depth++
		var args []quantity
		for {
			args = append(args, p.expr(0))
			if p.status != 1 {
				p.depth--
				return quantity{}
			}
			if p.at >= len(p.ts) {
				p.status = 0
				break
			}
			end := p.ts[p.at]
			p.at++
			if end.kind == css.RightParenthesisToken {
				break
			}
			if end.kind != css.CommaToken {
				p.status = 0
				break
			}
		}
		p.depth--
		if len(args) == 0 {
			return quantity{}
		}
		q := args[0]
		for _, a := range args {
			if q.length != a.length {
				p.status = 0
			}
		}
		switch name {
		case "calc(":
			if len(args) != 1 {
				p.status = 0
			}
		case "clamp(":
			if len(args) != 3 {
				p.status = 0
			} else {
				q.n = math.Max(args[0].n, math.Min(args[1].n, args[2].n))
			}
		case "min(":
			for _, a := range args {
				q.n = math.Min(q.n, a.n)
			}
		case "max(":
			for _, a := range args {
				q.n = math.Max(q.n, a.n)
			}
		}
		return q
	}
	if t.kind == css.NumberToken {
		v, ok := number(t.raw)
		if !ok {
			p.status = 2
		}
		return quantity{n: v}
	}
	if t.kind == css.PercentageToken {
		v, ok := number(strings.TrimSuffix(t.raw, "%"))
		if !ok {
			p.status = 2
		}
		if p.prop == opacity {
			return quantity{n: v / 100}
		}
		if !p.parent[fontSize].Known {
			p.status = 2
		}
		return quantity{v * p.parent[fontSize].Number / 100, true}
	}
	if t.kind == css.DimensionToken {
		if p.prop == opacity {
			p.status = 0
			return quantity{}
		}
		s := strings.ToLower(t.raw)
		for _, unit := range []string{"rem", "px", "pt", "em"} {
			if strings.HasSuffix(s, unit) {
				v, ok := number(strings.TrimSuffix(s, unit))
				if !ok {
					p.status = 0
				}
				factor := 1.0
				switch unit {
				case "pt":
					factor = 96.0 / 72
				case "em":
					factor = p.parent[fontSize].Number
					if !p.parent[fontSize].Known {
						p.status = 2
					}
				case "rem":
					factor = p.root[fontSize].Number
					if !p.root[fontSize].Known {
						p.status = 2
					}
				}
				return quantity{v * factor, true}
			}
		}
		p.status = 2
		return quantity{}
	}
	if t.kind == css.IdentToken {
		p.status = 2
	} else {
		p.status = 0
	}
	return quantity{}
}
