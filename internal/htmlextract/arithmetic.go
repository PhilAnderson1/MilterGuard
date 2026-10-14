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
	ts              []valueToken
	at, depth, prop int
	status          valueStatus
	parent, root    *Style
	budget          *expressionBudget
}

func isMath(s string) bool {
	s = normalizeCSSKeyword(s)
	for _, f := range []string{"calc(", "min(", "max(", "clamp("} {
		if strings.HasPrefix(s, f) {
			return true
		}
	}
	return false
}
func evalMath(prop int, src string, parent, root *Style, budget *expressionBudget) (Value, valueStatus) {
	// Substituted values do not have a reusable token stream. Charge their byte
	// scan before invoking the lexer so an exhausted budget cannot repeatedly
	// allocate tokens for values it will subsequently reject.
	if !budget.charge(len(src)) {
		return Value{Text: src}, valueUnsupported
	}
	ts, status := lexValue(src)
	if status != valueResolved {
		return Value{Text: src}, status
	}
	return evalMathTokens(prop, src, ts, parent, root, budget)
}

func evalMathTokens(prop int, src string, ts []valueToken, parent, root *Style, budget *expressionBudget) (Value, valueStatus) {
	if !budget.charge(len(ts)) {
		return Value{Text: src}, valueUnsupported
	}
	// Binary + and - require whitespace on both sides (comments alone do not suffice).
	for i, t := range ts {
		if t.kind == css.DelimToken && (t.raw == "+" || t.raw == "-") {
			if i == 0 || i+1 == len(ts) || ts[i-1].kind != css.WhitespaceToken || ts[i+1].kind != css.WhitespaceToken {
				return Value{}, valueInvalid
			}
		}
	}
	p := mathParser{ts: significant(ts), status: valueResolved, prop: prop, parent: parent, root: root, budget: budget}
	q := p.expr(0)
	if p.at != len(p.ts) && p.status == valueResolved {
		p.status = valueInvalid
	}
	if p.status != valueResolved {
		return Value{Text: src}, p.status
	}
	if prop == fontSize && !q.length || prop == opacity && q.length {
		return Value{}, valueInvalid
	}
	if math.IsNaN(q.n) || math.IsInf(q.n, 0) {
		return Value{Text: src}, valueUnsupported
	}
	q.n = math.Max(0, q.n)
	if prop == opacity {
		q.n = math.Min(1, q.n)
	}
	txt := strconv.FormatFloat(q.n, 'g', -1, 64)
	if prop == fontSize {
		txt += "px"
	}
	return Value{Text: txt, Number: q.n, Known: true}, valueResolved
}
func (p *mathParser) expr(min int) quantity {
	left := p.atom()
	for p.status == valueResolved && p.at < len(p.ts) {
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
				p.status = valueInvalid
				break
			}
			if t.raw == "+" {
				left.n += right.n
			} else {
				left.n -= right.n
			}
		case "*":
			if left.length && right.length {
				p.status = valueUnsupported
				break
			}
			left = quantity{left.n * right.n, left.length || right.length}
		case "/":
			if right.n == 0 {
				p.status = valueUnsupported
				break
			}
			if right.length {
				p.status = valueUnsupported
				break
			}
			left.n /= right.n
		}
		if math.IsNaN(left.n) || math.IsInf(left.n, 0) {
			p.status = valueUnsupported
		}
	}
	return left
}
func (p *mathParser) atom() quantity {
	if p.at >= len(p.ts) {
		p.status = valueInvalid
		return quantity{}
	}
	if p.depth >= maxExpressionDepth {
		p.budget.rejectDepth()
		p.status = valueUnsupported
		return quantity{}
	}
	t := p.ts[p.at]
	p.at++
	if t.kind == css.FunctionToken || t.kind == css.LeftParenthesisToken {
		name := asciiLower(t.raw)
		if t.kind == css.LeftParenthesisToken {
			name = "calc("
		}
		if name != "calc(" && name != "min(" && name != "max(" && name != "clamp(" {
			p.status = valueUnsupported
			return quantity{}
		}
		p.depth++
		var args []quantity
		for {
			args = append(args, p.expr(0))
			if p.status != valueResolved {
				p.depth--
				return quantity{}
			}
			if p.at >= len(p.ts) {
				p.status = valueInvalid
				break
			}
			end := p.ts[p.at]
			p.at++
			if end.kind == css.RightParenthesisToken {
				break
			}
			if end.kind != css.CommaToken {
				p.status = valueInvalid
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
				p.status = valueInvalid
			}
		}
		switch name {
		case "calc(":
			if len(args) != 1 {
				p.status = valueInvalid
			}
		case "clamp(":
			if len(args) != 3 {
				p.status = valueInvalid
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
			p.status = valueUnsupported
		}
		return quantity{n: v}
	}
	if t.kind == css.PercentageToken {
		v, ok := number(strings.TrimSuffix(t.raw, "%"))
		if !ok {
			p.status = valueUnsupported
		}
		if p.prop == opacity {
			return quantity{n: v / 100}
		}
		if !p.parent[fontSize].Known {
			p.status = valueUnsupported
		}
		return quantity{v * p.parent[fontSize].Number / 100, true}
	}
	if t.kind == css.DimensionToken {
		if p.prop == opacity {
			p.status = valueInvalid
			return quantity{}
		}
		s := asciiLower(t.raw)
		numberText, unit, found := splitLength(s)
		if !found || unit.kind == lengthUnitContextual || unit.kind == lengthUnitPercentage {
			p.status = valueUnsupported
			return quantity{}
		}
		v, ok := number(numberText)
		if !ok {
			p.status = valueInvalid
		}
		factor := unit.scale
		switch unit.kind {
		case lengthUnitParentFont:
			factor = p.parent[fontSize].Number
			if !p.parent[fontSize].Known {
				p.status = valueUnsupported
			}
		case lengthUnitRootFont:
			factor = p.root[fontSize].Number
			if !p.root[fontSize].Known {
				p.status = valueUnsupported
			}
		}
		return quantity{v * factor, true}
	}
	if t.kind == css.IdentToken {
		p.status = valueUnsupported
	} else {
		p.status = valueInvalid
	}
	return quantity{}
}
