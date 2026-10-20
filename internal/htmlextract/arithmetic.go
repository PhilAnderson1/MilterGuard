package htmlextract

import (
	"math"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type quantity struct {
	n      float64
	length bool
}
type mathParser struct {
	ts              []valueToken
	literals        []mathLiteral
	at, depth, prop int
	status          valueStatus
	parent, root    *Style
	budget          *cpuGuard
}

// Numeric conversion is context independent; only unit scaling depends on
// the element. A parallel slice avoids enlarging every CSS lexer token.
type mathLiteral struct {
	value float64
	unit  int16 // index into lengthUnits, or -1 for an unsupported dimension
	valid bool
}

func prepareMathLiterals(ts []valueToken, budget *cpuGuard) []mathLiteral {
	literals := resourceguard.MakeSlice[mathLiteral](budget.allocationMemory(), len(ts), len(ts))

	for i, t := range ts {
		budget.check()

		text := t.raw
		switch t.kind {
		case css.NumberToken:
		case css.PercentageToken:
			text = strings.TrimSuffix(text, "%")
		case css.DimensionToken:
			literals[i].unit = -1
			text = asciiLowerWithBudget(text, budget)
			for j, unit := range lengthUnits {
				if strings.HasSuffix(text, unit.suffix) {
					if unit.kind == lengthUnitContextual || unit.kind == lengthUnitPercentage {
						break
					}
					literals[i].unit = int16(j)
					text = text[:len(text)-len(unit.suffix)]
					break
				}
			}
			if literals[i].unit < 0 {
				continue
			}
		default:
			continue
		}
		literals[i].value, literals[i].valid = numberWithBudget(text, budget)
	}

	return literals
}

func isMath(s string) bool {
	s = trimCSSWhitespace(s)
	for _, f := range []string{"calc(", "min(", "max(", "clamp("} {
		if hasASCIIFoldPrefix(s, f) {
			return true
		}
	}
	return false
}
func evalMath(prop int, src string, parent, root *Style, budget *cpuGuard) (Value, valueStatus) {
	// Substituted values do not have a reusable token stream. Check before
	// allocating lexer storage; lexer and evaluator loops continue sampling.
	budget.check()

	ts, status := lexValue(src, budget)
	if status != valueResolved {
		return Value{Text: src}, status
	}
	return evalMathTokens(prop, src, ts, parent, root, budget)
}

func evalMathTokens(prop int, src string, ts []valueToken, parent, root *Style, budget *cpuGuard) (Value, valueStatus) {
	return evalPreparedMathTokens(prop, src, ts, nil, parent, root, budget)
}
func evalPreparedMathTokens(prop int, src string, ts []valueToken, literals []mathLiteral, parent, root *Style, budget *cpuGuard) (Value, valueStatus) {
	if len(literals) != len(ts) {
		literals = prepareMathLiterals(ts, budget)
	}
	if len(literals) != len(ts) {
		return Value{Text: src}, valueUnsupported
	}

	budget.check()

	// Binary + and - require whitespace on both sides (comments alone do not suffice).
	for i, t := range ts {
		budget.check()

		if t.kind == css.DelimToken && (t.raw == "+" || t.raw == "-") {
			if i == 0 || i+1 == len(ts) || ts[i-1].kind != css.WhitespaceToken || ts[i+1].kind != css.WhitespaceToken {
				return Value{}, valueInvalid
			}
		}
	}
	p := mathParser{ts: ts, literals: literals, status: valueResolved, prop: prop, parent: parent, root: root, budget: budget}
	q := p.expr(0)
	p.skipSpace()
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
	unit := ""
	if prop == fontSize {
		unit = "px"
	}
	txt := numberStringWithBudget(q.n, unit, budget)
	return Value{Text: txt, Number: q.n, Known: true}, valueResolved
}
func (p *mathParser) expr(min int) quantity {
	left := p.atom()
	for p.status == valueResolved {
		p.skipSpace()
		if p.at >= len(p.ts) {
			break
		}
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
func (p *mathParser) skipSpace() {
	for p.at < len(p.ts) && (p.ts[p.at].kind == css.WhitespaceToken || p.ts[p.at].kind == css.CommentToken) {
		p.at++
	}
}
func (p *mathParser) atom() quantity {
	p.skipSpace()
	if p.at >= len(p.ts) {
		p.status = valueInvalid
		return quantity{}
	}

	p.budget.check()

	t := p.ts[p.at]
	literal := p.literals[p.at]
	p.at++
	if t.kind == css.FunctionToken || t.kind == css.LeftParenthesisToken {
		name := asciiLowerWithBudget(t.raw, p.budget)
		if t.kind == css.LeftParenthesisToken {
			name = "calc("
		}
		if name != "calc(" && name != "min(" && name != "max(" && name != "clamp(" {
			p.status = valueUnsupported
			return quantity{}
		}
		p.depth++
		if p.depth > maxCSSValueDepth {
			p.depth--
			p.status = valueUnsupported
			return quantity{}
		}
		var firstThree [3]quantity
		var q quantity
		count := 0
		dimensionsValid := true
		for {
			arg := p.expr(0)
			if p.status != valueResolved {
				p.depth--
				return quantity{}
			}
			if count < 3 {
				firstThree[count] = arg
			}
			if count == 0 {
				q = arg
			} else {
				dimensionsValid = dimensionsValid && q.length == arg.length
				if name == "min(" {
					q.n = math.Min(q.n, arg.n)
				} else if name == "max(" {
					q.n = math.Max(q.n, arg.n)
				}
			}
			count++
			p.skipSpace()
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
		if !dimensionsValid {
			p.status = valueInvalid
		}
		switch name {
		case "calc(":
			if count != 1 {
				p.status = valueInvalid
			}
		case "clamp(":
			if count != 3 {
				p.status = valueInvalid
			} else {
				q.n = math.Max(firstThree[0].n, math.Min(firstThree[1].n, firstThree[2].n))
			}
		}
		return q
	}
	if t.kind == css.NumberToken {
		v, ok := literal.value, literal.valid
		if !ok {
			p.status = valueUnsupported
		}
		return quantity{n: v}
	}
	if t.kind == css.PercentageToken {
		v, ok := literal.value, literal.valid
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
		if literal.unit < 0 {
			p.status = valueUnsupported
			return quantity{}
		}
		unit := lengthUnits[literal.unit]
		v, ok := literal.value, literal.valid
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
