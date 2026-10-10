package htmlextract

import (
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"sort"
	"strings"
)

const maxValueBytes = 16384
const maxValueTokens = 4096
const maxExpressionDepth = 32

type valueToken struct {
	kind css.TokenType
	raw  string
}
type expressionBudget struct {
	remaining int64
	exhausted bool
}

func (b *expressionBudget) charge(n int) bool {
	if b.exhausted {
		return false
	}
	b.remaining -= int64(n)
	if b.remaining < 0 {
		b.exhausted = true
		return false
	}
	return true
}
func lexValue(s string) ([]valueToken, int) {
	if len(s) > maxValueBytes {
		return nil, 2
	}
	l := css.NewLexer(parse.NewInputString(s))
	var ts []valueToken
	for {
		k, v := l.Next()
		if k == css.ErrorToken {
			break
		}
		if len(ts) >= maxValueTokens {
			return nil, 2
		}
		if k == css.BadStringToken || k == css.BadURLToken {
			return nil, 0
		}
		ts = append(ts, valueToken{k, string(v)})
	}
	return ts, 1
}
func hasVariables(s string) bool {
	return strings.Contains(strings.ToLower(s), "var(") || strings.Contains(s, "\\")
}
func tokenText(ts []valueToken) string {
	var b strings.Builder
	for _, t := range ts {
		b.WriteString(t.raw)
	}
	return b.String()
}
func significant(ts []valueToken) []valueToken {
	var out []valueToken
	for _, t := range ts {
		if t.kind != css.WhitespaceToken && t.kind != css.CommentToken {
			out = append(out, t)
		}
	}
	return out
}
func closing(ts []valueToken, start int) int {
	depth := 1
	for i := start + 1; i < len(ts); i++ {
		switch ts[i].kind {
		case css.FunctionToken, css.LeftParenthesisToken:
			depth++
		case css.RightParenthesisToken:
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// Includes fallback dependencies even when the fallback would not be used.
func variableRefs(ts []valueToken) []string {
	var out []string
	for i, t := range ts {
		if t.kind == css.FunctionToken && strings.EqualFold(t.raw, "var(") {
			j := i + 1
			for j < len(ts) && (ts[j].kind == css.WhitespaceToken || ts[j].kind == css.CommentToken) {
				j++
			}
			if j < len(ts) {
				out = append(out, ts[j].raw)
			}
		}
	}
	return out
}

type variableValue struct {
	text   string
	status int
}
type variableScope struct {
	parent *variableScope
	values map[string]variableValue
}

func (s *variableScope) get(name string) variableValue {
	for ; s != nil; s = s.parent {
		if v, ok := s.values[name]; ok {
			return v
		}
	}
	return variableValue{status: 0}
}

// A scope stores only this element's computed overrides. Parent references have
// already been substituted, so a child's --b cannot change inherited --a:var(--b).
func buildVariables(parent *variableScope, defs map[string]declaration, budget *expressionBudget) *variableScope {
	if len(defs) == 0 {
		return parent
	}
	s := &variableScope{parent: parent, values: make(map[string]variableValue)}
	if len(defs) > 1024 {
		for n := range defs {
			s.values[n] = variableValue{status: 2}
		}
		return s
	}
	var ordered []string
	for n := range defs {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	tokens := map[string][]valueToken{}
	cyclic := map[string]bool{}
	states := map[string]uint8{}
	var path []string
	for _, name := range ordered {
		d := defs[name]
		ts, status := lexValue(d.value)
		if status != 1 || d.unsupported {
			s.values[name] = variableValue{status: 2}
		} else {
			tokens[name] = ts
		}
	}
	var visit func(string, int)
	visit = func(n string, depth int) {
		if depth > maxExpressionDepth || !budget.charge(1) {
			s.values[n] = variableValue{status: 2}
			return
		}
		if states[n] == 2 {
			return
		}
		if states[n] == 1 {
			for i, x := range path {
				if x == n {
					for _, y := range path[i:] {
						cyclic[y] = true
					}
					break
				}
			}
			return
		}
		states[n] = 1
		path = append(path, n)
		for _, ref := range variableRefs(tokens[n]) {
			if _, local := tokens[ref]; local {
				visit(ref, depth+1)
			}
		}
		path = path[:len(path)-1]
		states[n] = 2
	}
	for _, n := range ordered {
		visit(n, 0)
	}
	for n := range cyclic {
		s.values[n] = variableValue{status: 0}
	}
	var resolveName func(string, int) variableValue
	resolveName = func(n string, depth int) variableValue {
		if v, ok := s.values[n]; ok {
			return v
		}
		d, local := defs[n]
		if !local {
			return parent.get(n)
		}
		if depth > maxExpressionDepth {
			return variableValue{status: 2}
		}
		var v variableValue
		switch strings.ToLower(strings.TrimSpace(d.value)) {
		case "inherit", "unset":
			v = parent.get(n)
		case "initial":
			v = variableValue{status: 0}
		case "revert", "revert-layer":
			v = variableValue{status: 2}
		default:
			v = substituteTokens(tokens[n], func(ref string) variableValue { return resolveName(ref, depth+1) }, budget, depth)
		}
		s.values[n] = v
		return v
	}
	for _, n := range ordered {
		resolveName(n, 0)
	}
	return s
}
func substitute(s string, vars *variableScope, budget *expressionBudget) variableValue {
	if !hasVariables(s) {
		return variableValue{s, 1}
	}
	// Escaped identifiers require CSS unescaping beyond this bounded subset.
	if strings.Contains(s, "\\") {
		return variableValue{status: 2}
	}
	ts, status := lexValue(s)
	if status != 1 {
		return variableValue{status: status}
	}
	return substituteTokens(ts, vars.get, budget, 0)
}
func substituteTokens(ts []valueToken, lookup func(string) variableValue, budget *expressionBudget, depth int) variableValue {
	if depth > maxExpressionDepth || !budget.charge(len(ts)) {
		return variableValue{status: 2}
	}
	var out strings.Builder
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		if t.kind != css.FunctionToken || !strings.EqualFold(t.raw, "var(") {
			out.WriteString(t.raw)
		} else {
			end := closing(ts, i)
			if end < 0 {
				return variableValue{status: 0}
			}
			inner := ts[i+1 : end]
			comma := -1
			level := 0
			for j, v := range inner {
				switch v.kind {
				case css.FunctionToken, css.LeftParenthesisToken:
					level++
				case css.RightParenthesisToken:
					level--
				case css.CommaToken:
					if level == 0 && comma < 0 {
						comma = j
					}
				}
			}
			nameTokens := inner
			if comma >= 0 {
				nameTokens = inner[:comma]
			}
			nameTokens = significant(nameTokens)
			if len(nameTokens) != 1 || !strings.HasPrefix(nameTokens[0].raw, "--") || nameTokens[0].raw == "--" {
				return variableValue{status: 0}
			}
			v := lookup(nameTokens[0].raw)
			if v.status == 0 && comma >= 0 {
				v = substituteTokens(inner[comma+1:], lookup, budget, depth+1)
			}
			if v.status != 1 {
				return v
			}
			if !budget.charge(len(v.text)) {
				return variableValue{status: 2}
			}
			// Whitespace prevents token concatenation such as var(--n)px.
			out.WriteByte(' ')
			out.WriteString(v.text)
			out.WriteByte(' ')
			i = end
		}
		if out.Len() > maxValueBytes {
			return variableValue{status: 2}
		}
	}
	return variableValue{strings.TrimSpace(out.String()), 1}
}
