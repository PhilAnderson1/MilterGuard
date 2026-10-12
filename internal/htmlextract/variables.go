package htmlextract

import (
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
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
func lexValue(s string) ([]valueToken, valueStatus) {
	if len(s) > maxValueBytes {
		return nil, valueUnsupported
	}
	l := css.NewLexer(parse.NewInputString(s))
	var ts []valueToken
	for {
		k, v := l.Next()
		if k == css.ErrorToken {
			if !errors.Is(l.Err(), io.EOF) {
				return nil, valueUnsupported
			}
			break
		}
		if len(ts) >= maxValueTokens {
			return nil, valueUnsupported
		}
		if k == css.BadStringToken || k == css.BadURLToken {
			return nil, valueInvalid
		}
		ts = append(ts, valueToken{k, string(v)})
	}
	return ts, valueResolved
}
func hasVariables(s string) bool {
	return containsFold(s, "var(") || strings.Contains(s, "\\")
}

func tokensHaveVariables(tokens []valueToken) bool {
	for _, token := range tokens {
		if token.kind == css.FunctionToken && strings.EqualFold(token.raw, "var(") {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
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
	// CSS automatically closes an open function at end of input.
	return len(ts)
}

// validVariableFunctions validates the grammar of every var() reference in a
// custom-property value. CSS requires a custom-property declaration containing
// a malformed var() to be ignored rather than allowed to win the cascade.
func validVariableFunctions(ts []valueToken) bool {
	type frame struct {
		variable    bool
		fallback    bool
		name        valueToken
		nameTokens  int
		invalidName bool
	}
	var stack []frame
	validName := func(f frame) bool {
		if f.invalidName || f.nameTokens != 1 || (f.name.kind != css.IdentToken && f.name.kind != css.CustomPropertyNameToken) {
			return false
		}
		decoded := cssUnescape(f.name.raw)
		return strings.HasPrefix(decoded, "--") && decoded != "--"
	}
	addNameToken := func(token valueToken) {
		if len(stack) == 0 || !stack[len(stack)-1].variable || stack[len(stack)-1].fallback {
			return
		}
		f := &stack[len(stack)-1]
		if token.kind == css.WhitespaceToken || token.kind == css.CommentToken {
			return
		}
		f.nameTokens++
		if f.nameTokens == 1 {
			f.name = token
		} else {
			f.invalidName = true
		}
	}
	closeFrame := func() bool {
		if len(stack) == 0 {
			return true
		}
		last := len(stack) - 1
		f := stack[last]
		stack = stack[:last]
		return !f.variable || validName(f)
	}

	for _, token := range ts {
		switch token.kind {
		case css.FunctionToken:
			// A nested function before a var()'s comma is part of its name
			// grammar and therefore makes that name invalid.
			addNameToken(token)
			stack = append(stack, frame{variable: strings.EqualFold(token.raw, "var(")})
		case css.LeftParenthesisToken:
			addNameToken(token)
			stack = append(stack, frame{})
		case css.RightParenthesisToken:
			if !closeFrame() {
				return false
			}
		case css.CommaToken:
			if len(stack) > 0 && stack[len(stack)-1].variable && !stack[len(stack)-1].fallback {
				stack[len(stack)-1].fallback = true
			} else {
				addNameToken(token)
			}
		default:
			addNameToken(token)
		}
	}
	// CSS automatically closes open functions at the end of a declaration.
	for len(stack) > 0 {
		if !closeFrame() {
			return false
		}
	}
	return true
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
				out = append(out, cssUnescape(ts[j].raw))
			}
		}
	}
	return out
}

type variableValue struct {
	text   string
	status valueStatus
}
type variableScope struct {
	parent     *variableScope
	values     map[string]variableValue
	unresolved map[string]variableDefinition
}

type variableDefinition struct {
	declaration     *declaration
	uncertainOrigin bool
}

func (s *variableScope) get(name string) variableValue {
	for ; s != nil; s = s.parent {
		if v, ok := s.values[name]; ok {
			return v
		}
		if _, ok := s.unresolved[name]; ok {
			return variableValue{status: valueUnsupported}
		}
	}
	return variableValue{status: valueInvalid}
}

func unresolvedVariableScope(parent *variableScope, defs map[string]variableDefinition) *variableScope {
	return &variableScope{parent: parent, unresolved: defs}
}

// A scope stores only this element's computed overrides. Parent references have
// already been substituted, so a child's --b cannot change inherited --a:var(--b).
func buildVariables(parent *variableScope, defs map[string]variableDefinition, budget *expressionBudget) *variableScope {
	if len(defs) == 0 {
		return parent
	}
	if len(defs) > 1024 || !budget.charge(len(defs)) {
		return unresolvedVariableScope(parent, defs)
	}
	s := &variableScope{parent: parent, values: make(map[string]variableValue)}
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
		definition := defs[name]
		d := definition.declaration
		if !d.tokensReady || d.valueStatus != valueResolved || d.unsupported || definition.uncertainOrigin {
			s.values[name] = variableValue{status: valueUnsupported}
		} else {
			tokens[name] = d.valueTokens
		}
	}
	var visit func(string, int)
	visit = func(n string, depth int) {
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
		if depth > maxExpressionDepth || !budget.charge(1+len(tokens[n])) {
			s.values[n] = variableValue{status: valueUnsupported}
			return
		}
		states[n] = 1
		path = append(path, n)
		definition := defs[n]
		dependencies := definition.declaration.variableDependencies
		if !definition.declaration.dependenciesReady {
			dependencies = variableRefs(tokens[n])
		}
		for _, ref := range dependencies {
			if _, local := tokens[ref]; local {
				visit(ref, depth+1)
			}
		}
		path = path[:len(path)-1]
		states[n] = 2
	}
	for _, n := range ordered {
		visit(n, 0)
		if budget.exhausted {
			return unresolvedVariableScope(parent, defs)
		}
	}
	for n := range cyclic {
		s.values[n] = variableValue{status: valueInvalid}
	}
	var resolveName func(string, int) variableValue
	resolveName = func(n string, depth int) variableValue {
		if v, ok := s.values[n]; ok {
			return v
		}
		definition, local := defs[n]
		if !local {
			return parent.get(n)
		}
		d := definition.declaration
		if depth > maxExpressionDepth {
			return variableValue{status: valueUnsupported}
		}
		var v variableValue
		switch d.keyword {
		case "inherit", "unset":
			v = parent.get(n)
		case "initial":
			v = variableValue{status: valueInvalid}
		case "revert", "revert-layer":
			v = variableValue{status: valueUnsupported}
		default:
			v = substituteTokens(tokens[n], func(ref string) variableValue { return resolveName(ref, depth+1) }, budget, depth)
		}
		s.values[n] = v
		return v
	}
	for _, n := range ordered {
		resolveName(n, 0)
		if budget.exhausted {
			return unresolvedVariableScope(parent, defs)
		}
	}
	return s
}
func substitute(d *declaration, vars *variableScope, budget *expressionBudget) variableValue {
	if !d.hasVars {
		return variableValue{d.value, valueResolved}
	}
	if !d.tokensReady || d.valueStatus != valueResolved {
		return variableValue{status: d.valueStatus}
	}
	return substituteTokens(d.valueTokens, vars.get, budget, 0)
}
func substituteTokens(ts []valueToken, lookup func(string) variableValue, budget *expressionBudget, depth int) variableValue {
	if depth > maxExpressionDepth || !budget.charge(len(ts)) {
		return variableValue{status: valueUnsupported}
	}
	var out strings.Builder
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		if t.kind != css.FunctionToken || !strings.EqualFold(t.raw, "var(") {
			out.WriteString(t.raw)
		} else {
			end := closing(ts, i)
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
			if len(nameTokens) != 1 || (nameTokens[0].kind != css.IdentToken && nameTokens[0].kind != css.CustomPropertyNameToken) {
				return variableValue{status: valueInvalid}
			}
			name := cssUnescape(nameTokens[0].raw)
			if !strings.HasPrefix(name, "--") || name == "--" {
				return variableValue{status: valueInvalid}
			}
			v := lookup(name)
			if v.status == valueInvalid && comma >= 0 {
				v = substituteTokens(inner[comma+1:], lookup, budget, depth+1)
			}
			if v.status != valueResolved {
				return v
			}
			if !budget.charge(len(v.text)) {
				return variableValue{status: valueUnsupported}
			}
			// Whitespace prevents token concatenation such as var(--n)px.
			out.WriteByte(' ')
			out.WriteString(v.text)
			out.WriteByte(' ')
			i = end
		}
		if out.Len() > maxValueBytes {
			return variableValue{status: valueUnsupported}
		}
	}
	return variableValue{strings.TrimSpace(out.String()), valueResolved}
}
