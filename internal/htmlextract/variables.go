package htmlextract

import (
	"errors"
	"io"
	"sort"
	"strings"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
)

// Fixed scope overhead. Map entries use the shared cumulative allocation
// estimate in both the literal fast path and the general dependency graph.
const (
	variableScopeBaseBytes int64 = 256
)

// Maps have a substantial fixed cost even with just one entry. These are
// conservative allowances, not a model of a particular Go map implementation.
const (
	literalVariableScopeBaseBytes int64 = 512
	variableColourMapBaseBytes    int64 = 256
)

const maxCSSValueDepth = 256

type valueToken struct {
	kind css.TokenType
	raw  string
}

func lexValue(s string, budget *cpuGuard) ([]valueToken, valueStatus) {
	// Admit the mutable input copy and lexer setup before constructing either.
	if budget != nil && !budget.reserve(int64(len(s))+1+cssLexerSetupBytes) {
		return nil, valueUnsupported
	}
	limits := css.ResourceLimits{}
	if budget != nil {
		limits.Memory = budget.memory
		limits.ShouldStop = func() bool { return budget.stopNow(true) }
	}
	l := css.NewLexerWithLimits(parse.NewInputString(s), limits)
	var ts []valueToken
	for {
		k, v := l.Next()
		if k == css.ErrorToken {
			if !errors.Is(l.Err(), io.EOF) {
				return nil, valueUnsupported
			}
			break
		}
		if k == css.BadStringToken || k == css.BadURLToken {
			return nil, valueInvalid
		}
		if len(ts) == cap(ts) {
			capacity := 16
			if len(ts) != 0 {
				capacity = len(ts) * 2
			}
			allocation := int64(capacity) * int64(unsafe.Sizeof(valueToken{}))
			if budget != nil && !budget.reserve(allocation) {
				return nil, valueUnsupported
			}
			next := make([]valueToken, len(ts), capacity)
			copy(next, ts)
			ts = next
		}
		if !budget.reserve(int64(len(v))) {
			return nil, valueUnsupported
		}
		ts = append(ts, valueToken{k, string(v)})
	}
	return ts, valueResolved
}
func hasVariables(s string) bool { return hasVariablesWithBudget(s, nil) }
func hasVariablesWithBudget(s string, budget *cpuGuard) bool {
	return containsASCIIFoldWithBudget(s, "var(", budget) || indexByteWithBudget(s, '\\', budget) >= 0
}

func tokensHaveVariables(tokens []valueToken) bool {
	for _, token := range tokens {
		if token.kind == css.FunctionToken && equalASCIIFold(token.raw, "var(") {
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
		if equalASCIIFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}
func tokenText(ts []valueToken) string { return tokenTextWithBudget(ts, nil) }

func tokenTextWithBudget(ts []valueToken, budget *cpuGuard) string {
	var b strings.Builder
	for _, t := range ts {
		if !budget.check() || !writeBudgetedString(&b, t.raw, budget) {
			return ""
		}
	}
	return b.String()
}

// significant compacts a privately owned lexer result. Never pass retained
// declaration tokens: math evaluates those with a whitespace-skipping cursor.
func significant(ts []valueToken, budget *cpuGuard) []valueToken {
	out := ts[:0]
	for _, t := range ts {
		if !budget.check() {
			return nil
		}
		if t.kind != css.WhitespaceToken && t.kind != css.CommentToken {
			out = append(out, t)
		}
	}
	clear(ts[len(out):])
	return out
}

func expectedClosingToken(kind css.TokenType) (css.TokenType, bool) {
	switch kind {
	case css.FunctionToken, css.LeftParenthesisToken:
		return css.RightParenthesisToken, true
	case css.LeftBracketToken:
		return css.RightBracketToken, true
	case css.LeftBraceToken:
		return css.RightBraceToken, true
	default:
		return 0, false
	}
}

func isClosingToken(kind css.TokenType) bool {
	switch kind {
	case css.RightParenthesisToken, css.RightBracketToken, css.RightBraceToken:
		return true
	default:
		return false
	}
}

// advanceDelimiters follows CSS component-value block matching. A closing
// token only closes the corresponding innermost block; a mismatched closer is
// part of that block and must not prematurely close an enclosing function.
func advanceDelimiters(stack []css.TokenType, kind css.TokenType, budget *cpuGuard) ([]css.TokenType, bool) {
	if closer, ok := expectedClosingToken(kind); ok {
		var grown bool
		stack, grown = growSlice(stack, 1, budget.allocationMemory())
		if !grown {
			return stack, false
		}
		return append(stack, closer), false
	}
	if !isClosingToken(kind) {
		return stack, false
	}
	if len(stack) == 0 || stack[len(stack)-1] != kind {
		return stack, false
	}
	return stack[:len(stack)-1], true
}

func closing(ts []valueToken, start int, budget *cpuGuard) int {
	closer, ok := expectedClosingToken(ts[start].kind)
	if !ok {
		return len(ts)
	}
	var initial [1]css.TokenType
	initial[0] = closer
	stack := initial[:]
	for i := start + 1; i < len(ts); i++ {
		if !budget.check() {
			return len(ts)
		}
		var matched bool
		stack, matched = advanceDelimiters(stack, ts[i].kind, budget)
		if matched && len(stack) == 0 {
			return i
		}
	}
	// CSS automatically closes an open function at end of input.
	return len(ts)
}

// validVariableFunctions validates the grammar of every var() reference in a
// custom-property value. CSS requires a custom-property declaration containing
// a malformed var() to be ignored rather than allowed to win the cascade.
func validVariableFunctions(ts []valueToken, budget *cpuGuard) bool {
	type frame struct {
		variable    bool
		fallback    bool
		name        valueToken
		nameTokens  int
		invalidName bool
		closer      css.TokenType
	}
	var stack []frame
	validName := func(f frame) bool {
		if f.invalidName || f.nameTokens != 1 || (f.name.kind != css.IdentToken && f.name.kind != css.CustomPropertyNameToken) {
			return false
		}
		decoded := cssUnescapeWithBudget(f.name.raw, budget)
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
		if !budget.check() {
			return false
		}
		switch token.kind {
		case css.FunctionToken:
			// A nested function before a var()'s comma is part of its name
			// grammar and therefore makes that name invalid.
			addNameToken(token)
			var ok bool
			stack, ok = growSlice(stack, 1, budget.allocationMemory())
			if !ok {
				return false
			}
			stack = append(stack, frame{variable: equalASCIIFold(token.raw, "var("), closer: css.RightParenthesisToken})
		case css.LeftParenthesisToken, css.LeftBracketToken, css.LeftBraceToken:
			addNameToken(token)
			closer, _ := expectedClosingToken(token.kind)
			var ok bool
			stack, ok = growSlice(stack, 1, budget.allocationMemory())
			if !ok {
				return false
			}
			stack = append(stack, frame{closer: closer})
		case css.RightParenthesisToken, css.RightBracketToken, css.RightBraceToken:
			if len(stack) == 0 || stack[len(stack)-1].closer != token.kind {
				addNameToken(token)
				continue
			}
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
func variableRefs(ts []valueToken, budget *cpuGuard) []string {
	var out []string
	for i, t := range ts {
		if !budget.check() {
			return nil
		}
		if t.kind == css.FunctionToken && equalASCIIFold(t.raw, "var(") {
			j := i + 1
			for j < len(ts) && (ts[j].kind == css.WhitespaceToken || ts[j].kind == css.CommentToken) {
				j++
			}
			if j < len(ts) {
				var ok bool
				out, ok = growSlice(out, 1, budget.allocationMemory())
				if !ok {
					return nil
				}
				out = append(out, cssUnescapeWithBudget(ts[j].raw, budget))
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
	parent              *variableScope
	values              map[string]variableValue
	colourDependent     map[string]bool
	hasColourDependency bool
	allUnresolved       bool
}

func (s *variableScope) get(name string, budget *cpuGuard) variableValue {
	for ; s != nil; s = s.parent {
		if !budget.check() {
			return variableValue{status: valueUnsupported}
		}
		if s.allUnresolved {
			return variableValue{status: valueUnsupported}
		}
		if v, ok := s.values[name]; ok {
			return v
		}
	}
	return variableValue{status: valueInvalid}
}

func (s *variableScope) colourSchemeDependent(name string, budget *cpuGuard) bool {
	for ; s != nil; s = s.parent {
		if !budget.check() {
			// Exhaustion cannot prove that no inherited definition is
			// colour-scheme dependent, so preserve the uncertainty.
			return true
		}
		if s.allUnresolved {
			return true
		}
		if dependent, ok := s.colourDependent[name]; ok {
			return dependent
		}
	}
	return false
}

func unresolvedVariableScope(parent *variableScope) *variableScope {
	// Once variable evaluation has been abandoned, treating every lookup as
	// unresolved is conservative and avoids copying an attacker-sized set of
	// property names on the resource-exhaustion path.
	return &variableScope{parent: parent, hasColourDependency: true, allUnresolved: true}
}

// buildLiteralVariables handles scopes whose winning custom properties cannot
// refer to other variables. Their values form no dependency graph, so sorting,
// cycle detection and token-by-token substitution would only reproduce the
// already prepared literal text. The boolean reports whether this fast path
// was applicable, including when its own bounded work was exhausted.
func buildLiteralVariables(parent *variableScope, defs map[string]candidate, alternate map[string]bool, budget *cpuGuard) (*variableScope, bool) {
	for _, definition := range defs {
		d := definition.d
		if d == nil || !d.tokensReady || d.valueStatus != valueResolved || d.unsupported || definition.uncertainOrigin || d.hasVars || len(d.variableDependencies) != 0 {
			return nil, false
		}
	}
	if !budget.check() {
		return unresolvedVariableScope(parent), true
	}
	if !budget.reserve(int64(len(defs))*mapEntryAllocationBytes[string, variableValue]() + literalVariableScopeBaseBytes) {
		return unresolvedVariableScope(parent), true
	}
	s := &variableScope{parent: parent, hasColourDependency: parent != nil && parent.hasColourDependency, values: make(map[string]variableValue, len(defs))}
	for name, definition := range defs {
		d := definition.d
		var value variableValue
		switch d.keyword {
		case "inherit", "unset":
			value = parent.get(name, budget)
		case "initial":
			value = variableValue{status: valueInvalid}
		case "revert", "revert-layer":
			value = variableValue{status: valueUnsupported}
		default:
			value = variableValue{text: trimCSSWhitespace(d.value), status: valueResolved}
		}
		s.values[name] = value
		if budget.stopped {
			return unresolvedVariableScope(parent), true
		}
	}

	// With no alternate definitions and no inherited dependency, every local
	// literal is colour-scheme independent and a nil map answers that directly.
	if len(alternate) == 0 && (parent == nil || !parent.hasColourDependency) {
		return s, true
	}
	if !budget.check() {
		return unresolvedVariableScope(parent), true
	}
	if !budget.reserve(int64(len(defs)+len(alternate))*mapEntryAllocationBytes[string, bool]() + variableColourMapBaseBytes) {
		return unresolvedVariableScope(parent), true
	}
	s.colourDependent = make(map[string]bool, len(defs)+len(alternate))
	for name := range alternate {
		s.colourDependent[name] = true
		s.hasColourDependency = true
	}
	for name, definition := range defs {
		dependent := alternate[name]
		if !dependent && (definition.d.keyword == "inherit" || definition.d.keyword == "unset") {
			dependent = parent.colourSchemeDependent(name, budget)
		}
		s.colourDependent[name] = dependent
		s.hasColourDependency = s.hasColourDependency || dependent
	}
	return s, true
}

// A scope stores only this element's computed overrides. Parent references have
// already been substituted, so a child's --b cannot change inherited --a:var(--b).
func buildVariables(parent *variableScope, defs map[string]candidate, alternate map[string]bool, budget *cpuGuard) *variableScope {
	if len(defs) == 0 && len(alternate) == 0 {
		return parent
	}
	if !budget.check() {
		return unresolvedVariableScope(parent)
	}
	if scope, ok := buildLiteralVariables(parent, defs, alternate, budget); ok {
		return scope
	}
	// Admit the four dependency maps and both string-index arrays before
	// constructing them. The colour-dependency map has separate admission below.
	definitionBytes := mapEntryAllocationBytes[string, variableValue]() +
		mapEntryAllocationBytes[string, []valueToken]() +
		mapEntryAllocationBytes[string, bool]() +
		mapEntryAllocationBytes[string, uint8]() + int64(unsafe.Sizeof([2]string{}))
	if !budget.reserve(int64(len(defs))*definitionBytes + int64(len(alternate))*mapEntryAllocationBytes[string, bool]() + variableScopeBaseBytes) {
		return unresolvedVariableScope(parent)
	}
	s := &variableScope{parent: parent, hasColourDependency: parent != nil && parent.hasColourDependency, values: make(map[string]variableValue, len(defs))}
	ordered := make([]string, 0, len(defs))
	for n := range defs {
		ordered = append(ordered, n)
	}
	if !budget.check() {
		return unresolvedVariableScope(parent)
	}
	sort.Strings(ordered)
	tokens := make(map[string][]valueToken, len(defs))
	cyclic := make(map[string]bool, len(defs))
	states := make(map[string]uint8, len(defs))
	path := make([]string, 0, min(len(defs), maxCSSValueDepth))
	depthExceeded := false
	for _, name := range ordered {
		definition := defs[name]
		d := definition.d
		if !d.tokensReady || d.valueStatus != valueResolved || d.unsupported || definition.uncertainOrigin {
			s.values[name] = variableValue{status: valueUnsupported}
		} else {
			tokens[name] = d.valueTokens
		}
	}
	var visit func(string, int)
	visit = func(n string, depth int) {
		if depth >= maxCSSValueDepth {
			depthExceeded = true
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
		if !budget.check() {
			s.values[n] = variableValue{status: valueUnsupported}
			return
		}
		states[n] = 1
		path = append(path, n)
		definition := defs[n]
		dependencies := definition.d.variableDependencies
		if !definition.d.dependenciesReady {
			dependencies = variableRefs(tokens[n], budget)
		}
		// Cached and missing dependencies still consume work on every edge.
		for _, ref := range dependencies {
			if !budget.check() {
				return
			}
			if _, local := tokens[ref]; local {
				visit(ref, depth+1)
			}
		}
		path = path[:len(path)-1]
		states[n] = 2
	}
	for _, n := range ordered {
		visit(n, 0)
		if budget.stopped || depthExceeded {
			return unresolvedVariableScope(parent)
		}
	}
	for n := range cyclic {
		s.values[n] = variableValue{status: valueInvalid}
	}
	var resolveName func(string, int) variableValue
	resolveName = func(n string, depth int) variableValue {
		if depth >= maxCSSValueDepth {
			return variableValue{status: valueUnsupported}
		}
		if v, ok := s.values[n]; ok {
			return v
		}
		definition, local := defs[n]
		if !local {
			return parent.get(n, budget)
		}
		d := definition.d
		if !budget.check() {
			return variableValue{status: valueUnsupported}
		}
		var v variableValue
		switch d.keyword {
		case "inherit", "unset":
			v = parent.get(n, budget)
		case "initial":
			v = variableValue{status: valueInvalid}
		case "revert", "revert-layer":
			v = variableValue{status: valueUnsupported}
		default:
			v = substituteIndexedTokens(tokens[n], d.variableBlocks, func(ref string) variableValue { return resolveName(ref, depth+1) }, budget, depth)
		}
		s.values[n] = v
		return v
	}
	for _, n := range ordered {
		resolveName(n, 0)
		if budget.stopped {
			return unresolvedVariableScope(parent)
		}
	}
	if len(alternate) == 0 && (parent == nil || !parent.hasColourDependency) {
		return s
	}
	if !budget.reserve(int64(len(defs)+len(alternate))*mapEntryAllocationBytes[string, bool]() + variableColourMapBaseBytes) {
		return unresolvedVariableScope(parent)
	}
	s.colourDependent = make(map[string]bool, len(defs)+len(alternate))
	// Cycle detection is complete; reuse its scratch map for colour dependencies.
	clear(states)
	dependencyState := states
	var dependsOnColourScheme func(string, int) bool
	dependsOnColourScheme = func(name string, depth int) bool {
		if depth >= maxCSSValueDepth {
			return true
		}
		if dependencyState[name] == 2 {
			return s.colourDependent[name]
		}
		if alternate[name] {
			s.colourDependent[name] = true
			s.hasColourDependency = true
			return true
		}
		if dependencyState[name] == 1 {
			return false
		}
		definition, local := defs[name]
		if !local {
			return parent.colourSchemeDependent(name, budget)
		}
		if !budget.check() {
			s.colourDependent[name] = true
			s.hasColourDependency = true
			return true
		}
		dependencyState[name] = 1
		dependent := false
		switch definition.d.keyword {
		case "inherit", "unset":
			dependent = parent.colourSchemeDependent(name, budget)
		default:
			for _, ref := range definition.d.variableDependencies {
				if !budget.check() {
					return true
				}
				if dependsOnColourScheme(ref, depth+1) {
					dependent = true
				}
			}
		}
		dependencyState[name] = 2
		s.colourDependent[name] = dependent
		s.hasColourDependency = s.hasColourDependency || dependent
		return dependent
	}
	for name := range alternate {
		if _, local := defs[name]; !local {
			s.colourDependent[name] = true
			s.hasColourDependency = true
		}
	}
	for _, name := range ordered {
		dependsOnColourScheme(name, 0)
	}
	return s
}

func substitute(d *declaration, vars *variableScope, budget *cpuGuard) variableValue {
	if !d.hasVars {
		return variableValue{d.value, valueResolved}
	}
	if !d.tokensReady || d.valueStatus != valueResolved {
		return variableValue{status: d.valueStatus}
	}
	return substituteIndexedTokens(d.valueTokens, d.variableBlocks, func(name string) variableValue {
		return vars.get(name, budget)
	}, budget, 0)
}

// valueBlock records component-value boundaries in one pass. Mismatched
// closing tokens remain inside their current block; EOF implicitly closes it.
type valueBlock struct {
	end, comma int
	// Decode the immutable variable reference once, not on every element.
	name string
}

func indexValueBlocks(ts []valueToken, budget *cpuGuard) ([]valueBlock, bool) {
	if !budget.reserve(int64(len(ts)) * int64(unsafe.Sizeof(valueBlock{}))) {
		return nil, false
	}
	blocks := make([]valueBlock, len(ts))
	var stack []int
	for i, t := range ts {
		if !budget.check() {
			return nil, false
		}
		if _, open := expectedClosingToken(t.kind); open {
			blocks[i] = valueBlock{end: len(ts), comma: -1}
			var ok bool
			stack, ok = growSlice(stack, 1, budget.allocationMemory())
			if !ok {
				return nil, false
			}
			stack = append(stack, i)
		} else if len(stack) > 0 {
			top := stack[len(stack)-1]
			closer, _ := expectedClosingToken(ts[top].kind)
			if t.kind == closer {
				blocks[top].end = i
				stack = stack[:len(stack)-1]
			} else if t.kind == css.CommaToken && blocks[top].comma < 0 {
				blocks[top].comma = i
			}
		}
	}
	for i, token := range ts {
		if !budget.check() {
			return nil, false
		}
		if token.kind != css.FunctionToken || !equalASCIIFold(token.raw, "var(") {
			continue
		}
		end := blocks[i].end
		if blocks[i].comma >= 0 {
			end = blocks[i].comma
		}
		var name valueToken
		count := 0
		for j := i + 1; j < end; j++ {
			if !budget.check() {
				return nil, false
			}
			if ts[j].kind != css.WhitespaceToken && ts[j].kind != css.CommentToken {
				name = ts[j]
				count++
				if count > 1 {
					break
				}
			}
		}
		if count == 1 && (name.kind == css.IdentToken || name.kind == css.CustomPropertyNameToken) {
			blocks[i].name = cssUnescapeWithBudget(name.raw, budget)
		}
	}
	if budget.stopNow(false) {
		return nil, false
	}
	return blocks, true
}

func substituteTokens(ts []valueToken, lookup func(string) variableValue, budget *cpuGuard, depth int) variableValue {
	return substituteIndexedTokens(ts, nil, lookup, budget, depth)
}
func substituteIndexedTokens(ts []valueToken, blocks []valueBlock, lookup func(string) variableValue, budget *cpuGuard, depth int) variableValue {
	if depth >= maxCSSValueDepth || !budget.check() {
		return variableValue{status: valueUnsupported}
	}
	if len(blocks) != len(ts) {
		var ok bool
		blocks, ok = indexValueBlocks(ts, budget)
		if !ok {
			return variableValue{status: valueUnsupported}
		}
	}
	var expand func(int, int, int) variableValue
	expand = func(start, limit, depth int) variableValue {
		if depth >= maxCSSValueDepth || !budget.check() {
			return variableValue{status: valueUnsupported}
		}
		var out strings.Builder
		for i := start; i < limit; i++ {
			if !budget.check() {
				return variableValue{status: valueUnsupported}
			}
			t := ts[i]
			if t.kind != css.FunctionToken || !equalASCIIFold(t.raw, "var(") {
				if !writeBudgetedString(&out, t.raw, budget) {
					return variableValue{status: valueUnsupported}
				}
				continue
			}
			end, comma := blocks[i].end, blocks[i].comma
			name := blocks[i].name
			if !strings.HasPrefix(name, "--") || name == "--" {
				return variableValue{status: valueInvalid}
			}
			v := lookup(name)
			if v.status == valueInvalid && comma >= 0 {
				v = expand(comma+1, end, depth+1)
			}
			if v.status != valueResolved {
				return v
			}
			if !budget.check() || !writeBudgetedString(&out, " ", budget) ||
				!writeBudgetedString(&out, v.text, budget) || !writeBudgetedString(&out, " ", budget) {
				return variableValue{status: valueUnsupported}
			}
			i = end
		}
		text, ok := trimCSSWhitespaceWithBudget(out.String(), budget)
		if !ok {
			return variableValue{status: valueUnsupported}
		}
		return variableValue{text, valueResolved}
	}
	return expand(0, len(ts), depth)
}
