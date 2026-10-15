package htmlextract

import (
	"errors"
	"io"
	"math/bits"
	"sort"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
)

const maxValueBytes = 16384
const maxValueTokens = 4096
const maxExpressionDepth = 32

type valueToken struct {
	kind css.TokenType
	raw  string
}
type expressionBudget struct {
	remaining          int64
	exhausted          bool
	depthLimitExceeded bool
}

func (b *expressionBudget) rejectDepth() {
	b.depthLimitExceeded = true
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
func advanceDelimiters(stack []css.TokenType, kind css.TokenType) ([]css.TokenType, bool) {
	if closer, ok := expectedClosingToken(kind); ok {
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

// parserCompatibleCSS preserves CSS token boundaries that the syntax parser
// otherwise loses and works around a recovery divergence for a closing
// parenthesis inside a nested [] or {} component block. Comments separate
// selector tokens, but the parser drops them before exposing the selector;
// replacing lexer-recognized comments with whitespace prevents adjacent token
// text from being joined into a different selector. Escaping only a mismatched
// nested delimiter preserves its character value while allowing the parser to
// expose the declaration to our component-value evaluator. Ordinary CSS takes
// the allocation-free fast path.
type cssParserCompatibility struct {
	text                            string
	insertedRightParenthesisEscapes []int
	stopped                         bool
}

func parserCompatibleCSS(text string, shouldStop func() bool) cssParserCompatibility {
	hasComments := strings.Contains(text, "/*")
	needsDelimiterCompatibility := containsFold(text, "var(") && strings.Contains(text, ")") && (strings.Contains(text, "[") || strings.Contains(text, "{"))
	if !hasComments && !needsDelimiterCompatibility {
		return cssParserCompatibility{text: text}
	}
	input := parse.NewInputString(text)
	if shouldStop != nil {
		input.SetProgressCheck(func() error {
			if shouldStop() {
				return css.ErrResourceStopped
			}
			return nil
		})
	}
	l := css.NewLexer(input)
	var stack []css.TokenType
	var b strings.Builder
	var insertedRightParenthesisEscapes []int
	changed := false
	parenthesisBlocks := 0
	offset := 0
	for {
		kind, raw := l.Next()
		if kind == css.ErrorToken {
			if !errors.Is(l.Err(), io.EOF) {
				if errors.Is(l.Err(), css.ErrResourceStopped) {
					return cssParserCompatibility{text: text, stopped: true}
				}
				return cssParserCompatibility{text: text}
			}
			break
		}
		if kind == css.CommentToken {
			if !changed {
				b.Grow(len(text) + 1)
				b.WriteString(text[:offset])
				changed = true
			}
			// Preserve the source width. Ordinary parser paths collapse this
			// whitespace, while custom-property values retain it, allowing the
			// parser's construct-byte guard to charge the original comment size.
			for range raw {
				b.WriteByte(' ')
			}
			offset += len(raw)
			continue
		}
		if kind == css.RightParenthesisToken && len(stack) > 0 && stack[len(stack)-1] != kind && parenthesisBlocks > 0 {
			if !changed {
				b.Grow(len(text) + 1)
				b.WriteString(text[:offset])
				changed = true
			}
			if changed {
				insertedRightParenthesisEscapes = append(insertedRightParenthesisEscapes, b.Len())
				b.WriteByte('\\')
			}
		}
		if changed {
			b.Write(raw)
		}
		offset += len(raw)
		if closer, ok := expectedClosingToken(kind); ok && closer == css.RightParenthesisToken {
			parenthesisBlocks++
		}
		var matched bool
		stack, matched = advanceDelimiters(stack, kind)
		if matched && kind == css.RightParenthesisToken {
			parenthesisBlocks--
		}
	}
	if !changed {
		return cssParserCompatibility{text: text}
	}
	return cssParserCompatibility{text: b.String(), insertedRightParenthesisEscapes: insertedRightParenthesisEscapes}
}

// declarationProperty restores the author-written spelling of an escaped
// custom-property name. The CSS parser lowercases declaration names before it
// decodes escapes, which can change the case-sensitive name (for example,
// \2d\2dX becomes --x instead of --X). Re-lexing the bounded grammar span
// preserves escape boundaries, including an escaped colon within the name.
func (c cssParserCompatibility) declarationProperty(parsed string, grammarStart, grammarEnd int) (string, bool) {
	property := normalizeDeclarationProperty(parsed)
	if !strings.HasPrefix(property, "--") || !strings.Contains(parsed, `\`) {
		return property, true
	}
	if grammarStart < 0 || grammarEnd > len(c.text) || grammarStart >= grammarEnd {
		return property, false
	}
	l := css.NewLexer(parse.NewInputString(c.text[grammarStart:grammarEnd]))
	var name []byte
	for {
		kind, raw := l.Next()
		switch kind {
		case css.WhitespaceToken, css.CommentToken, css.SemicolonToken:
			continue
		case css.IdentToken, css.CustomPropertyNameToken:
			name = raw
		default:
			return property, false
		}
		break
	}
	for {
		kind, _ := l.Next()
		if kind == css.WhitespaceToken || kind == css.CommentToken {
			continue
		}
		if kind != css.ColonToken {
			return property, false
		}
		break
	}
	property = normalizeDeclarationProperty(string(name))
	if !strings.HasPrefix(property, "--") {
		return property, false
	}
	return property, true
}

// restoreDeclarationValue removes only escapes inserted by
// parserCompatibleCSS. Author-written escapes can occur in strings, URLs and
// custom properties and must remain byte-for-byte intact. Parser offsets bound
// the source grammar; occurrence order maps that span to rawTokenString's value
// without requiring the parser to expose individual token offsets.
func (c cssParserCompatibility) restoreDeclarationValue(value string, grammarStart, grammarEnd int) (string, bool, bool) {
	if len(c.insertedRightParenthesisEscapes) == 0 {
		return value, false, true
	}
	if grammarStart < 0 || grammarEnd > len(c.text) || grammarStart >= grammarEnd {
		return value, false, false
	}
	span := c.text[grammarStart:grammarEnd]
	colon := strings.IndexByte(span, ':')
	if colon < 0 {
		return value, false, false
	}
	valueStart := grammarStart + colon + 1
	first := sort.SearchInts(c.insertedRightParenthesisEscapes, valueStart)
	last := sort.SearchInts(c.insertedRightParenthesisEscapes, grammarEnd)
	if first == last {
		return value, false, true
	}
	inserted := c.insertedRightParenthesisEscapes[first:last]
	flags := make([]bool, 0, strings.Count(c.text[valueStart:grammarEnd], `\)`))
	insertedIndex, insertedSeen := 0, 0
	for offset := valueStart; offset+1 < grammarEnd; {
		relative := strings.Index(c.text[offset:grammarEnd], `\)`)
		if relative < 0 {
			break
		}
		offset += relative
		for insertedIndex < len(inserted) && inserted[insertedIndex] < offset {
			insertedIndex++
		}
		wasInserted := insertedIndex < len(inserted) && inserted[insertedIndex] == offset
		flags = append(flags, wasInserted)
		if wasInserted {
			insertedIndex++
			insertedSeen++
		}
		offset += 2
	}
	if insertedSeen != len(inserted) || len(flags) == 0 {
		return value, false, false
	}

	var restored strings.Builder
	restored.Grow(len(value))
	valueOffset, occurrence := 0, 0
	for valueOffset < len(value) {
		relative := strings.Index(value[valueOffset:], `\)`)
		if relative < 0 {
			break
		}
		relative += valueOffset
		if occurrence >= len(flags) {
			return value, false, false
		}
		restored.WriteString(value[valueOffset:relative])
		if flags[occurrence] {
			restored.WriteByte(')')
		} else {
			restored.WriteString(`\)`)
		}
		occurrence++
		valueOffset = relative + 2
	}
	if occurrence != len(flags) {
		return value, false, false
	}
	restored.WriteString(value[valueOffset:])
	return restored.String(), true, true
}

func closing(ts []valueToken, start int) int {
	closer, ok := expectedClosingToken(ts[start].kind)
	if !ok {
		return len(ts)
	}
	stack := []css.TokenType{closer}
	for i := start + 1; i < len(ts); i++ {
		var matched bool
		stack, matched = advanceDelimiters(stack, ts[i].kind)
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
func validVariableFunctions(ts []valueToken) bool {
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
			stack = append(stack, frame{variable: equalASCIIFold(token.raw, "var("), closer: css.RightParenthesisToken})
		case css.LeftParenthesisToken, css.LeftBracketToken, css.LeftBraceToken:
			addNameToken(token)
			closer, _ := expectedClosingToken(token.kind)
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
func variableRefs(ts []valueToken) []string {
	var out []string
	for i, t := range ts {
		if t.kind == css.FunctionToken && equalASCIIFold(t.raw, "var(") {
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
	parent              *variableScope
	values              map[string]variableValue
	colourDependent     map[string]bool
	hasColourDependency bool
	allUnresolved       bool
}

func (s *variableScope) get(name string, budget *expressionBudget) variableValue {
	for ; s != nil; s = s.parent {
		if !budget.charge(1) {
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

func (s *variableScope) colourSchemeDependent(name string, budget *expressionBudget) bool {
	for ; s != nil; s = s.parent {
		if !budget.charge(1) {
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
func buildLiteralVariables(parent *variableScope, defs map[string]candidate, alternate map[string]bool, budget *expressionBudget) (*variableScope, bool) {
	for _, definition := range defs {
		d := definition.d
		if d == nil || !d.tokensReady || d.valueStatus != valueResolved || d.unsupported || definition.uncertainOrigin || d.hasVars || len(d.variableDependencies) != 0 {
			return nil, false
		}
	}
	if !budget.charge(len(defs)) {
		return unresolvedVariableScope(parent), true
	}
	s := &variableScope{parent: parent, values: make(map[string]variableValue, len(defs))}
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
		if budget.exhausted {
			return unresolvedVariableScope(parent), true
		}
	}

	// With no alternate definitions and no inherited dependency, every local
	// literal is colour-scheme independent and a nil map answers that directly.
	if len(alternate) == 0 && (parent == nil || !parent.hasColourDependency) {
		return s, true
	}
	if !budget.charge(len(defs) + len(alternate)) {
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
func buildVariables(parent *variableScope, defs map[string]candidate, alternate map[string]bool, budget *expressionBudget) *variableScope {
	if len(defs) == 0 && len(alternate) == 0 {
		return parent
	}
	if len(defs)+len(alternate) > 1024 || !budget.charge(len(defs)+len(alternate)) {
		return unresolvedVariableScope(parent)
	}
	if scope, ok := buildLiteralVariables(parent, defs, alternate, budget); ok {
		return scope
	}
	s := &variableScope{parent: parent, values: make(map[string]variableValue), colourDependent: make(map[string]bool)}
	var ordered []string
	for n := range defs {
		ordered = append(ordered, n)
	}
	if !budget.charge(variableSortWork(len(ordered))) {
		return unresolvedVariableScope(parent)
	}
	sort.Strings(ordered)
	tokens := map[string][]valueToken{}
	cyclic := map[string]bool{}
	states := map[string]uint8{}
	var path []string
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
		if depth > maxExpressionDepth {
			budget.rejectDepth()
			s.values[n] = variableValue{status: valueUnsupported}
			return
		}
		if !budget.charge(1 + len(tokens[n])) {
			s.values[n] = variableValue{status: valueUnsupported}
			return
		}
		states[n] = 1
		path = append(path, n)
		definition := defs[n]
		dependencies := definition.d.variableDependencies
		if !definition.d.dependenciesReady {
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
			return unresolvedVariableScope(parent)
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
			return parent.get(n, budget)
		}
		d := definition.d
		if depth > maxExpressionDepth {
			budget.rejectDepth()
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
			v = substituteTokens(tokens[n], func(ref string) variableValue { return resolveName(ref, depth+1) }, budget, depth)
		}
		s.values[n] = v
		return v
	}
	for _, n := range ordered {
		resolveName(n, 0)
		if budget.exhausted {
			return unresolvedVariableScope(parent)
		}
	}
	if len(alternate) == 0 && (parent == nil || !parent.hasColourDependency) {
		return s
	}
	var dependencyState = make(map[string]uint8, len(defs))
	var dependsOnColourScheme func(string, int) bool
	dependsOnColourScheme = func(name string, depth int) bool {
		if dependencyState[name] == 2 {
			return s.colourDependent[name]
		}
		if alternate[name] || depth > maxExpressionDepth {
			if depth > maxExpressionDepth {
				budget.rejectDepth()
			}
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
		if !budget.charge(1 + len(definition.d.variableDependencies)) {
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

func variableSortWork(n int) int {
	if n < 2 {
		return 0
	}
	return n * bits.Len(uint(n-1))
}
func substitute(d *declaration, vars *variableScope, budget *expressionBudget) variableValue {
	if !d.hasVars {
		return variableValue{d.value, valueResolved}
	}
	if !d.tokensReady || d.valueStatus != valueResolved {
		return variableValue{status: d.valueStatus}
	}
	return substituteTokens(d.valueTokens, func(name string) variableValue {
		return vars.get(name, budget)
	}, budget, 0)
}
func substituteTokens(ts []valueToken, lookup func(string) variableValue, budget *expressionBudget, depth int) variableValue {
	if depth > maxExpressionDepth {
		budget.rejectDepth()
		return variableValue{status: valueUnsupported}
	}
	if !budget.charge(len(ts)) {
		return variableValue{status: valueUnsupported}
	}
	var out strings.Builder
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		if t.kind != css.FunctionToken || !equalASCIIFold(t.raw, "var(") {
			// Token count bounds structural work, but a single token can contain
			// almost maxValueBytes. Charge the bytes before copying them so large
			// strings and identifiers cannot consume unmetered expression work.
			if !budget.charge(len(t.raw)) {
				return variableValue{status: valueUnsupported}
			}
			out.WriteString(t.raw)
		} else {
			end := closing(ts, i)
			inner := ts[i+1 : end]
			comma := -1
			var stack []css.TokenType
			for j, v := range inner {
				if v.kind == css.CommaToken && len(stack) == 0 && comma < 0 {
					comma = j
				}
				stack, _ = advanceDelimiters(stack, v.kind)
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
	return variableValue{trimCSSWhitespace(out.String()), valueResolved}
}
