package htmlextract

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/andybalholm/cascadia"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
)

const (
	display = iota
	visibility
	contentVisibility
	opacity
	fontSize
	color
	background
	backgroundImage
	filter
	blend
	backdropFilter
	backgroundBlend
	maskImage
	backgroundClip
	textShadow
	textFill
	transform
	position
	textStroke
	clip
	clipPath
	properties
)

var names = [properties]string{"display", "visibility", "content-visibility", "opacity", "font-size", "color", "background-color", "background-image", "filter", "mix-blend-mode", "backdrop-filter", "background-blend-mode", "mask-image", "background-clip", "text-shadow", "-webkit-text-fill-color", "transform", "position", "-webkit-text-stroke", "clip", "clip-path"}

type declaration struct {
	prop        int
	value       string
	valueTokens []valueToken
	valueStatus int
	tokensReady bool
	hasVars     bool
	hasEscape   bool
	keyword     string
	important   bool
	order       int
	unsupported bool
	custom      string
	shorthand   bool
}

// prepareDeclaration performs the context-independent work for a declaration
// once. Declarations are copied while cascading, so valueTokens must remain
// immutable after this point.
func prepareDeclaration(d declaration) declaration {
	d.hasVars = hasVariables(d.value)
	d.hasEscape = strings.Contains(d.value, "\\")
	if d.custom != "" {
		d.keyword = strings.ToLower(strings.TrimSpace(d.value))
	}
	if d.custom != "" || d.hasVars {
		d.valueTokens, d.valueStatus = lexValue(d.value)
		d.tokensReady = true
	}
	return d
}

func prepareDeclarations(ds []declaration) []declaration {
	for i := range ds {
		ds[i] = prepareDeclaration(ds[i])
	}
	return ds
}

type rule struct {
	selectors         cascadia.SelectorGroup
	fallbackScopes    []cascadia.SelectorGroup
	costs, scopeCosts []int64
	decls             []declaration
	conditions        []mediaCondition
	uncertainSelector bool
}
type sheet struct {
	rules             []rule
	selectors, order  int
	limits            Limits
	planningWork      int64
	cascadeIncomplete bool
	mediaCache        map[mediaCacheKey][]uint8
}

func (s *sheet) abandonCascade() {
	s.cascadeIncomplete = true
	s.rules = nil
	s.selectors = 0
	s.planningWork = 0
	s.mediaCache = nil
}

func (s *sheet) invalidateMediaCache() {
	s.mediaCache = nil
}

func tokenString(v []css.Token) string {
	return strings.TrimSpace(rawTokenString(v))
}

func rawTokenString(v []css.Token) string {
	var b strings.Builder
	for _, t := range v {
		b.Write(t.Data)
	}
	return b.String()
}

func cssUnescape(value string) string {
	if !strings.Contains(value, "\\") {
		return value
	}
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '\\' || i+1 == len(value) {
			out.WriteByte(value[i])
			i++
			continue
		}
		i++
		if value[i] == '\n' || value[i] == '\f' {
			i++
			continue
		}
		if value[i] == '\r' {
			i++
			if i < len(value) && value[i] == '\n' {
				i++
			}
			continue
		}
		start := i
		for i < len(value) && i-start < 6 && ((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f') || (value[i] >= 'A' && value[i] <= 'F')) {
			i++
		}
		if i > start {
			codepoint, _ := strconv.ParseUint(value[start:i], 16, 32)
			r := rune(codepoint)
			if r == 0 || !utf8.ValidRune(r) {
				r = utf8.RuneError
			}
			out.WriteRune(r)
			if i < len(value) && (value[i] == ' ' || value[i] == '\t' || value[i] == '\n' || value[i] == '\r' || value[i] == '\f') {
				if value[i] == '\r' && i+1 < len(value) && value[i+1] == '\n' {
					i++
				}
				i++
			}
			continue
		}
		out.WriteByte(value[i])
		i++
	}
	return out.String()
}

type parsedDeclarationValue struct {
	text                  string
	important             bool
	unsafeIdentifier      bool
	unsafeWithoutFunction bool
}

// parseDeclarationValue preserves CSS token boundaries while decoding the
// identifier escapes that the supported property grammars need. In
// particular, an escaped '!' remains part of an identifier and cannot become
// an !important delimiter, and an escaped space cannot disappear through
// string trimming.
func parseDeclarationValue(value string) parsedDeclarationValue {
	ts, status := lexValue(value)
	if status != 1 {
		return parsedDeclarationValue{text: strings.TrimSpace(value)}
	}
	start, end := 0, len(ts)
	for start < end && (ts[start].kind == css.WhitespaceToken || ts[start].kind == css.CommentToken) {
		start++
	}
	for end > start && (ts[end-1].kind == css.WhitespaceToken || ts[end-1].kind == css.CommentToken) {
		end--
	}

	important := false
	last := end - 1
	if last >= start && ts[last].kind == css.IdentToken && strings.EqualFold(cssUnescape(ts[last].raw), "important") {
		bang := last - 1
		for bang >= start && (ts[bang].kind == css.WhitespaceToken || ts[bang].kind == css.CommentToken) {
			bang--
		}
		if bang >= start && ts[bang].kind == css.DelimToken && ts[bang].raw == "!" {
			important = true
			end = bang
			for end > start && (ts[end-1].kind == css.WhitespaceToken || ts[end-1].kind == css.CommentToken) {
				end--
			}
		}
	}

	unsafe := false
	hasFunction := false
	var out strings.Builder
	for i := start; i < end; i++ {
		t := ts[i]
		hasFunction = hasFunction || t.kind == css.FunctionToken
		if t.kind == css.CommentToken {
			// Keep tokens on either side of a comment from being accidentally
			// joined into a different token.
			out.WriteByte(' ')
			continue
		}
		raw := t.raw
		if (t.kind == css.IdentToken || t.kind == css.FunctionToken) && strings.Contains(raw, "\\") {
			decoded := cssUnescape(raw)
			decodedTokens, decodedStatus := lexValue(decoded)
			if decodedStatus == 1 && len(decodedTokens) == 1 && decodedTokens[0].kind == t.kind {
				raw = decoded
			} else {
				unsafe = true
			}
		}
		out.WriteString(raw)
	}
	return parsedDeclarationValue{
		text:                  out.String(),
		important:             important,
		unsafeIdentifier:      unsafe,
		unsafeWithoutFunction: unsafe && !hasFunction,
	}
}

func (s *sheet) declarations(prop, value string) []declaration {
	prop = cssUnescape(prop)
	if !strings.HasPrefix(prop, "--") {
		prop = strings.ToLower(prop)
	}
	parsed := parseDeclarationValue(value)
	value = parsed.text
	imp := parsed.important
	s.order++
	if strings.HasPrefix(prop, "--") {
		return prepareDeclarations([]declaration{{prop: -1, custom: prop, value: value, important: imp, order: s.order}})
	}
	// None of the tracked property grammars accepts an arbitrary identifier.
	// If decoding it would change its token type or boundaries, it cannot be a
	// supported keyword and the browser will reject the declaration.
	if parsed.unsafeWithoutFunction {
		return nil
	}
	for p, n := range names {
		if n == prop {
			return prepareDeclarations([]declaration{{prop: p, value: value, important: imp, order: s.order, unsupported: parsed.unsafeIdentifier}})
		}
	}
	if prop == "background" {
		if parsed.unsafeIdentifier {
			return prepareDeclarations([]declaration{
				{prop: background, value: value, important: imp, order: s.order, shorthand: true, unsupported: true},
				{prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true, unsupported: true},
			})
		}
		if hasVariables(value) {
			return prepareDeclarations([]declaration{{prop: background, value: value, important: imp, order: s.order, shorthand: true}, {prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true}})
		}
		return backgroundDeclarations(strings.ToLower(value), imp, s.order)
	}
	if prop == "mask" {
		return prepareDeclarations([]declaration{{prop: maskImage, value: value, important: imp, order: s.order, unsupported: true}})
	}
	var affected []int
	switch prop {
	case "font":
		affected = []int{fontSize}
	case "all":
		for i := 0; i < properties; i++ {
			affected = append(affected, i)
		}
	}
	if len(affected) > 0 {
		out := make([]declaration, 0, len(affected))
		for _, p := range affected {
			out = append(out, declaration{prop: p, value: value, important: imp, order: s.order, unsupported: true})
		}
		return prepareDeclarations(out)
	}
	return nil
}

// parseCSS consumes the syntax library's recoverable stream. Unknown
// conditions and selectors retain uncertainty only for declarations they can
// affect; print blocks are skipped.
func (s *sheet) parseCSS(text string, inline bool) []declaration {
	if !inline {
		s.invalidateMediaCache()
	}
	p := css.NewParser(parse.NewInputString(text), inline)
	var conditions []mediaCondition
	current := -1
	var out []declaration
	for {
		if s.cascadeIncomplete {
			return out
		}
		g, _, data := p.Next()
		values := p.Values()
		vals := tokenString(values)
		switch g {
		case css.ErrorGrammar:
			if p.HasParseError() {
				continue
			}
			return out
		case css.BeginAtRuleGrammar:
			var cond mediaCondition
			switch strings.ToLower(string(data)) {
			case "@media":
				cond = parseMedia(vals)
			case "@font-face", "@keyframes", "@-webkit-keyframes":
				cond = mediaCondition{{never: true}}
			default:
				cond = mediaCondition{{unknown: true}}
			}
			if len(conditions) >= s.limits.Depth {
				s.abandonCascade()
				return out
			}
			conditions = append(conditions, cond)
		case css.EndAtRuleGrammar:
			if len(conditions) > 0 {
				conditions = conditions[:len(conditions)-1]
			}
			current = -1
		case css.AtRuleGrammar:
		case css.BeginRulesetGrammar:
			current = -1
			if inline {
				// Rulesets are not valid members of a style attribute. In
				// particular, do not let a ruleset nested in a malformed inline
				// at-rule escape into the document stylesheet.
				continue
			}
			selector := vals
			var staticBranches []string
			for _, branch := range splitSelectorList(selector) {
				if !inactiveInteractiveSelector(branch) {
					staticBranches = append(staticBranches, branch)
				}
			}
			if len(staticBranches) == 0 {
				continue
			}
			selector = strings.Join(staticBranches, ",")
			if len(selector) > s.limits.SelectorBytes {
				s.abandonCascade()
				return out
			}
			if !supportedSelector(selector) {
				if len(s.rules) >= s.limits.Rules {
					s.abandonCascade()
					return out
				}
				// Preserve any provable target constraint from the rightmost
				// compound selector. For example, .offer:hover cannot be
				// resolved without client interaction, but it can only affect
				// .offer elements. Falling back to a universal scope remains
				// conservative when no such constraint can be recovered.
				scope := uncertainSelectorScope(selector)
				s.selectors += len(scope)
				if s.selectors > s.limits.Selectors {
					s.abandonCascade()
					return out
				}
				s.rules = append(s.rules, rule{selectors: scope, conditions: append([]mediaCondition(nil), conditions...), uncertainSelector: true})
				current = len(s.rules) - 1
				continue
			}
			group, err := cascadia.ParseGroup(selector)
			if err != nil {
				continue
			}
			s.selectors += len(group)
			if s.selectors > s.limits.Selectors || len(s.rules) >= s.limits.Rules {
				s.abandonCascade()
				return out
			}
			s.rules = append(s.rules, rule{selectors: group, conditions: append([]mediaCondition(nil), conditions...)})
			current = len(s.rules) - 1
		case css.EndRulesetGrammar:
			current = -1
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			// Unlike selectors and media queries, declaration values can end
			// with an escaped whitespace character. Preserve the raw token data
			// so it cannot be mistaken for insignificant surrounding space.
			vals = rawTokenString(values)
			// A style attribute is a declaration list, not a stylesheet. Some
			// recoverable parsers nevertheless expose declarations nested in an
			// invalid at-rule. Such declarations have no unconditional inline
			// effect and must not override valid top-level declarations.
			if inline {
				if len(conditions) == 0 {
					out = append(out, s.declarations(string(data), vals)...)
				}
			} else if current >= 0 {
				s.rules[current].decls = append(s.rules[current].decls, s.declarations(string(data), vals)...)
			}
		case css.QualifiedRuleGrammar, css.TokenGrammar:
		}
	}
}

// parseStylesheet parses a style element and applies the element's media
// attribute to every rule it contributes. Conditions already attached by
// nested at-rules are retained, making the conditions conjunctive.
func (s *sheet) parseStylesheet(text, media string) {
	firstRule := len(s.rules)
	s.parseCSS(text, false)
	if strings.TrimSpace(media) == "" {
		return
	}
	condition := parseMedia(media)
	for i := firstRule; i < len(s.rules); i++ {
		s.rules[i].conditions = append([]mediaCondition{condition}, s.rules[i].conditions...)
	}
}

func inactiveInteractiveSelector(selector string) bool {
	lower := strings.ToLower(selector)
	brackets, parens := 0, 0
	var quote byte
	for i := 0; i < len(lower); i++ {
		c := lower[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '[' {
			brackets++
			continue
		}
		if c == ']' && brackets > 0 {
			brackets--
			continue
		}
		if brackets == 0 && c == '(' {
			parens++
			continue
		}
		if brackets == 0 && c == ')' && parens > 0 {
			parens--
			continue
		}
		// An interaction state nested in a selector function may coexist with a
		// statically matching arm, as in :is(.offer,:hover). Keep that branch so
		// unsupported-selector handling can conservatively mark its scope unknown.
		if brackets != 0 || parens != 0 || c != ':' || i+1 < len(lower) && lower[i+1] == ':' {
			continue
		}
		for _, pseudo := range []string{":hover", ":focus-visible", ":focus-within", ":focus", ":active", ":visited"} {
			if strings.HasPrefix(lower[i:], pseudo) {
				end := i + len(pseudo)
				if end == len(lower) || !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789_-", rune(lower[end])) {
					return true
				}
			}
		}
	}
	return false
}

// uncertainSelectorScope returns a conservative selector for the elements an
// unsupported selector could target. It intentionally uses only the tag, ID,
// and class portion preceding attributes and pseudo-classes in the rightmost
// compound. Dropping those later constraints broadens the match, never narrows
// it. A branch that supplies no safely compilable constraint makes the whole
// group universal.
func uncertainSelectorScope(selector string) cascadia.SelectorGroup {
	branches := splitSelectorList(selector)
	if len(branches) == 0 {
		return universalSelectorScope()
	}
	var result cascadia.SelectorGroup
	seen := make(map[string]bool)
	for _, branch := range branches {
		compound := rightmostCompound(branch)
		prefix := basicCompoundPrefix(compound)
		if prefix == "" || prefix == "*" {
			return universalSelectorScope()
		}
		group, err := cascadia.ParseGroup(prefix)
		if err != nil || len(group) == 0 {
			return universalSelectorScope()
		}
		if !seen[prefix] {
			seen[prefix] = true
			result = append(result, group...)
		}
	}
	if len(result) == 0 {
		return universalSelectorScope()
	}
	return result
}

func universalSelectorScope() cascadia.SelectorGroup {
	group, _ := cascadia.ParseGroup("*")
	return group
}

func splitSelectorList(selector string) []string {
	var result []string
	start, brackets, parens := 0, 0, 0
	var quote byte
	for i := 0; i < len(selector); i++ {
		c := selector[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		case ',':
			if brackets == 0 && parens == 0 {
				if branch := strings.TrimSpace(selector[start:i]); branch != "" {
					result = append(result, branch)
				}
				start = i + 1
			}
		}
	}
	if branch := strings.TrimSpace(selector[start:]); branch != "" {
		result = append(result, branch)
	}
	return result
}

func rightmostCompound(selector string) string {
	start, brackets, parens := 0, 0, 0
	var quote byte
	for i := 0; i < len(selector); i++ {
		c := selector[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '[':
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '(':
			parens++
		case ')':
			if parens > 0 {
				parens--
			}
		default:
			if brackets == 0 && parens == 0 && (c == '>' || c == '+' || c == '~' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f') {
				start = i + 1
			}
		}
	}
	return strings.TrimSpace(selector[start:])
}

func basicCompoundPrefix(compound string) string {
	if compound == "" {
		return ""
	}
	for i := 0; i < len(compound); i++ {
		if compound[i] == '\\' {
			i++
			continue
		}
		if compound[i] == ':' || compound[i] == '[' || compound[i] == '|' {
			return strings.TrimSpace(compound[:i])
		}
	}
	return strings.TrimSpace(compound)
}

// Restrict Cascadia's broader selector language. Bound syntax length, nesting
// and combinators before compiling recursive library selectors.
func supportedSelector(s string) bool {
	bracket := false
	var quote byte
	combinators := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '[' {
			bracket = true
			continue
		}
		if c == ']' {
			bracket = false
			continue
		}
		if bracket {
			continue
		}
		if c == ':' {
			if strings.HasPrefix(s[i:], ":root") && (i+5 == len(s) || !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", rune(s[i+5]))) {
				i += 4
				continue
			}
			if !strings.HasPrefix(s[i:], ":not(") {
				return false
			}
			end := strings.IndexByte(s[i+5:], ')')
			if end < 0 {
				return false
			}
			arg := s[i+5 : i+5+end]
			if strings.ContainsAny(arg, ":(),>+~ \t\n") {
				return false
			}
			i += 5 + end
			continue
		}
		if c == '>' || c == '+' || c == '~' || c == ' ' {
			combinators++
			if combinators > 32 {
				return false
			}
		}
		if c == '(' || c == ')' || c == '|' {
			return false
		}
	}
	return !bracket && quote == 0
}

// selectorCost bounds the branching scans in Cascadia for this limited grammar.
// It is deliberately conservative: every sibling scan is charged the entire
// document node count, and every descendant scan the maximum document depth.
const siblingMatchWeight int64 = 10

func selectorCost(sel string, depth, nodes int, limit int64) int64 {
	cost := int64(len(sel) + 1)
	brackets, parens := 0, 0
	var quote byte
	add := func(n int, weight int64) {
		if int64(n) > (limit-cost)/weight {
			cost = limit + 1
		} else {
			cost += int64(n) * weight
		}
	}
	for i := 0; i < len(sel) && cost <= limit; i++ {
		c := sel[i]
		if c == '\\' {
			i++
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '[':
			brackets++
		case ']':
			brackets--
		case '(':
			parens++
		case ')':
			parens--
		}
		if brackets > 0 || parens > 0 {
			continue
		}
		if c == '~' || c == '+' {
			// Cascadia follows sibling pointers for these combinators. Weight
			// that traversal to reflect its measured CPU cost relative to the
			// cheap selector and rule-visit units used by the shared budget.
			add(nodes+1, siblingMatchWeight)
		}
		if c == ' ' {
			j := i
			for j < len(sel) && sel[j] == ' ' {
				j++
			}
			if i > 0 && j < len(sel) && !strings.ContainsRune(">+~", rune(sel[i-1])) && !strings.ContainsRune(">+~", rune(sel[j])) {
				add(depth+1, 1)
			}
			i = j - 1
		}
	}
	return cost
}
