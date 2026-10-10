package htmlextract

import (
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/cascadia"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
)

const (
	display = iota
	visibility
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

var names = [properties]string{"display", "visibility", "opacity", "font-size", "color", "background-color", "background-image", "filter", "mix-blend-mode", "backdrop-filter", "background-blend-mode", "mask-image", "background-clip", "text-shadow", "-webkit-text-fill-color", "transform", "position", "-webkit-text-stroke", "clip", "clip-path"}

type declaration struct {
	prop        int
	value       string
	important   bool
	order       int
	unsupported bool
	custom      string
	shorthand   bool
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
	rules            []rule
	selectors, order int
	diagnostics      []string
	seen             map[string]bool
	limits           Limits
	planningWork     int64
	err              error
}

func (s *sheet) warn(reason string) {
	if s.err != nil {
		return
	}
	if len(reason) > 512 {
		reason = reason[:512] + " [truncated]"
	}
	if s.seen == nil {
		s.seen = make(map[string]bool)
	}
	if s.seen[reason] {
		return
	}
	s.seen[reason] = true
	if len(s.diagnostics) >= s.limits.Diagnostics {
		s.err = fmt.Errorf("limit: diagnostics > %d", s.limits.Diagnostics)
		return
	}
	s.diagnostics = append(s.diagnostics, reason)
}
func tokenString(v []css.Token) string {
	var b strings.Builder
	for _, t := range v {
		b.Write(t.Data)
	}
	return strings.TrimSpace(b.String())
}
func (s *sheet) declarations(prop, value string) []declaration {
	if !strings.HasPrefix(prop, "--") {
		prop = strings.ToLower(prop)
	}
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/*") {
		if ts, status := lexValue(value); status == 1 {
			var b strings.Builder
			for _, t := range ts {
				if t.kind == css.CommentToken {
					b.WriteByte(' ')
				} else {
					b.WriteString(t.raw)
				}
			}
			value = strings.TrimSpace(b.String())
		}
	}
	imp := false
	// CSS comments/whitespace can occur between ! and important. The parser
	// retains those tokens; canonicalize only this terminal priority marker.
	if at := strings.LastIndex(value, "!"); at >= 0 && strings.EqualFold(strings.TrimSpace(value[at+1:]), "important") {
		imp = true
		value = strings.TrimSpace(value[:at])
	}
	s.order++
	if strings.HasPrefix(prop, "--") {
		return []declaration{{prop: -1, custom: prop, value: value, important: imp, order: s.order}}
	}
	for p, n := range names {
		if n == prop {
			return []declaration{{prop: p, value: value, important: imp, order: s.order}}
		}
	}
	if prop == "background" {
		if hasVariables(value) {
			return []declaration{{prop: background, value: value, important: imp, order: s.order, shorthand: true}, {prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true}}
		}
		return backgroundDeclarations(strings.ToLower(value), imp, s.order)
	}
	if prop == "mask" {
		s.warn("unsupported shorthand: mask")
		return []declaration{{prop: maskImage, value: value, important: imp, order: s.order, unsupported: true}}
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
		s.warn("unsupported shorthand: " + prop)
		out := make([]declaration, 0, len(affected))
		for _, p := range affected {
			out = append(out, declaration{prop: p, value: value, important: imp, order: s.order, unsupported: true})
		}
		return out
	}
	if prop == "content" || prop == "filter" || prop == "clip" || prop == "clip-path" || prop == "height" || prop == "max-height" || prop == "overflow" || prop == "position" || prop == "transform" {
		s.warn("outside concealment coverage: " + prop)
	}
	return nil
}

// parseCSS consumes the syntax library's recoverable stream. Unknown
// conditions and selectors retain uncertainty only for declarations they can
// affect; print blocks are skipped.
func (s *sheet) parseCSS(text string, inline bool) []declaration {
	p := css.NewParser(parse.NewInputString(text), inline)
	var conditions []mediaCondition
	current := -1
	var out []declaration
	for {
		if s.err != nil {
			return out
		}
		g, _, data := p.Next()
		vals := tokenString(p.Values())
		switch g {
		case css.ErrorGrammar:
			if p.HasParseError() {
				s.warn("malformed CSS recovered")
				continue
			}
			if p.Err() != nil && p.Err() != io.EOF {
				s.warn("CSS read error: " + p.Err().Error())
			}
			return out
		case css.BeginAtRuleGrammar:
			var cond mediaCondition
			switch strings.ToLower(string(data)) {
			case "@media":
				cond = parseMedia(vals)
			case "@font-face", "@keyframes", "@-webkit-keyframes":
				cond = mediaCondition{{never: true}}
				s.warn("inactive at-rule: " + string(data))
			default:
				cond = mediaCondition{{unknown: true}}
				s.warn("unsupported conditional/at-rule: " + string(data))
			}
			if len(conditions) >= s.limits.Depth {
				s.err = fmt.Errorf("limit: CSS conditional depth")
				return out
			}
			conditions = append(conditions, cond)
		case css.EndAtRuleGrammar:
			if len(conditions) > 0 {
				conditions = conditions[:len(conditions)-1]
			}
			current = -1
		case css.AtRuleGrammar:
			s.warn("ignored at-rule: " + string(data))
		case css.BeginRulesetGrammar:
			current = -1
			selector := vals
			var staticBranches []string
			for _, branch := range splitSelectorList(selector) {
				if !inactiveInteractiveSelector(branch) {
					staticBranches = append(staticBranches, branch)
				}
			}
			if len(staticBranches) == 0 {
				s.warn("inactive interactive selector: " + selector)
				continue
			}
			selector = strings.Join(staticBranches, ",")
			if len(selector) > s.limits.SelectorBytes {
				s.err = fmt.Errorf("limit: selector bytes")
				return out
			}
			if !supportedSelector(selector) {
				s.warn("unsupported selector: " + selector)
				if len(s.rules) >= s.limits.Rules {
					s.err = fmt.Errorf("limit: rules/selectors")
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
					s.err = fmt.Errorf("limit: rules/selectors")
					return out
				}
				s.rules = append(s.rules, rule{selectors: scope, conditions: append([]mediaCondition(nil), conditions...), uncertainSelector: true})
				current = len(s.rules) - 1
				continue
			}
			group, err := cascadia.ParseGroup(selector)
			if err != nil {
				s.warn("invalid selector: " + selector)
				continue
			}
			s.selectors += len(group)
			if s.selectors > s.limits.Selectors || len(s.rules) >= s.limits.Rules {
				s.err = fmt.Errorf("limit: rules/selectors")
				return out
			}
			s.rules = append(s.rules, rule{selectors: group, conditions: append([]mediaCondition(nil), conditions...)})
			current = len(s.rules) - 1
		case css.EndRulesetGrammar:
			current = -1
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			if inline {
				out = append(out, s.declarations(string(data), vals)...)
			} else if current >= 0 {
				s.rules[current].decls = append(s.rules[current].decls, s.declarations(string(data), vals)...)
			}
		case css.QualifiedRuleGrammar, css.TokenGrammar:
			s.warn("malformed or unsupported CSS grammar")
		}
	}
}

func inactiveInteractiveSelector(selector string) bool {
	lower := strings.ToLower(selector)
	// Negated interaction states describe the initial state and cannot simply
	// be discarded without compiling the negation.
	if strings.Contains(lower, ":not(") {
		return false
	}
	brackets := 0
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
		if brackets != 0 || c != ':' || i+1 < len(lower) && lower[i+1] == ':' {
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
func selectorCost(sel string, depth, nodes int, limit int64) int64 {
	cost := int64(len(sel) + 1)
	brackets, parens := 0, 0
	var quote byte
	add := func(n int) {
		if int64(n) > limit-cost {
			cost = limit + 1
		} else {
			cost += int64(n)
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
			add(nodes + 1)
		}
		if c == ' ' {
			j := i
			for j < len(sel) && sel[j] == ' ' {
				j++
			}
			if i > 0 && j < len(sel) && !strings.ContainsRune(">+~", rune(sel[i-1])) && !strings.ContainsRune(">+~", rune(sel[j])) {
				add(depth + 1)
			}
			i = j - 1
		}
	}
	return cost
}
