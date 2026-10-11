package htmlextract

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"
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
	prop          int
	value         string
	prepared      *preparedDeclaration
	validity      int
	validityReady bool
	valueTokens   []valueToken
	valueStatus   int
	tokensReady   bool
	hasVars       bool
	hasEscape     bool
	keyword       string
	important     bool
	order         int
	unsupported   bool
	custom        string
	shorthand     bool
}

type preparedDeclaration struct {
	value  Value
	status int
}

const maxResolvedValueBytes = 4096

// contextualDeclaration reports whether computing the value requires an
// element's inherited/root style. Variables and shorthands are handled by the
// caller because their substituted value may change this answer.
func contextualDeclaration(d declaration) bool {
	value := strings.ToLower(strings.TrimSpace(d.value))
	if value == "inherit" || value == "unset" {
		return true
	}
	if (d.prop == fontSize || d.prop == opacity) && isMath(value) {
		return true
	}
	if d.prop == color && value == "currentcolor" {
		return true
	}
	if d.prop != fontSize {
		return false
	}
	if value == "smaller" || value == "larger" {
		return true
	}
	return strings.HasSuffix(value, "%") || strings.HasSuffix(value, "em")
}

// prepareDeclaration performs the context-independent work for a declaration
// once. Declarations are copied while cascading, so valueTokens must remain
// immutable after this point.
func prepareDeclaration(d declaration) declaration {
	if d.tokensReady {
		d.hasVars = tokensHaveVariables(d.valueTokens)
		d.hasEscape = tokensHaveEscape(d.valueTokens)
	} else {
		d.hasVars = hasVariables(d.value)
		d.hasEscape = strings.Contains(d.value, "\\")
	}
	if d.custom != "" {
		d.keyword = strings.ToLower(strings.TrimSpace(d.value))
	}
	if (d.custom != "" || d.hasVars) && !d.tokensReady {
		d.valueTokens, d.valueStatus = lexValue(d.value)
		d.tokensReady = true
	}
	if d.custom == "" && !d.hasVars && !d.shorthand && !contextualDeclaration(d) {
		prepared := preparedDeclaration{}
		if d.unsupported || len(d.value) > maxResolvedValueBytes {
			prepared.value = Value{Text: d.value}
			prepared.status = 2
		} else {
			prepared.value, prepared.status = resolve(d.prop, d.value, initialStyle, initialStyle)
		}
		d.prepared = &prepared
		d.validity, d.validityReady = prepared.status, true
	} else if d.custom == "" && !d.hasVars && !d.shorthand && !d.unsupported {
		value := strings.ToLower(strings.TrimSpace(d.value))
		if (d.prop == fontSize || d.prop == opacity) && isMath(value) && d.tokensReady && d.valueStatus == 1 {
			budget := expressionBudget{remaining: int64(maxValueTokens * 4)}
			_, d.validity = evalMathTokens(d.prop, value, d.valueTokens, initialStyle, initialStyle, &budget)
		} else {
			_, d.validity = resolve(d.prop, value, initialStyle, initialStyle)
		}
		d.validityReady = true
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
	plans      []selectorPlan
	decls      []declaration
	conditions []mediaCondition
}

type sheet struct {
	rules               []rule
	selectors, order    int
	limits              Limits
	planningWork        int64
	cascadeIncomplete   bool
	workIncomplete      bool
	mediaCache          map[mediaCacheKey][]uint8
	planCount           int
	conditionDepth      int
	index               selectorIndex
	cacheMatches        bool
	candidateScratch    []selectorRef
	candidateMarks      []uint32
	candidateGeneration uint32
	ancestorRefs        map[*html.Node][]selectorRef
	matchCacheEntries   int
}

func (s *sheet) chargeDeclarationWork(value string) bool {
	cost := int64(len(value) + 1)
	if cost < 1 || s.planningWork > s.limits.MatchWork || cost > s.limits.MatchWork-s.planningWork {
		s.workIncomplete = true
		return false
	}
	s.planningWork += cost
	return true
}

func (s *sheet) abandonCascade() {
	s.cascadeIncomplete = true
	s.rules = nil
	s.selectors = 0
	s.planCount = 0
	s.conditionDepth = 0
	s.index = selectorIndex{}
	s.cacheMatches = false
	s.candidateScratch = nil
	s.candidateMarks = nil
	s.candidateGeneration = 0
	s.ancestorRefs = nil
	s.matchCacheEntries = 0
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
	tokens                []valueToken
	status                int
	important             bool
	unsafeIdentifier      bool
	unsafeWithoutFunction bool
}

// parseDeclarationTokens preserves CSS token boundaries while decoding the
// identifier escapes that the supported property grammars need. In
// particular, an escaped '!' remains part of an identifier and cannot become
// an !important delimiter, and an escaped space cannot disappear through
// string trimming.
func parseDeclarationTokens(ts []valueToken, status int, fallback string) parsedDeclarationValue {
	if status != 1 {
		return parsedDeclarationValue{text: strings.TrimSpace(fallback), tokens: ts, status: status}
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
	preparedTokens := make([]valueToken, 0, end-start)
	for i := start; i < end; i++ {
		t := ts[i]
		hasFunction = hasFunction || t.kind == css.FunctionToken
		if t.kind == css.CommentToken {
			// Keep tokens on either side of a comment from being accidentally
			// joined into a different token.
			out.WriteByte(' ')
			preparedTokens = append(preparedTokens, valueToken{kind: css.WhitespaceToken, raw: " "})
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
		preparedTokens = append(preparedTokens, valueToken{kind: t.kind, raw: raw})
	}
	return parsedDeclarationValue{
		text:                  out.String(),
		tokens:                preparedTokens,
		status:                1,
		important:             important,
		unsafeIdentifier:      unsafe,
		unsafeWithoutFunction: unsafe && !hasFunction,
	}
}

func (s *sheet) declarations(prop, value string) []declaration {
	tokens, status := lexValue(value)
	return s.declarationsFromTokens(prop, tokens, status, value)
}

func ownedValueTokens(values []css.Token) ([]valueToken, int) {
	if len(values) > maxValueTokens {
		return nil, 2
	}
	tokens := make([]valueToken, 0, len(values))
	bytes := 0
	for _, token := range values {
		bytes += len(token.Data)
		if bytes > maxValueBytes {
			return nil, 2
		}
		if token.TokenType == css.BadStringToken || token.TokenType == css.BadURLToken {
			return nil, 0
		}
		tokens = append(tokens, valueToken{kind: token.TokenType, raw: string(token.Data)})
	}
	return tokens, 1
}

func (s *sheet) declarationsFromTokens(prop string, tokens []valueToken, status int, fallback string) []declaration {
	prop = cssUnescape(prop)
	if !strings.HasPrefix(prop, "--") {
		prop = strings.ToLower(prop)
	}
	parsed := parseDeclarationTokens(tokens, status, fallback)
	value := parsed.text
	imp := parsed.important
	custom := strings.HasPrefix(prop, "--")
	if custom && (parsed.status == 0 || (parsed.status == 1 && !validVariableFunctions(parsed.tokens))) {
		return nil
	}
	prepared := func(d declaration) declaration {
		d.unsupported = d.unsupported || parsed.status == 2
		d.valueTokens = parsed.tokens
		d.valueStatus = parsed.status
		d.tokensReady = true
		return prepareDeclaration(d)
	}
	s.order++
	if custom {
		return []declaration{prepared(declaration{prop: -1, custom: prop, value: value, important: imp, order: s.order})}
	}
	// None of the tracked property grammars accepts an arbitrary identifier.
	// If decoding it would change its token type or boundaries, it cannot be a
	// supported keyword and the browser will reject the declaration.
	if parsed.unsafeWithoutFunction {
		return nil
	}
	for p, n := range names {
		if n == prop {
			return []declaration{prepared(declaration{prop: p, value: value, important: imp, order: s.order, unsupported: parsed.unsafeIdentifier})}
		}
	}
	if prop == "background" {
		if len(value) > maxResolvedValueBytes {
			return prepareDeclarations([]declaration{
				{prop: background, value: value, important: imp, order: s.order, unsupported: true},
				{prop: backgroundImage, value: value, important: imp, order: s.order, unsupported: true},
			})
		}
		if parsed.unsafeIdentifier {
			return []declaration{
				prepared(declaration{prop: background, value: value, important: imp, order: s.order, shorthand: true, unsupported: true}),
				prepared(declaration{prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true, unsupported: true}),
			}
		}
		if tokensHaveVariables(parsed.tokens) {
			return []declaration{
				prepared(declaration{prop: background, value: value, important: imp, order: s.order, shorthand: true}),
				prepared(declaration{prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true}),
			}
		}
		return prepareDeclarations(backgroundDeclarations(strings.ToLower(value), imp, s.order))
	}
	if prop == "mask" {
		return []declaration{prepared(declaration{prop: maskImage, value: value, important: imp, order: s.order, unsupported: true})}
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
			out = append(out, prepared(declaration{prop: p, value: value, important: imp, order: s.order, unsupported: true}))
		}
		return out
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
		if s.cascadeIncomplete || s.workIncomplete {
			return out
		}
		g, _, data := p.Next()
		values := p.Values()
		switch g {
		case css.ErrorGrammar:
			if p.HasParseError() {
				continue
			}
			return out
		case css.BeginAtRuleGrammar:
			vals := tokenString(values)
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
			if len(conditions) > s.conditionDepth {
				s.conditionDepth = len(conditions)
			}
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
			selector := tokenString(values)
			if len(selector) > s.limits.SelectorBytes {
				s.abandonCascade()
				return out
			}
			plans := planSelectorList(selector, &s.planCount)
			if len(plans) == 0 {
				continue
			}
			s.selectors += len(plans)
			if s.selectors > s.limits.Selectors || len(s.rules) >= s.limits.Rules {
				s.abandonCascade()
				return out
			}
			s.rules = append(s.rules, rule{plans: plans, conditions: append([]mediaCondition(nil), conditions...)})
			current = len(s.rules) - 1
		case css.EndRulesetGrammar:
			current = -1
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			// Unlike selectors and media queries, declaration values can end
			// with an escaped whitespace character. Preserve the raw token data
			// so it cannot be mistaken for insignificant surrounding space.
			vals := rawTokenString(values)
			if !s.chargeDeclarationWork(vals) {
				return out
			}
			valueTokens, valueStatus := ownedValueTokens(values)
			// tdewolff deliberately exposes a custom-property value as one
			// opaque CustomPropertyValue token. Lex that payload once here so
			// var() dependencies and !important retain their CSS token boundaries.
			if g == css.CustomPropertyGrammar {
				valueTokens, valueStatus = lexValue(vals)
			}
			// A style attribute is a declaration list, not a stylesheet. Some
			// recoverable parsers nevertheless expose declarations nested in an
			// invalid at-rule. Such declarations have no unconditional inline
			// effect and must not override valid top-level declarations.
			if inline {
				if len(conditions) == 0 {
					out = append(out, s.declarationsFromTokens(string(data), valueTokens, valueStatus, vals)...)
				}
			} else if current >= 0 {
				s.rules[current].decls = append(s.rules[current].decls, s.declarationsFromTokens(string(data), valueTokens, valueStatus, vals)...)
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
