package htmlextract

import (
	"bytes"
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
	msoHide
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

const (
	overflowX = properties + iota
	overflowY
	width
	height
	maxWidth
	maxHeight
	left
	top
	right
	bottom
	textIndent
	marginTop
	marginRight
	marginBottom
	marginLeft
	zoom
	declarationProperties
	layoutProperties = declarationProperties - properties
	// allShorthandProperty is an internal sentinel. Keep one declaration for
	// the source shorthand and broadcast it across the tracked properties only
	// while applying the cascade; eagerly materialising every property permits
	// severe memory amplification from a small stylesheet.
	allShorthandProperty = declarationProperties
)

var names = [declarationProperties]string{"display", "visibility", "content-visibility", "mso-hide", "opacity", "font-size", "color", "background-color", "background-image", "filter", "mix-blend-mode", "backdrop-filter", "background-blend-mode", "mask-image", "background-clip", "text-shadow", "-webkit-text-fill-color", "transform", "position", "-webkit-text-stroke", "clip", "clip-path", "overflow-x", "overflow-y", "width", "height", "max-width", "max-height", "left", "top", "right", "bottom", "text-indent", "margin-top", "margin-right", "margin-bottom", "margin-left", "zoom"}

// A declaration progresses through these preparation states:
//
//   - tokensReady makes valueTokens and valueStatus meaningful. A false value
//     may mean tokens were deliberately not retained for an ordinary static
//     declaration, rather than that tokenization failed.
//   - validityReady makes validity meaningful. Context-dependent declarations
//     may be validated before evaluation, so validityReady does not imply that
//     prepared is non-nil.
//   - prepared holds the complete context-independent result and implies
//     validityReady. Its duplicate token storage has been released, leaving
//     tokensReady false and valueTokens nil.
//   - dependenciesReady makes variableDependencies complete and implies a
//     custom property with a retained, successfully parsed token stream.
//
// Once prepareDeclaration returns, these fields and the retained token slices
// are immutable; cascade candidates safely retain pointers to declarations.
type declaration struct {
	prop                 int
	value                string
	prepared             *preparedDeclaration
	validity             valueStatus
	validityReady        bool
	valueTokens          []valueToken
	valueStatus          valueStatus
	tokensReady          bool
	hasVars              bool
	keyword              string
	important            bool
	order                int
	unsupported          bool
	custom               string
	shorthand            bool
	variableDependencies []string
	dependenciesReady    bool
}

type preparedDeclaration struct {
	value  Value
	status valueStatus
}

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
	_, unit, found := splitLength(value)
	return found && (unit.kind == lengthUnitPercentage || unit.kind == lengthUnitParentFont || unit.kind == lengthUnitRootFont)
}

// prepareDeclaration performs the context-independent work for a declaration
// once. Declarations are copied while cascading, so valueTokens must remain
// immutable after this point.
func prepareDeclaration(d declaration) declaration {
	if d.prepared != nil {
		return d
	}
	if d.tokensReady {
		d.hasVars = tokensHaveVariables(d.valueTokens)
	} else {
		d.hasVars = hasVariables(d.value)
	}
	if d.custom != "" {
		d.keyword = strings.ToLower(strings.TrimSpace(d.value))
	}
	if (d.custom != "" || d.hasVars) && !d.tokensReady {
		d.valueTokens, d.valueStatus = lexValue(d.value)
		d.tokensReady = true
	}
	if d.custom != "" && d.tokensReady && d.valueStatus == valueResolved {
		d.variableDependencies = variableRefs(d.valueTokens)
		d.dependenciesReady = true
	}
	if d.custom == "" && !d.hasVars && !d.shorthand && !contextualDeclaration(d) {
		prepared := preparedDeclaration{}
		if d.unsupported || len(d.value) > maxValueBytes {
			prepared.value = Value{Text: d.value}
			prepared.status = valueUnsupported
		} else {
			prepared.value, prepared.status = resolve(d.prop, d.value, &initialStyle, &initialStyle)
		}
		d.prepared = &prepared
		d.validity, d.validityReady = prepared.status, true
		// The prepared value is the complete runtime representation. Keeping the
		// parser token stream as well only retains duplicate strings and slices.
		d.valueTokens = nil
		d.tokensReady = false
	} else if d.custom == "" && !d.hasVars && !d.shorthand && !d.unsupported {
		value := strings.ToLower(strings.TrimSpace(d.value))
		if (d.prop == fontSize || d.prop == opacity) && isMath(value) && d.tokensReady && d.valueStatus == valueResolved {
			budget := expressionBudget{remaining: int64(maxValueTokens * 4)}
			_, d.validity = evalMathTokens(d.prop, value, d.valueTokens, &initialStyle, &initialStyle, &budget)
		} else {
			_, d.validity = resolve(d.prop, value, &initialStyle, &initialStyle)
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
	plans                        []selectorPlan
	decls                        []declaration
	conditions                   *conditionFrame
	mediaWork, fallbackMediaWork int64
}

// sheetRuntime contains evaluation caches and reusable scratch storage. Rules,
// declarations and selector plans remain immutable once indexing completes.
type sheetRuntime struct {
	mediaCache          map[mediaCacheKey][]uint8
	cacheMatches        bool
	matchCaches         []map[*html.Node]uint8
	candidateScratch    []selectorRef
	candidateMarks      []uint32
	candidateGeneration uint32
	ancestorNodes       []*html.Node
	ancestorStates      []map[*html.Node]ancestorChainState
	matchCacheEntries   int
}

type sheet struct {
	rules                []rule
	rulesSeen            int
	selectors, order     int
	limits               Limits
	planningWork         int64
	cascadeIncomplete    bool
	workIncomplete       bool
	planCount            int
	conditionDepth       int
	index                selectorIndex
	cssBytes             int
	importDepth          int
	unresolvedStylesheet bool
	runtime              sheetRuntime
}

// admitCSS applies allocation-light source bounds before tdewolff's parser is
// allowed to accumulate a selector or declaration value into a token slice.
// CSS is counted across style elements and style attributes so splitting a
// payload into many individually acceptable inputs cannot bypass the document
// limit.
func (s *sheet) admitCSS(text string, inline bool) bool {
	if s.cascadeIncomplete || s.workIncomplete {
		return false
	}
	if len(text) > s.limits.CSSBytes || s.cssBytes > s.limits.CSSBytes-len(text) || !boundedCSSConstructs(text, inline, s.limits.CSSConstructBytes, s.limits.CSSConstructTokens) {
		s.abandonCascade()
		return false
	}
	s.cssBytes += len(text)
	return true
}

func (s *sheet) chargePlanningWork(value string) bool {
	return s.chargePlanningBytes(len(value))
}

func (s *sheet) chargePlanningTokens(tokens []css.Token) bool {
	bytes := 0
	for _, token := range tokens {
		bytes += len(token.Data)
	}
	return s.chargePlanningBytes(bytes)
}

func (s *sheet) chargePlanningBytes(bytes int) bool {
	cost := int64(bytes) + 1
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
	s.planCount = 0
	s.index = selectorIndex{}
	s.runtime = sheetRuntime{}
}

func (s *sheet) invalidateMediaCache() {
	s.runtime.mediaCache = nil
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

// defaultNamespaceRule reports whether an @namespace statement establishes a
// default namespace. A leading identifier instead declares a named prefix.
// Invalid or unfamiliar non-empty forms are treated conservatively as default
// declarations because namespace semantics cannot be delegated to Cascadia.
func defaultNamespaceRule(values []css.Token) bool {
	for _, token := range values {
		if token.TokenType == css.WhitespaceToken || token.TokenType == css.CommentToken {
			continue
		}
		return token.TokenType != css.IdentToken
	}
	return false
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
	status                valueStatus
	important             bool
	unsafeIdentifier      bool
	unsafeWithoutFunction bool
}

// cssTokensNeedRetention reports whether later declaration processing needs a
// durable value-token stream. Most ordinary declarations are resolved once
// immediately and retain only their prepared value. Escapes take the careful
// path because they may decode into a function name or different token class.
func cssTokensNeedRetention(prop string, values []css.Token) bool {
	if prop == "background" {
		return true
	}
	for _, token := range values {
		if bytes.IndexByte(token.Data, '\\') >= 0 {
			return true
		}
		if token.TokenType != css.FunctionToken {
			continue
		}
		if bytes.EqualFold(token.Data, []byte("var(")) {
			return true
		}
		// Context-sensitive arithmetic is evaluated from tokens so nested
		// functions and operator boundaries retain their exact meaning.
		if prop == "font-size" || prop == "opacity" {
			return true
		}
	}
	return false
}

// parseUnretainedCSSTokens handles the common static-declaration path without
// allocating a []valueToken that prepareDeclaration would immediately discard.
// Token boundaries still determine trimming and !important; comments inside a
// value become whitespace so removing one cannot join adjacent tokens.
func parseUnretainedCSSTokens(ts []css.Token, fallback string) parsedDeclarationValue {
	if len(ts) > maxValueTokens {
		return parsedDeclarationValue{text: strings.TrimSpace(fallback), status: valueUnsupported}
	}
	bytesSeen := 0
	for _, token := range ts {
		bytesSeen += len(token.Data)
		if bytesSeen > maxValueBytes {
			return parsedDeclarationValue{text: strings.TrimSpace(fallback), status: valueUnsupported}
		}
		if token.TokenType == css.BadStringToken || token.TokenType == css.BadURLToken {
			return parsedDeclarationValue{text: strings.TrimSpace(fallback), status: valueInvalid}
		}
	}

	start, end := 0, len(ts)
	for start < end && (ts[start].TokenType == css.WhitespaceToken || ts[start].TokenType == css.CommentToken) {
		start++
	}
	for end > start && (ts[end-1].TokenType == css.WhitespaceToken || ts[end-1].TokenType == css.CommentToken) {
		end--
	}

	important := false
	last := end - 1
	if last >= start && ts[last].TokenType == css.IdentToken && bytes.EqualFold(ts[last].Data, []byte("important")) {
		bang := last - 1
		for bang >= start && (ts[bang].TokenType == css.WhitespaceToken || ts[bang].TokenType == css.CommentToken) {
			bang--
		}
		if bang >= start && ts[bang].TokenType == css.DelimToken && bytes.Equal(ts[bang].Data, []byte("!")) {
			important = true
			end = bang
			for end > start && (ts[end-1].TokenType == css.WhitespaceToken || ts[end-1].TokenType == css.CommentToken) {
				end--
			}
		}
	}

	startByte := 0
	for i := 0; i < start; i++ {
		startByte += len(ts[i].Data)
	}
	endByte := startByte
	hasComment := false
	for i := start; i < end; i++ {
		endByte += len(ts[i].Data)
		hasComment = hasComment || ts[i].TokenType == css.CommentToken
	}
	text := fallback[startByte:endByte]
	if hasComment {
		var out strings.Builder
		out.Grow(endByte - startByte)
		for i := start; i < end; i++ {
			if ts[i].TokenType == css.CommentToken {
				out.WriteByte(' ')
			} else {
				out.Write(ts[i].Data)
			}
		}
		text = out.String()
	}
	return parsedDeclarationValue{text: text, status: valueResolved, important: important}
}

// parseDeclarationTokens preserves CSS token boundaries while decoding the
// identifier escapes that the supported property grammars need. In
// particular, an escaped '!' remains part of an identifier and cannot become
// an !important delimiter, and an escaped space cannot disappear through
// string trimming.
func parseDeclarationTokens(ts []valueToken, status valueStatus, fallback string) parsedDeclarationValue {
	if status != valueResolved {
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
	// This token slice is private to the declaration. Compact it in place so
	// normalization does not allocate a second slice proportional to the value.
	originalTokens := ts
	preparedTokens := ts[:0]
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
			sameIdentifierClass := t.kind == css.IdentToken && len(decodedTokens) == 1 && decodedTokens[0].kind == css.CustomPropertyNameToken
			if decodedStatus == valueResolved && len(decodedTokens) == 1 && (decodedTokens[0].kind == t.kind || sameIdentifierClass) {
				raw = decoded
			} else {
				unsafe = true
			}
		}
		out.WriteString(raw)
		preparedTokens = append(preparedTokens, valueToken{kind: t.kind, raw: raw})
	}
	clear(originalTokens[len(preparedTokens):])
	return parsedDeclarationValue{
		text:                  out.String(),
		tokens:                preparedTokens,
		status:                valueResolved,
		important:             important,
		unsafeIdentifier:      unsafe,
		unsafeWithoutFunction: unsafe && !hasFunction,
	}
}

func (s *sheet) declarations(prop, value string) []declaration {
	tokens, status := lexValue(value)
	return s.declarationsFromTokens(prop, tokens, status, value)
}

func ownedValueTokens(values []css.Token, raw string) ([]valueToken, valueStatus) {
	if len(values) > maxValueTokens {
		return nil, valueUnsupported
	}
	tokens := make([]valueToken, 0, len(values))
	offset := 0
	for _, token := range values {
		next := offset + len(token.Data)
		if next > maxValueBytes || next > len(raw) {
			return nil, valueUnsupported
		}
		if token.TokenType == css.BadStringToken || token.TokenType == css.BadURLToken {
			return nil, valueInvalid
		}
		// rawTokenString concatenates these exact byte sequences. Slice that one
		// owned string instead of allocating a separate string for every token.
		tokens = append(tokens, valueToken{kind: token.TokenType, raw: raw[offset:next]})
		offset = next
	}
	if offset != len(raw) {
		return nil, valueUnsupported
	}
	return tokens, valueResolved
}

func normalizeDeclarationProperty(prop string) string {
	prop = cssUnescape(prop)
	if !strings.HasPrefix(prop, "--") {
		prop = strings.ToLower(prop)
	}
	// Some email clients implement concealment-capable properties only under
	// historical engine prefixes. Canonicalize only explicit aliases whose
	// behavior maps onto an existing tracked property; arbitrary prefix
	// stripping could give unrelated vendor extensions incorrect semantics.
	switch prop {
	case "-webkit-mask":
		return "mask"
	case "-webkit-mask-image":
		return "mask-image"
	case "-webkit-transform", "-ms-transform":
		return "transform"
	case "-webkit-text-stroke-width":
		// Stroke colour cannot affect rendering while the width is zero. A
		// non-zero or unresolved width makes the existing stroke-effect slot
		// uncertain, including when a separate stroke colour is also present.
		return "-webkit-text-stroke"
	default:
		return prop
	}
}

func relevantDeclarationProperty(prop string) bool {
	return relevantNormalizedDeclarationProperty(normalizeDeclarationProperty(prop))
}

func relevantNormalizedDeclarationProperty(prop string) bool {
	if strings.HasPrefix(prop, "--") {
		return true
	}
	for _, name := range names {
		if name == prop {
			return true
		}
	}
	switch prop {
	case "margin", "overflow", "background", "mask", "font", "all":
		return true
	default:
		return false
	}
}

func (s *sheet) declarationsFromTokens(prop string, tokens []valueToken, status valueStatus, fallback string) []declaration {
	prop = normalizeDeclarationProperty(prop)
	parsed := parseDeclarationTokens(tokens, status, fallback)
	return s.declarationsFromParsed(prop, parsed, true)
}

func (s *sheet) declarationsFromParsed(prop string, parsed parsedDeclarationValue, tokensReady bool) []declaration {
	value := parsed.text
	imp := parsed.important
	custom := strings.HasPrefix(prop, "--")
	if custom && (parsed.status == valueInvalid || (parsed.status == valueResolved && !validVariableFunctions(parsed.tokens))) {
		return nil
	}
	prepared := func(d declaration) declaration {
		d.unsupported = d.unsupported || parsed.status == valueUnsupported
		d.valueTokens = parsed.tokens
		d.valueStatus = parsed.status
		d.tokensReady = tokensReady
		return prepareDeclaration(d)
	}
	s.order++
	if custom {
		return []declaration{prepared(declaration{prop: -1, custom: prop, value: value, important: imp, order: s.order})}
	}
	if prop == "margin" {
		values, ok, uncertain := marginShorthandValues(value)
		if !ok {
			return nil
		}
		properties := [...]int{marginTop, marginRight, marginBottom, marginLeft}
		out := make([]declaration, 0, len(properties))
		for i, property := range properties {
			componentTokens, componentStatus := lexValue(values[i])
			d := declaration{
				prop: property, value: values[i], important: imp, order: s.order,
				unsupported: uncertain || parsed.status == valueUnsupported || parsed.unsafeIdentifier,
				valueTokens: componentTokens, valueStatus: componentStatus, tokensReady: true,
			}
			out = append(out, prepareDeclaration(d))
		}
		return out
	}
	if prop == "overflow" {
		values, ok, uncertain := overflowShorthandValues(value)
		if !ok {
			return nil
		}
		properties := [...]int{overflowX, overflowY}
		out := make([]declaration, 0, len(properties))
		for i, property := range properties {
			d := declaration{
				prop: property, value: value, important: imp, order: s.order, shorthand: true,
				unsupported: uncertain || parsed.status == valueUnsupported || parsed.unsafeIdentifier,
			}
			if !uncertain {
				d.value = values[i]
			}
			out = append(out, prepareDeclaration(d))
		}
		return out
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
		if len(value) > maxValueBytes {
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
		return prepareDeclarations(backgroundDeclarationsTokens(strings.ToLower(value), parsed.tokens, parsed.status, imp, s.order))
	}
	if prop == "mask" {
		return []declaration{prepared(declaration{prop: maskImage, value: value, important: imp, order: s.order, unsupported: true})}
	}
	var affected []int
	switch prop {
	case "font":
		affected = []int{fontSize}
	case "all":
		return []declaration{prepared(declaration{prop: allShorthandProperty, value: value, important: imp, order: s.order, unsupported: true})}
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

func overflowShorthandValues(value string) ([2]string, bool, bool) {
	var out [2]string
	value = strings.TrimSpace(value)
	if value == "" {
		return out, false, false
	}
	// Functions can contain whitespace or substitute one or two components.
	// Retain the complete shorthand for resolution after variable substitution.
	if strings.Contains(value, "(") {
		out[0], out[1] = value, value
		return out, true, true
	}
	parts := strings.Fields(value)
	if len(parts) < 1 || len(parts) > 2 {
		return out, false, false
	}
	out[0], out[1] = parts[0], parts[0]
	if len(parts) == 2 {
		out[1] = parts[1]
	}
	return out, true, false
}

func marginShorthandValues(value string) ([4]string, bool, bool) {
	var out [4]string
	value = strings.TrimSpace(value)
	if value == "" {
		return out, false, false
	}
	// Functions can contain whitespace and expand to multiple components via
	// variables. Preserve their cascade effect conservatively rather than
	// incorrectly splitting their argument text.
	if strings.Contains(value, "(") {
		for i := range out {
			out[i] = value
		}
		return out, true, true
	}
	fields := strings.Fields(value)
	if len(fields) < 1 || len(fields) > 4 {
		return out, false, false
	}
	switch len(fields) {
	case 1:
		out = [4]string{fields[0], fields[0], fields[0], fields[0]}
	case 2:
		out = [4]string{fields[0], fields[1], fields[0], fields[1]}
	case 3:
		out = [4]string{fields[0], fields[1], fields[2], fields[1]}
	case 4:
		copy(out[:], fields)
	}
	for i, component := range out {
		property := [...]int{marginTop, marginRight, marginBottom, marginLeft}[i]
		if _, status := resolveLayoutProperty(property, component); status == valueInvalid {
			return [4]string{}, false, false
		}
	}
	return out, true, false
}

// parseCSS consumes the syntax library's recoverable stream. Unknown
// conditions and selectors retain uncertainty only for declarations they can
// affect; print blocks are skipped.
func (s *sheet) parseCSS(text string, inline bool) []declaration {
	if !inline {
		s.invalidateMediaCache()
	}
	if !s.admitCSS(text, inline) {
		return nil
	}
	p := css.NewParser(parse.NewInputString(text), inline)
	var conditions *conditionFrame
	conditionDepth := 0
	defaultNamespace := false
	current := -1
	// CSS permits @import only before ordinary rules and block at-rules. The
	// statement forms of @charset and @layer do not close that import window;
	// every assignment below corresponds to syntax that does.
	importsAllowed := !inline
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
			importsAllowed = false
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
			if conditionDepth >= s.limits.Depth {
				s.abandonCascade()
				return out
			}
			conditions = &conditionFrame{condition: cond, parent: conditions}
			conditionDepth++
			if conditionDepth > s.conditionDepth {
				s.conditionDepth = conditionDepth
			}
		case css.EndAtRuleGrammar:
			if conditions != nil {
				conditions = conditions.parent
				conditionDepth--
			}
			current = -1
		case css.AtRuleGrammar:
			name := strings.ToLower(string(data))
			if name == "@import" {
				if importsAllowed && conditions == nil {
					s.parseImport(values)
				}
				continue
			}
			if name != "@charset" && name != "@layer" {
				importsAllowed = false
			}
			if !inline && conditions == nil && name == "@namespace" && defaultNamespaceRule(values) {
				defaultNamespace = true
			}
		case css.BeginRulesetGrammar:
			importsAllowed = false
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
			if !s.chargePlanningWork(selector) {
				return out
			}
			plans := planSelectorList(selector, &s.planCount)
			if len(plans) == 0 {
				continue
			}
			if defaultNamespace {
				for i := range plans {
					// A default namespace can alter even otherwise supported type
					// selectors. Cascadia cannot express that constraint, so do not
					// let its HTML-oriented scope or index omit a possible match.
					plans[i].scopePrefix = ""
					plans[i].key = selectorKey{}
					plans[i].makeUncertain()
				}
			}
			s.selectors += len(plans)
			s.rulesSeen++
			if s.selectors > s.limits.Selectors || len(s.rules) >= s.limits.Rules {
				s.abandonCascade()
				return out
			}
			r := rule{plans: plans, conditions: conditions}
			r.prepareMediaWork()
			s.rules = append(s.rules, r)
			current = len(s.rules) - 1
		case css.EndRulesetGrammar:
			current = -1
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			// Unlike selectors and media queries, declaration values can end
			// with an escaped whitespace character. Preserve the raw token data
			// so it cannot be mistaken for insignificant surrounding space.
			if !s.chargePlanningTokens(values) {
				return out
			}
			prop := normalizeDeclarationProperty(string(data))
			applicable := (inline && conditions == nil) || (!inline && current >= 0)
			if !applicable || !relevantNormalizedDeclarationProperty(prop) {
				continue
			}
			vals := rawTokenString(values)
			var declarations []declaration
			// tdewolff deliberately exposes a custom-property value as one
			// opaque CustomPropertyValue token. Lex that payload once here so
			// var() dependencies and !important retain their CSS token boundaries.
			if g == css.CustomPropertyGrammar {
				valueTokens, valueStatus := lexValue(vals)
				declarations = s.declarationsFromTokens(prop, valueTokens, valueStatus, vals)
			} else if cssTokensNeedRetention(prop, values) {
				valueTokens, valueStatus := ownedValueTokens(values, vals)
				declarations = s.declarationsFromTokens(prop, valueTokens, valueStatus, vals)
			} else {
				declarations = s.declarationsFromParsed(prop, parseUnretainedCSSTokens(values, vals), false)
			}
			// A style attribute is a declaration list, not a stylesheet. Some
			// recoverable parsers nevertheless expose declarations nested in an
			// invalid at-rule. Such declarations have no unconditional inline
			// effect and must not override valid top-level declarations.
			if inline {
				out = append(out, declarations...)
			} else if current >= 0 {
				s.rules[current].decls = append(s.rules[current].decls, declarations...)
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
	s.attachMediaCondition(firstRule, media)
}

func (s *sheet) attachMediaCondition(firstRule int, media string) {
	if strings.TrimSpace(media) == "" {
		return
	}
	condition := parseMedia(media)
	for i := firstRule; i < len(s.rules); i++ {
		s.rules[i].conditions = &conditionFrame{condition: condition, parent: s.rules[i].conditions}
		s.rules[i].prepareMediaWork()
	}
}
