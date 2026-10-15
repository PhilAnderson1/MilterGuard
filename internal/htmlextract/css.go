package htmlextract

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
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
	lineHeight
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
	letterSpacing
	wordSpacing
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
	// animationProperty is a cascade-only sentinel. Animation is not rendered;
	// its winning declaration is retained solely to prevent a time-varying
	// subtree from receiving a static visibility conclusion.
	animationProperty = allShorthandProperty + 1
)

var names = [declarationProperties]string{"display", "visibility", "content-visibility", "mso-hide", "opacity", "font-size", "color", "background-color", "background-image", "filter", "mix-blend-mode", "backdrop-filter", "background-blend-mode", "mask-image", "background-clip", "text-shadow", "-webkit-text-fill-color", "transform", "position", "-webkit-text-stroke", "clip", "clip-path", "line-height", "overflow-x", "overflow-y", "width", "height", "max-width", "max-height", "left", "top", "right", "bottom", "text-indent", "letter-spacing", "word-spacing", "margin-top", "margin-right", "margin-bottom", "margin-left", "zoom"}

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
//   - dependenciesReady makes variableDependencies complete for a declaration
//     containing var() with a retained, successfully parsed token stream.
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
	animationShorthand   bool
	animation            *animationValue
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
	value := normalizeCSSKeyword(d.value)
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
// once. Cascade candidates retain pointers to prepared declarations, so the
// declaration and any retained valueTokens must remain immutable afterward.
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
		d.keyword = normalizeCSSKeyword(d.value)
	}
	if (d.custom != "" || d.hasVars) && !d.tokensReady {
		d.valueTokens, d.valueStatus = lexValue(d.value)
		d.tokensReady = true
	}
	if d.hasVars && d.tokensReady && d.valueStatus == valueResolved {
		d.variableDependencies = variableRefs(d.valueTokens)
		d.dependenciesReady = true
	}
	if d.prop == animationProperty && d.custom == "" {
		// Cache context-independent name parsing, including escaped identifiers
		// that the conservative hasVars fast path initially treated as dynamic.
		if !d.hasVars || (d.tokensReady && !tokensHaveVariables(d.valueTokens)) {
			value := parseAnimationValue(d.value, d.animationShorthand)
			d.animation = &value
		}
		return d
	}
	if d.custom == "" && !d.hasVars && !d.shorthand && !contextualDeclaration(d) {
		prepared := preparedDeclaration{}
		if d.unsupported {
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
		value := normalizeCSSKeyword(d.value)
		if (d.prop == fontSize || d.prop == opacity) && isMath(value) && d.tokensReady && d.valueStatus == valueResolved {
			budget := cpuGuard{}
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

func (s *sheet) prepareDeclaration(d declaration) declaration {
	if !s.checkCPU() {
		d.valueTokens = nil
		d.tokensReady = false
		d.variableDependencies = nil
		d.dependenciesReady = false
		return d
	}
	d = prepareDeclaration(d)
	return d
}

func (s *sheet) prepareDeclarations(ds []declaration) []declaration {
	for i := range ds {
		ds[i] = s.prepareDeclaration(ds[i])
	}
	return ds
}

type rule struct {
	plans           []selectorPlan
	decls           []declaration
	conditions      *conditionFrame
	uncertainOrigin bool
}

// sheetRuntime contains evaluation caches and reusable scratch storage. Rules,
// declarations and selector plans remain immutable once indexing completes.
type sheetRuntime struct {
	mediaCache          map[mediaCacheKey][]uint8
	cacheMatches        bool
	matchCaches         []map[*html.Node]uint8
	attributeCandidates map[*html.Node]selectorAttributeCandidates
	candidateScratch    []selectorRef
	candidateMarks      []uint32
	candidateGeneration uint32
	ancestorNodes       []*html.Node
	ancestorRecent      []ancestorStateEntry
	ancestorStates      []map[*html.Node]ancestorChainState
	activeAncestors     activeAncestorBuckets
	variableScratch     map[string]candidate
}

type sheet struct {
	rules                []rule
	rulesSeen            int
	selectors, order     int
	limits               Limits
	cascadeIncomplete    bool
	planCount            int
	index                selectorIndex
	cssBytes             int
	mediaConditions      map[string]mediaCondition
	keyframeNames        map[string]struct{}
	unresolvedStylesheet bool
	unsupportedNesting   bool
	unsupportedColours   int
	runtime              sheetRuntime
	shouldStop           func() bool
	selectorControl      *cascadia.MatchControl
	cpu                  *cpuGuard
	memory               *resourceguard.Memory
	stopped              bool
}

// admitCSS applies the cumulative source and work bounds. Per-construct and
// stack limits are enforced where the local CSS parser grows those resources.
func (s *sheet) admitCSS(text string) bool {
	if s.cascadeIncomplete || s.stopped {
		return false
	}
	if len(text) > s.limits.CSSBytes || s.cssBytes > s.limits.CSSBytes-len(text) {
		s.abandonCascade()
		return false
	}
	// Cover extractor-owned token strings, declarations, condition frames and
	// parser compatibility copies. The forked parser and selector compiler
	// additionally charge their allocations at their actual insertion points.
	if !s.memory.Reserve(int64(len(text))*64 + 256) {
		s.abandonCascade()
		return false
	}
	// Account for the complete parser pass before doing it. Selector and
	// declaration processing below is charged separately.
	if !s.checkCPU() {
		return false
	}
	s.cssBytes += len(text)
	return true
}

func (s *sheet) checkCPU() bool {
	if s.stopped {
		return false
	}
	if s.cpu != nil && !s.cpu.check() {
		s.stopped = true
		return false
	}
	return true
}

func (s *sheet) abandonCascade() {
	s.cascadeIncomplete = true
	s.rules = nil
	s.keyframeNames = nil
	s.planCount = 0
	s.index = selectorIndex{}
	s.runtime = sheetRuntime{}
}

func (s *sheet) noteUnsupportedNesting() {
	s.unsupportedNesting = true
	s.unresolvedStylesheet = true
}

// hasTopLevelCSSBlock distinguishes a nested rule recovered as a declaration
// from braces inside a function or other component value. Custom properties
// are handled separately because arbitrary brace blocks are valid in them.
func hasTopLevelCSSBlock(tokens []css.Token) bool {
	depth := 0
	havePrelude := false
	for _, token := range tokens {
		switch token.TokenType {
		case css.WhitespaceToken, css.CommentToken:
			continue
		case css.FunctionToken, css.LeftParenthesisToken, css.LeftBracketToken:
			if depth == 0 {
				havePrelude = true
			}
			depth++
		case css.RightParenthesisToken, css.RightBracketToken:
			if depth > 0 {
				depth--
			}
		case css.LeftBraceToken:
			if depth == 0 {
				return havePrelude
			}
			depth++
		case css.RightBraceToken:
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				havePrelude = true
			}
		}
	}
	return false
}

func hasCSSToken(tokens []css.Token, kind css.TokenType) bool {
	for _, token := range tokens {
		if token.TokenType == kind {
			return true
		}
	}
	return false
}

func cssNestingGroup(name string) bool {
	switch asciiLower(name) {
	case "@media", "@supports", "@container", "@layer", "@scope", "@starting-style":
		return true
	}
	return false
}

// tdewolff exposes the bodies of these rule-bearing at-rules as opaque token
// streams. Their nested selectors therefore cannot be evaluated here even
// though supporting clients may apply them.
func opaqueRuleBearingAtRule(name string) bool {
	switch asciiLower(name) {
	case "@container", "@scope", "@starting-style":
		return true
	}
	return false
}

func (s *sheet) invalidateMediaCache() {
	s.runtime.mediaCache = nil
}

func tokenString(v []css.Token) string {
	return trimCSSWhitespace(rawTokenString(v))
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
	unsupportedColours    int
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
		if equalASCIIFoldBytes(token.Data, "var(") {
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
	for _, token := range ts {
		if token.TokenType == css.BadStringToken || token.TokenType == css.BadURLToken {
			return parsedDeclarationValue{text: trimCSSWhitespace(fallback), status: valueInvalid}
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
	if last >= start && ts[last].TokenType == css.IdentToken && equalASCIIFoldBytes(ts[last].Data, "important") {
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
	unsupportedColours := 0
	for _, token := range ts[start:end] {
		if token.TokenType == css.FunctionToken && isUnsupportedColourFunction(string(token.Data)) {
			unsupportedColours++
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
	return parsedDeclarationValue{text: text, status: valueResolved, important: important, unsupportedColours: unsupportedColours}
}

// parseDeclarationTokens preserves CSS token boundaries while decoding the
// identifier escapes that the supported property grammars need. In
// particular, an escaped '!' remains part of an identifier and cannot become
// an !important delimiter, and an escaped space cannot disappear through
// string trimming.
func parseDeclarationTokens(ts []valueToken, status valueStatus, fallback string) parsedDeclarationValue {
	if status != valueResolved {
		return parsedDeclarationValue{text: trimCSSWhitespace(fallback), tokens: ts, status: status, unsupportedColours: countUnsupportedColourFunctions(ts)}
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
	if last >= start && ts[last].kind == css.IdentToken && equalASCIIFold(cssUnescape(ts[last].raw), "important") {
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
		unsupportedColours:    countUnsupportedColourFunctions(preparedTokens),
	}
}

func (s *sheet) declarations(prop, value string) []declaration {
	tokens, status := lexValue(value)
	return s.declarationsFromTokens(prop, tokens, status, value)
}

func ownedValueTokens(values []css.Token, raw string) ([]valueToken, valueStatus) {
	tokens := make([]valueToken, 0, len(values))
	offset := 0
	for _, token := range values {
		next := offset + len(token.Data)
		if next > len(raw) {
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
		prop = asciiLower(prop)
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
	case "-webkit-animation":
		return "animation"
	case "-webkit-animation-name":
		return "animation-name"
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
	case "margin", "overflow", "background", "mask", "font", "all", "animation", "animation-name":
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
	s.unsupportedColours += parsed.unsupportedColours
	if custom && (parsed.status == valueInvalid || (parsed.status == valueResolved && !validVariableFunctions(parsed.tokens))) {
		return nil
	}
	prepared := func(d declaration) declaration {
		d.unsupported = d.unsupported || parsed.status == valueUnsupported
		d.valueTokens = parsed.tokens
		d.valueStatus = parsed.status
		d.tokensReady = tokensReady
		return s.prepareDeclaration(d)
	}
	s.order++
	if custom {
		return []declaration{prepared(declaration{prop: -1, custom: prop, value: value, important: imp, order: s.order})}
	}
	if prop == "animation" || prop == "animation-name" {
		// Keep the animation shorthand and longhand in one cascade slot. Values
		// are interpreted only as active/inactive after variable substitution;
		// keyframe declarations themselves remain outside the presentation
		// cascade.
		return []declaration{prepared(declaration{
			prop: animationProperty, value: value, important: imp, order: s.order,
			shorthand: true, animationShorthand: prop == "animation", unsupported: parsed.unsafeIdentifier,
		})}
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
			out = append(out, s.prepareDeclaration(d))
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
			out = append(out, s.prepareDeclaration(d))
		}
		return out
	}
	for p, n := range names {
		if n == prop {
			return []declaration{prepared(declaration{prop: p, value: value, important: imp, order: s.order, unsupported: parsed.unsafeIdentifier})}
		}
	}
	if prop == "background" {
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
		return s.prepareDeclarations(backgroundDeclarationsTokens(asciiLower(value), parsed.tokens, parsed.status, imp, s.order))
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
	// Decoding an escaped identifier can change its token type or boundaries.
	// Standards-based clients reject those values, but legacy clients also use
	// this syntax for compatibility hacks such as display:none\9. Preserve the
	// uncertainty for tracked properties above; unrelated properties remain
	// irrelevant to the visibility model.
	if parsed.unsafeWithoutFunction {
		return nil
	}
	return nil
}

func overflowShorthandValues(value string) ([2]string, bool, bool) {
	var out [2]string
	value = trimCSSWhitespace(value)
	if value == "" {
		return out, false, false
	}
	// Functions can contain whitespace or substitute one or two components.
	// Retain the complete shorthand for resolution after variable substitution.
	if strings.Contains(value, "(") {
		out[0], out[1] = value, value
		return out, true, true
	}
	parts := splitCSSWhitespace(value)
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
	value = trimCSSWhitespace(value)
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
	fields := splitCSSWhitespace(value)
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
		// CSS keywords and unit identifiers are ASCII case-insensitive. Normalize
		// before this shorthand-specific validation, which runs earlier than the
		// ordinary declaration resolver's normalization.
		component = normalizeCSSKeyword(component)
		out[i] = component
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
type cssParseResult struct {
	declarations []declaration
	incomplete   bool
}

// parseCSS preserves the compact declaration-only interface used by internal
// callers that do not need localized inline-error handling. A stylesheet parse
// error invalidates the shared cascade; callers parsing a style attribute use
// parseInlineCSS so the uncertainty can remain local to that element.
func (s *sheet) parseCSS(text string, inline bool) []declaration {
	result := s.parseCSSResult(text, inline)
	if result.incomplete && !inline {
		s.abandonCascade()
	}
	return result.declarations
}

func (s *sheet) parseInlineCSS(text string) cssParseResult {
	return s.parseCSSResult(text, true)
}

func (s *sheet) parseCSSResult(text string, inline bool) cssParseResult {
	if !inline {
		s.invalidateMediaCache()
	}
	if !s.admitCSS(text) {
		return cssParseResult{}
	}
	compatibility := parserCompatibleCSS(text, s.shouldStop)
	if compatibility.stopped {
		s.stopped = true
		return cssParseResult{}
	}
	p := css.NewParserWithLimits(parse.NewInputString(compatibility.text), inline, css.ResourceLimits{
		ShouldStop: s.shouldStop,
		Memory:     s.memory,
	})
	var conditions *conditionFrame
	// Each at-rule temporarily suspends its enclosing qualified rule. Keep
	// this separate from conditions, which are retained by parsed rules.
	var enclosingRules []int
	var nestedGroups []bool
	// Record the qualified-rule depth at which each block at-rule began.
	// tdewolff also reports keyframe selectors such as "from" as rulesets;
	// this lets us distinguish those from a qualified rule nested directly
	// inside another qualified rule.
	var atRuleRulesetDepth []int
	conditionDepth := 0
	rulesetDepth := 0
	defaultNamespace := false
	current := -1
	// CSS permits @import only before ordinary rules and block at-rules. The
	// statement forms of @charset and @layer do not close that import window;
	// every assignment below corresponds to syntax that does.
	importsAllowed := !inline
	var out []declaration
	grammarEnd := 0
	for {
		if s.cascadeIncomplete || s.stopped {
			return cssParseResult{declarations: out}
		}
		grammarStart := grammarEnd
		g, tokenType, data := p.Next()
		grammarEnd = p.Offset()
		values := p.Values()
		switch g {
		case css.ErrorGrammar:
			if !p.HasParseError() {
				err := p.Err()
				if errors.Is(err, css.ErrResourceStopped) {
					s.stopped = true
					return cssParseResult{declarations: out}
				}
				var limitErr *css.ResourceLimitError
				if errors.As(err, &limitErr) || errors.Is(err, css.ErrUnsafeDelimiter) {
					if inline {
						return cssParseResult{declarations: out, incomplete: true}
					}
					s.abandonCascade()
				}
				return cssParseResult{declarations: out}
			}
			insideNestedGroup := len(nestedGroups) > 0 && nestedGroups[len(nestedGroups)-1]
			if !inline && rulesetDepth > 0 && (hasTopLevelCSSBlock(values) || (current < 0 && insideNestedGroup)) {
				s.noteUnsupportedNesting()
			}
			// Recovery inside an inline at-rule can consume its closing brace
			// without emitting EndAtRuleGrammar. Subsequent declarations would
			// then look nested and be silently discarded. The block boundary
			// is no longer reliable: preserve local uncertainty instead.
			if inline && conditions != nil {
				return cssParseResult{declarations: out, incomplete: true}
			}
			// A stray right brace in a qualified-rule prelude can make
			// tdewolff silently pop its enclosing at-rule state without
			// emitting EndAtRuleGrammar. Its reported tokenType is whitespace,
			// but the brace remains in Values. Do not retain our now-stale
			// condition frame and misclassify later top-level rules.
			if !inline && conditions != nil && hasCSSToken(values, css.RightBraceToken) {
				return cssParseResult{declarations: out, incomplete: true}
			}
			// tdewolff's declaration recovery decrements its nesting level for
			// an unmatched ')' or ']'. The level then remains negative, so the
			// recovery routine can consume later declarations or the rest of
			// the sheet. Other reported parse errors recover at the normal CSS
			// boundary and remain safe to skip.
			if tokenType == css.RightParenthesisToken || tokenType == css.RightBracketToken {
				return cssParseResult{declarations: out, incomplete: true}
			}
			continue
		case css.BeginAtRuleGrammar:
			importsAllowed = false
			if !inline && opaqueRuleBearingAtRule(string(data)) {
				s.unresolvedStylesheet = true
			}
			// Descriptor declarations inside @page, @font-face and similar
			// blocks never belong to an enclosing qualified rule. Clear the
			// active rule before tdewolff emits the block's declarations so
			// they cannot override declarations on that outer selector. Restore
			// the enclosing rule only when this at-rule's block ends.
			enclosingRule := current
			current = -1
			if !s.checkCPU() {
				return cssParseResult{declarations: out}
			}
			vals := tokenString(values)
			var cond mediaCondition
			switch asciiLower(string(data)) {
			case "@media":
				cond = s.parseMediaCondition(vals)
			case "@font-face":
				cond = mediaCondition{{schemes: colourSchemeBoth, never: true}}
			case "@keyframes", "@-webkit-keyframes":
				if !inline {
					s.recordKeyframeName(values)
				}
				cond = mediaCondition{{schemes: colourSchemeBoth, never: true}}
			default:
				cond = mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
			}
			conditions = newConditionFrame(cond, conditions)
			enclosingRules = append(enclosingRules, enclosingRule)
			parentNested := len(nestedGroups) > 0 && nestedGroups[len(nestedGroups)-1]
			nestedGroups = append(nestedGroups, cssNestingGroup(string(data)) && (enclosingRule >= 0 || parentNested))
			atRuleRulesetDepth = append(atRuleRulesetDepth, rulesetDepth)
			conditionDepth++
		case css.EndAtRuleGrammar:
			current = -1
			if conditions != nil {
				conditions = conditions.parent
				conditionDepth--
				current = enclosingRules[len(enclosingRules)-1]
				enclosingRules = enclosingRules[:len(enclosingRules)-1]
				nestedGroups = nestedGroups[:len(nestedGroups)-1]
				atRuleRulesetDepth = atRuleRulesetDepth[:len(atRuleRulesetDepth)-1]
			}
		case css.AtRuleGrammar:
			if !s.checkCPU() {
				return cssParseResult{declarations: out}
			}
			name := asciiLower(string(data))
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
			// Newer tdewolff releases emit nested qualified rules directly
			// instead of routing them through declaration-error recovery.
			// MilterGuard does not yet resolve CSS nesting, so preserve the
			// conservative whole-stylesheet uncertainty used for older parser
			// event streams.
			nestedQualifiedRule := rulesetDepth > 0 &&
				(len(atRuleRulesetDepth) == 0 || rulesetDepth > atRuleRulesetDepth[len(atRuleRulesetDepth)-1])
			if !inline && (nestedQualifiedRule || len(nestedGroups) > 0 && nestedGroups[len(nestedGroups)-1]) {
				s.noteUnsupportedNesting()
			}
			rulesetDepth++
			current = -1
			if inline {
				// Rulesets are not valid members of a style attribute. In
				// particular, do not let a ruleset nested in a malformed inline
				// at-rule escape into the document stylesheet.
				continue
			}
			selector := tokenString(values)
			if !s.checkCPU() {
				return cssParseResult{declarations: out}
			}
			plans := planSelectorList(selector, &s.planCount, s.memory)
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
					plans[i].makeUncertain(s.memory)
				}
			}
			s.selectors += len(plans)
			s.rulesSeen++
			if !s.memory.Reserve(int64(unsafe.Sizeof(rule{})) + int64(len(plans))*int64(unsafe.Sizeof(selectorPlan{}))) {
				s.abandonCascade()
				return cssParseResult{declarations: out}
			}
			r := rule{plans: plans, conditions: conditions}
			s.rules = append(s.rules, r)
			current = len(s.rules) - 1
		case css.EndRulesetGrammar:
			current = -1
			if rulesetDepth > 0 {
				rulesetDepth--
			}
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			// Unlike selectors and media queries, declaration values can end
			// with an escaped whitespace character. Preserve the raw token data
			// so it cannot be mistaken for insignificant surrounding space.
			if !s.checkCPU() {
				return cssParseResult{declarations: out}
			}
			prop, propertySafe := compatibility.declarationProperty(string(data), grammarStart, grammarEnd)
			insideNestedGroup := len(nestedGroups) > 0 && nestedGroups[len(nestedGroups)-1]
			if !inline && rulesetDepth > 0 && g != css.CustomPropertyGrammar && (hasTopLevelCSSBlock(values) || (current < 0 && insideNestedGroup)) {
				s.noteUnsupportedNesting()
				continue
			}
			applicable := (inline && conditions == nil) || (!inline && current >= 0)
			if !applicable || !relevantNormalizedDeclarationProperty(prop) {
				continue
			}
			if !propertySafe {
				return cssParseResult{declarations: out, incomplete: true}
			}
			vals := rawTokenString(values)
			var declarations []declaration
			vals, compatibilityRestored, compatibilitySafe := compatibility.restoreDeclarationValue(vals, grammarStart, grammarEnd)
			if !compatibilitySafe {
				// Parser output could not be aligned with the rewritten source.
				// Retain the declaration as uncertain rather than evaluating bytes
				// that may differ from the author's value.
				valueTokens, _ := lexValue(vals)
				declarations = s.declarationsFromTokens(prop, valueTokens, valueUnsupported, vals)
			} else if compatibilityRestored {
				// Re-tokenize after restoring only the delimiters inserted by the
				// compatibility pass. Author-written escapes remain untouched.
				valueTokens, valueStatus := lexValue(vals)
				declarations = s.declarationsFromTokens(prop, valueTokens, valueStatus, vals)
			} else if g == css.CustomPropertyGrammar {
				// tdewolff deliberately exposes a custom-property value as one
				// opaque CustomPropertyValue token. Lex that payload once here so
				// var() dependencies and !important retain their CSS token boundaries.
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
func (s *sheet) parseStylesheet(text, media string, uncertainOrigin bool) {
	firstRule := len(s.rules)
	s.parseCSS(text, false)
	if uncertainOrigin {
		s.markRulesUncertain(firstRule)
	}
	s.attachMediaCondition(firstRule, media)
}

func (s *sheet) markRulesUncertain(firstRule int) {
	for i := firstRule; i < len(s.rules); i++ {
		s.rules[i].uncertainOrigin = true
	}
}

func (s *sheet) attachMediaCondition(firstRule int, media string) {
	if trimCSSWhitespace(media) == "" {
		return
	}
	condition := s.parseMediaCondition(media)
	frames := make(map[*conditionFrame]*conditionFrame)
	for i := firstRule; i < len(s.rules); i++ {
		parent := s.rules[i].conditions
		frame := frames[parent]
		if frame == nil {
			frame = newConditionFrame(condition, parent)
			frames[parent] = frame
		}
		s.rules[i].conditions = frame
	}
}
