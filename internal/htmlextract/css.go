package htmlextract

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// These structural bounds prevent tiny CSS constructs from amplifying into
// unbounded numbers of retained selector and cache objects. They deliberately
// count stable application concepts rather than Go allocator bytes.
const (
	maxSelectorBranches  = 4_096
	maxMatchCacheEntries = 65_536
	maxCSSDeclarations   = 32_768
)

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
	prop          int
	value         string
	prepared      *preparedDeclaration
	validity      valueStatus
	validityReady bool
	valueTokens   []valueToken
	mathLiterals  []mathLiteral
	valueStatus   valueStatus
	tokensReady   bool
	hasVars       bool
	keyword       string
	important     bool
	order         int
	unsupported   bool
	custom        string
	// Deferred edge shorthands borrow their source until variable substitution.
	edgeCount            uint8
	edgeIndex            uint8
	shorthand            bool
	animationShorthand   bool
	animation            *animationValue
	variableDependencies []string
	variableBlocks       []valueBlock
	dependenciesReady    bool
}

type preparedDeclaration struct {
	value  Value
	status valueStatus
}

func (d *declaration) setTokens(tokens []valueToken, status valueStatus, ready bool) {
	d.valueTokens = tokens
	d.valueStatus = status
	d.tokensReady = ready
}

func (d *declaration) ensureTokens(budget *cpuGuard) {
	if d.tokensReady {
		return
	}
	d.valueTokens, d.valueStatus = lexValue(d.value, budget)
	d.tokensReady = true
}

func (d *declaration) recordVariableDependencies(budget *cpuGuard) {
	if !d.hasVars || !d.tokensReady || d.valueStatus != valueResolved {
		return
	}
	d.variableBlocks = indexValueBlocks(d.valueTokens, budget)

	d.variableDependencies = variableRefs(d.valueTokens, budget)
	d.dependenciesReady = true
}

func (d *declaration) setPrepared(value Value, status valueStatus, budget *cpuGuard) {
	d.prepared = resourceguard.New(budget.allocationMemory(), preparedDeclaration{value: value, status: status})

	d.validity = status
	d.validityReady = true
	// The prepared value is the complete runtime representation. Keeping the
	// parser token stream as well only retains duplicate strings and slices.
	d.valueTokens = nil
	d.mathLiterals = nil
	d.tokensReady = false
}

func (d *declaration) setValidity(status valueStatus) {
	d.validity = status
	d.validityReady = true
}

func (d *declaration) discardTransientState() {
	d.valueTokens = nil
	d.mathLiterals = nil
	d.tokensReady = false
	d.variableDependencies = nil
	d.variableBlocks = nil
	d.dependenciesReady = false
}

// contextualDeclaration reports whether computing the value requires an
// element's inherited/root style. Variables and shorthands are handled by the
// caller because their substituted value may change this answer.
func contextualDeclaration(d declaration, budget *cpuGuard) bool {
	value := normalizeCSSKeywordWithBudget(d.value, budget)
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
func prepareDeclaration(d declaration, budget *cpuGuard) declaration {
	if d.prepared != nil {
		return d
	}
	if d.tokensReady {
		d.hasVars = tokensHaveVariables(d.valueTokens)
	} else {
		d.hasVars = hasVariablesWithBudget(d.value, budget)
	}
	if d.custom != "" {
		d.keyword = normalizeCSSKeywordWithBudget(d.value, budget)
	}
	if (d.custom != "" || d.hasVars) && !d.tokensReady {
		d.ensureTokens(budget)
	}
	d.recordVariableDependencies(budget)
	if d.prop == animationProperty && d.custom == "" {
		// Cache context-independent name parsing, including escaped identifiers
		// that the conservative hasVars fast path initially treated as dynamic.
		if !d.hasVars || d.tokensReady && !tokensHaveVariables(d.valueTokens) {
			value := parseAnimationValue(d.value, d.animationShorthand, budget)
			d.animation = resourceguard.New(budget.allocationMemory(), value)
		}
		return d
	}
	if d.custom == "" && !d.hasVars && !d.shorthand && !contextualDeclaration(d, budget) {
		prepared := preparedDeclaration{}
		if d.unsupported {
			prepared.value = Value{Text: d.value}
			prepared.status = valueUnsupported
		} else {
			prepared.value, prepared.status = resolveWithBudget(d.prop, d.value, &initialStyle, &initialStyle, budget)
		}
		d.setPrepared(prepared.value, prepared.status, budget)
	} else if d.custom == "" && !d.hasVars && !d.shorthand && !d.unsupported {
		value := normalizeCSSKeywordWithBudget(d.value, budget)
		if (d.prop == fontSize || d.prop == opacity) && isMath(value) && d.tokensReady && d.valueStatus == valueResolved {
			d.mathLiterals = prepareMathLiterals(d.valueTokens, budget)
			_, d.validity = evalPreparedMathTokens(d.prop, value, d.valueTokens, d.mathLiterals, &initialStyle, &initialStyle, budget)
		} else {
			_, d.validity = resolveWithBudget(d.prop, value, &initialStyle, &initialStyle, budget)
		}
		d.setValidity(d.validity)
	}

	return d
}

func prepareDeclarations(ds []declaration, budget *cpuGuard) []declaration {
	for i := range ds {
		ds[i] = prepareDeclaration(ds[i], budget)
	}
	return ds
}

func (s *sheet) prepareDeclaration(d declaration) declaration {
	s.checkCPU()

	d = prepareDeclaration(d, s.cpu)
	return d
}

func (s *sheet) prepareDeclarations(ds []declaration) []declaration {
	for i := range ds {
		ds[i] = s.prepareDeclaration(ds[i])
	}
	return ds
}

type rule struct {
	mediaGroup      int
	plans           []selectorPlan
	decls           []declaration
	conditions      *conditionFrame
	uncertainOrigin bool
}

// sheetRuntime contains evaluation caches and reusable scratch storage. Rules,
// declarations and selector plans remain immutable once selector and media
// grouping preparation completes.
type sheetRuntime struct {
	variableMemo        declarationScopeMemo
	mediaGroups         []*conditionFrame
	mediaCache          resourceguard.Table[mediaCacheKey, []uint8]
	cacheMatches        bool
	matchCaches         []resourceguard.Table[*html.Node, uint8]
	matchCacheEntries   int
	attributeCandidates resourceguard.Table[*html.Node, selectorAttributeCandidates]
	attributeMarks      []uint32
	attributeGeneration uint32
	candidateScratch    []selectorRef
	candidateMarks      []uint32
	candidateGeneration uint32
	ancestorNodes       []*html.Node
	ancestorRecent      []ancestorStateEntry
	ancestorStates      []resourceguard.Table[*html.Node, ancestorChainState]
	activeAncestors     activeAncestorBuckets
	variableScratch     resourceguard.Table[string, candidate]
}

type sheet struct {
	rules                []rule
	order                int
	limits               Limits
	cascadeIncomplete    bool
	planCount            int
	selectorBranches     int
	declarationCount     int
	index                selectorIndex
	cssBytes             int
	keyframeNames        resourceguard.Table[string, struct{}]
	unresolvedStylesheet bool
	unsupportedNesting   bool
	unsupportedColours   int
	runtime              sheetRuntime
	shouldStop           func()
	selectorControl      *cascadia.MatchControl
	cpu                  *cpuGuard
	memory               *resourceguard.Memory
}

// admitCSS applies the cumulative source and work bounds. Per-construct and
// stack limits are enforced where the local CSS parser grows those resources.
func (s *sheet) admitCSS(text string, mode cssParseMode) bool {
	if s.cascadeIncomplete {
		return false
	}
	if len(text) > s.limits.CSSBytes || s.cssBytes > s.limits.CSSBytes-len(text) {
		if mode == stylesheetCSS {
			s.abandonCascade()
		}
		return false
	}

	// Sample before entering the parser; its loops and declaration processing
	// continue sampling the shared cooperative stop callback.
	s.checkCPU()

	s.cssBytes += len(text)
	return true
}

func (s *sheet) checkCPU() {
	if s.cpu != nil {
		s.cpu.check()
	}
}

func (s *sheet) abandonCascade() {
	s.cascadeIncomplete = true
	s.rules = nil
	s.keyframeNames.Release()
	s.planCount = 0
	s.selectorBranches = 0
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
	for _, known := range [...]string{"@media", "@supports", "@container", "@layer", "@scope", "@starting-style"} {
		if equalASCIIFold(name, known) {
			return true
		}
	}
	return false
}

// tdewolff exposes the bodies of these rule-bearing at-rules as opaque token
// streams. Their nested selectors therefore cannot be evaluated here even
// though supporting clients may apply them.
func opaqueRuleBearingAtRule(name string) bool {
	for _, known := range [...]string{"@container", "@scope", "@starting-style"} {
		if equalASCIIFold(name, known) {
			return true
		}
	}
	return false
}

func (s *sheet) invalidateMediaCache() {
	s.runtime.mediaCache.Release()
	s.runtime.mediaGroups = nil
}

func tokenStringWithBudget(v []css.Token, budget *cpuGuard) string {
	value := trimCSSWhitespaceWithBudget(rawTokenStringWithBudget(v, budget), budget)
	return value
}

func rawTokenStringWithBudget(v []css.Token, budget *cpuGuard) string {
	var b strings.Builder
	size := 0
	for _, t := range v {
		budget.check()

		size += len(t.Data)
	}

	growBuilder(&b, size, budget)

	for _, t := range v {
		budget.check()

		writeBudgetedBytes(&b, t.Data, budget)
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

// Decoding owns one admitted buffer. A two-byte escape can become a three-byte
// replacement rune, so 3/2 of the input length bounds the decoded UTF-8 size.
func cssUnescapeWithBudget(value string, budget *cpuGuard) string {
	if indexByteWithBudget(value, '\\', budget) < 0 {
		return value
	}

	capacity := len(value) + len(value)/2
	var out strings.Builder

	growBuilder(&out, capacity, budget)

	sampled := 0
	for i := 0; i < len(value); {
		if i-sampled >= stringWorkChunk {
			budget.checkpoint()

			sampled = i
		}
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
		for i < len(value) && i-start < 6 && (value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f' || value[i] >= 'A' && value[i] <= 'F') {
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
	return parseUnretainedCSSTokensWithBudget(ts, fallback, nil)
}
func parseUnretainedCSSTokensWithBudget(ts []css.Token, fallback string, budget *cpuGuard) parsedDeclarationValue {
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
		if token.TokenType == css.FunctionToken && isUnsupportedColourFunctionWithBudget(ownedString(token.Data, budget), budget) {
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
	// Reject inconsistent token/source bounds before slicing. Resource failures
	// unwind before this function receives the owned source.
	if endByte > len(fallback) {
		return parsedDeclarationValue{status: valueUnsupported}
	}
	text := fallback[startByte:endByte]
	if hasComment {
		var out strings.Builder

		growBuilder(&out, endByte-startByte, budget)

		for i := start; i < end; i++ {
			if ts[i].TokenType == css.CommentToken {
				out.WriteByte(' ')
			} else {
				writeBudgetedBytes(&out, ts[i].Data, budget)
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
func parseDeclarationTokens(ts []valueToken, status valueStatus, fallback string, budget *cpuGuard) parsedDeclarationValue {
	if status != valueResolved {
		return parsedDeclarationValue{text: trimCSSWhitespace(fallback), tokens: ts, status: status, unsupportedColours: countUnsupportedColourFunctionsWithBudget(ts, budget)}
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
	if last >= start && ts[last].kind == css.IdentToken && equalASCIIFold(cssUnescapeWithBudget(ts[last].raw, budget), "important") {
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
		budget.check()

		t := ts[i]
		hasFunction = hasFunction || t.kind == css.FunctionToken
		if t.kind == css.CommentToken {
			// Keep tokens on either side of a comment from being accidentally
			// joined into a different token.
			writeBudgetedString(&out, " ", budget)

			preparedTokens = append(preparedTokens, valueToken{kind: css.WhitespaceToken, raw: " "})
			continue
		}
		raw := t.raw
		if (t.kind == css.IdentToken || t.kind == css.FunctionToken) && strings.Contains(raw, "\\") {
			decoded := cssUnescapeWithBudget(raw, budget)
			decodedTokens, decodedStatus := lexValue(decoded, budget)
			sameIdentifierClass := t.kind == css.IdentToken && len(decodedTokens) == 1 && decodedTokens[0].kind == css.CustomPropertyNameToken
			if decodedStatus == valueResolved && len(decodedTokens) == 1 && (decodedTokens[0].kind == t.kind || sameIdentifierClass) {
				raw = decoded
			} else {
				unsafe = true
			}
		}

		writeBudgetedString(&out, raw, budget)

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
		unsupportedColours:    countUnsupportedColourFunctionsWithBudget(preparedTokens, budget),
	}
}

func (s *sheet) declarations(prop, value string) []declaration {
	tokens, status := lexValue(value, s.cpu)
	return s.declarationsFromTokens(prop, tokens, status, value)
}

func ownedValueTokens(values []css.Token, raw string, budget *cpuGuard) ([]valueToken, valueStatus) {
	tokens := resourceguard.MakeSlice[valueToken](budget.allocationMemory(), 0, len(values))

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
	return normalizeDeclarationPropertyWithBudget(prop, nil)
}
func normalizeDeclarationPropertyWithBudget(prop string, budget *cpuGuard) string {
	prop = cssUnescapeWithBudget(prop, budget)
	if !strings.HasPrefix(prop, "--") {
		prop = asciiLowerWithBudget(prop, budget)
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
	case "margin", "inset", "inset-inline", "inset-block", "margin-inline", "margin-block", "overflow", "background", "mask", "font", "all", "animation", "animation-name":
		return true
	default:
		return false
	}
}

func (s *sheet) declarationsFromTokens(prop string, tokens []valueToken, status valueStatus, fallback string) []declaration {
	prop = normalizeDeclarationPropertyWithBudget(prop, s.cpu)
	parsed := parseDeclarationTokens(tokens, status, fallback, s.cpu)
	return s.declarationsFromParsed(prop, parsed, true)
}

func (s *sheet) declarationsFromParsed(prop string, parsed parsedDeclarationValue, tokensReady bool) []declaration {
	value := parsed.text
	imp := parsed.important
	custom := strings.HasPrefix(prop, "--")
	s.unsupportedColours += parsed.unsupportedColours
	if custom && (parsed.status == valueInvalid || parsed.status == valueResolved && !validVariableFunctions(parsed.tokens, s.cpu)) {
		return nil
	}
	prepared := func(d declaration) declaration {
		d.unsupported = d.unsupported || parsed.status == valueUnsupported
		d.setTokens(parsed.tokens, parsed.status, tokensReady)
		return s.prepareDeclaration(d)
	}
	s.order++
	if custom {
		return declarationList(s.cpu, prepared(declaration{prop: -1, custom: prop, value: value, important: imp, order: s.order}))
	}
	if prop == "animation" || prop == "animation-name" {
		// Keep the animation shorthand and longhand in one cascade slot. Values
		// are interpreted only as active/inactive after variable substitution;
		// keyframe declarations themselves remain outside the presentation
		// cascade.
		return declarationList(s.cpu, prepared(declaration{
			prop: animationProperty, value: value, important: imp, order: s.order,
			shorthand: true, animationShorthand: prop == "animation", unsupported: parsed.unsafeIdentifier,
		}))
	}
	if prop == "margin" || prop == "inset" || prop == "inset-inline" || prop == "inset-block" || prop == "margin-inline" || prop == "margin-block" {
		values, ok, uncertain := marginShorthandValuesWithBudget(value, s.cpu)
		if !ok {
			return nil
		}
		propertyList := [4]int{marginTop, marginRight, marginBottom, marginLeft}
		count := 4
		switch prop {
		case "inset":
			propertyList = [4]int{top, right, bottom, left}
		case "inset-inline":
			propertyList = [4]int{insetInlineStart, insetInlineEnd}
			count = 2
		case "inset-block":
			propertyList = [4]int{insetBlockStart, insetBlockEnd}
			count = 2
		case "margin-inline":
			propertyList = [4]int{marginInlineStart, marginInlineEnd}
			count = 2
		case "margin-block":
			propertyList = [4]int{marginBlockStart, marginBlockEnd}
			count = 2
		}
		if count == 2 && !uncertain {
			var scratch [4]string
			if len(splitCSSWhitespace(value, scratch[:])) > 2 {
				return nil
			}
		}
		properties := propertyList[:count]
		out := resourceguard.MakeSlice[declaration](s.memory, 0, len(properties))

		hasVariables := tokensHaveVariables(parsed.tokens)
		for i, property := range properties {
			if hasVariables {
				d := declaration{prop: property, value: value, important: imp, order: s.order, shorthand: true, edgeCount: uint8(count), edgeIndex: uint8(i)}
				out = append(out, prepared(d))
				continue
			}
			componentTokens, componentStatus := lexValue(values[i], s.cpu)
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
		out := resourceguard.MakeSlice[declaration](s.memory, 0, len(properties))

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
			return declarationList(s.cpu, prepared(declaration{prop: p, value: value, important: imp, order: s.order, unsupported: parsed.unsafeIdentifier}))
		}
	}
	if prop == "background" {
		if parsed.unsafeIdentifier {
			return declarationList(s.cpu, prepared(declaration{prop: background, value: value, important: imp, order: s.order, shorthand: true, unsupported: true}), prepared(declaration{prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true, unsupported: true}), prepared(declaration{prop: backgroundClip, value: value, important: imp, order: s.order, shorthand: true, unsupported: true}))
		}
		if tokensHaveVariables(parsed.tokens) {
			return declarationList(s.cpu, prepared(declaration{prop: background, value: value, important: imp, order: s.order, shorthand: true}), prepared(declaration{prop: backgroundImage, value: value, important: imp, order: s.order, shorthand: true}), prepared(declaration{prop: backgroundClip, value: value, important: imp, order: s.order, shorthand: true}))
		}
		return s.prepareDeclarations(backgroundDeclarationsTokens(asciiLowerWithBudget(value, s.cpu), parsed.tokens, parsed.status, imp, s.order, s.cpu))
	}
	if prop == "mask" {
		return declarationList(s.cpu, prepared(declaration{prop: maskImage, value: value, important: imp, order: s.order, unsupported: true}))
	}
	var affected []int
	switch prop {
	case "font":
		affected = []int{fontSize}
	case "all":
		if !tokensHaveVariables(parsed.tokens) {
			keyword := normalizeCSSKeywordWithBudget(value, s.cpu)
			if keyword != "initial" && keyword != "inherit" && keyword != "unset" && keyword != "revert" && keyword != "revert-layer" {
				return nil
			}
		}
		return declarationList(s.cpu, prepared(declaration{prop: allShorthandProperty, value: value, important: imp, order: s.order, unsupported: true}))
	}
	if len(affected) > 0 {
		out := resourceguard.MakeSlice[declaration](s.memory, 0, len(affected))

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
	var scratch [2]string
	parts := splitCSSWhitespace(value, scratch[:])
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
	return marginShorthandValuesWithBudget(value, nil)
}
func marginShorthandValuesWithBudget(value string, budget *cpuGuard) ([4]string, bool, bool) {
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
	var scratch [4]string
	fields := splitCSSWhitespace(value, scratch[:])
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
		component = normalizeCSSKeywordWithBudget(component, budget)
		out[i] = component
		property := [...]int{marginTop, marginRight, marginBottom, marginLeft}[i]

		if _, status := resolveLayoutPropertyWithBudget(property, component, budget); status == valueInvalid {
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

type cssParseMode uint8

const (
	stylesheetCSS cssParseMode = iota
	inlineCSS
)

// parseStylesheetCSS invalidates the shared cascade on an incomplete parse.
// Style attributes use parseInlineCSS so their uncertainty remains local to
// the element.
func (s *sheet) parseStylesheetCSS(text string) []declaration {
	result := s.parseCSSResult(text, stylesheetCSS)
	if result.incomplete {
		s.abandonCascade()
	}
	return result.declarations
}

func (s *sheet) parseInlineCSS(text string) cssParseResult {
	return s.parseCSSResult(text, inlineCSS)
}

func (s *sheet) parseCSSResult(text string, mode cssParseMode) cssParseResult {
	session := newCSSParseSession(s, text, mode)
	return session.run(s)
}

type stylesheetOrigin uint8

const (
	trustedStylesheetOrigin stylesheetOrigin = iota
	uncertainStylesheetOrigin
)

// parseStylesheet parses a style element and applies the element's media
// attribute to every rule it contributes. Conditions already attached by
// nested at-rules are retained, making the conditions conjunctive.
func (s *sheet) parseStylesheet(text, media string, origin stylesheetOrigin) {
	firstRule := len(s.rules)
	s.parseStylesheetCSS(text)
	if origin == uncertainStylesheetOrigin {
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
	var frames resourceguard.Table[*conditionFrame, *conditionFrame]
	for i := firstRule; i < len(s.rules); i++ {
		parent := s.rules[i].conditions
		frame, _ := frames.Get(parent)
		if frame == nil {
			frame = newConditionFrame(condition, parent, s.memory)

			frames.Set(s.memory, parent, frame)
		}
		s.rules[i].conditions = frame
	}
}
