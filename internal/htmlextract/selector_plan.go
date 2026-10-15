package htmlextract

import (
	"strings"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type selectorKeyKind uint8

const (
	selectorUniversal selectorKeyKind = iota
	selectorTag
	selectorID
	selectorClass
	selectorAncestorTag
	selectorAncestorID
	selectorAncestorClass
)

type selectorKey struct {
	kind  selectorKeyKind
	value string
}

type selectorComplexity struct {
	compounds   []compoundComplexity
	combinators []byte
}

type compoundComplexity struct {
	source             string
	attributeSensitive bool
}

// selectorAttributeCandidates records the non-empty selector-index buckets
// selected by an element's immutable id and class attributes. Building this
// once avoids re-tokenizing an ancestor's class value for every descendant and
// every viewing case.
type selectorAttributeCandidates struct {
	direct, ancestor [][]selectorRef
}

// activeAncestorBuckets is the selector-index state for the current DFS path.
// Candidate buckets are activated after an element is resolved, so they apply
// to descendants but never to the element that supplied the key. Reference
// counts keep repeated ancestor keys active until their outermost contributor
// exits. Maintaining this state replaces an uncharged parent-chain walk; the
// existing per-descendant bucket charge remains unchanged.
type activeAncestorBuckets struct {
	buckets   [][]selectorRef
	counts    []int
	positions []int // active position plus one; zero means inactive
	enabled   bool
}

type selectorAncestorActivation struct {
	tag        []selectorRef
	attributes [][]selectorRef
}

func (a *activeAncestorBuckets) reset(selectorCount int) {
	if len(a.counts) < selectorCount {
		a.counts = make([]int, selectorCount)
		a.positions = make([]int, selectorCount)
	} else {
		clear(a.counts)
		clear(a.positions)
	}
	clear(a.buckets)
	a.buckets = a.buckets[:0]
}

func (a *activeAncestorBuckets) add(bucket []selectorRef) {
	if len(bucket) == 0 {
		return
	}
	key := bucket[0].sequence
	if a.counts[key] == 0 {
		a.positions[key] = len(a.buckets) + 1
		a.buckets = append(a.buckets, bucket)
	}
	a.counts[key]++
}

func (a *activeAncestorBuckets) remove(bucket []selectorRef) {
	if len(bucket) == 0 {
		return
	}
	key := bucket[0].sequence
	if a.counts[key] == 0 {
		return
	}
	a.counts[key]--
	if a.counts[key] != 0 {
		return
	}
	position := a.positions[key] - 1
	last := len(a.buckets) - 1
	if position != last {
		moved := a.buckets[last]
		a.buckets[position] = moved
		a.positions[moved[0].sequence] = position + 1
	}
	a.buckets[last] = nil
	a.buckets = a.buckets[:last]
	a.positions[key] = 0
}

func selectorCompoundComplexity(part string) compoundComplexity {
	complexity := compoundComplexity{source: part}
	brackets := 0
	var quote byte
	for i := 0; i < len(part); i++ {
		c := part[i]
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
			if brackets == 0 {
				complexity.attributeSensitive = true
			}
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '.':
			if brackets == 0 {
				complexity.attributeSensitive = true
			}
		case '#':
			if brackets == 0 {
				complexity.attributeSensitive = true
			}
		}
	}
	return complexity
}

func (c selectorComplexity) attributeSensitive() bool {
	for _, compound := range c.compounds {
		if compound.attributeSensitive {
			return true
		}
	}
	return false
}

type selectorPlan struct {
	source          string
	matcher         cascadia.Sel
	scope           cascadia.Matcher
	ancestorChain   []cascadia.Matcher
	specificity     cascadia.Specificity
	complexity      selectorComplexity
	execution       selectorComplexity
	key             selectorKey
	scopePrefix     string
	sequence        int
	ancestorCache   int
	uncertain       bool
	generatedPseudo bool
	foreignCaseType bool
}

func (p *selectorPlan) makeUncertain(memory *resourceguard.Memory) {
	p.uncertain = true
	scope, execution := p.conservativeScope()
	p.scope = compileConservativeScope(scope, memory)
	p.matcher = nil
	p.ancestorChain = nil
	p.specificity = cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}
	p.execution = execution
}

func (p *selectorPlan) makeForeignCaseUncertain(memory *resourceguard.Memory) {
	p.uncertain = true
	p.matcher = nil
	p.ancestorChain = nil
	p.specificity = cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}
	// A mixed-case SVG type in an ancestor cannot be evaluated by Cascadia.
	// Retain only the rightmost compound so the rule cannot be missed. When the
	// target itself is a canonical mixed-case SVG type, match that local name
	// with HTML/foreign namespace case rules instead of Cascadia's lowercase
	// type matcher.
	p.execution = scopeSelectorComplexity(p.scopePrefix)
	if name, ok := canonicalSVGTypeSelector(p.scopePrefix); ok {
		lower := asciiLower(name)
		p.scope = cascadia.Selector(func(n *html.Node) bool {
			if n.Type != html.ElementNode {
				return false
			}
			if n.Namespace == "" {
				return n.Data == lower
			}
			return n.Data == name
		})
		return
	}
	p.scope = compileConservativeScope(p.scopePrefix, memory)
}

// conservativeScope retains only conditions that are necessary for the full
// selector to match. In particular, an understood final descendant or child
// relationship is safe to preserve even when an earlier, expensive part of
// the selector has to be abandoned. This prevents a rule such as
// "u + .body .product img" from degrading all the way to every img element.
func (p *selectorPlan) conservativeScope() (string, selectorComplexity) {
	fallback := scopeSelectorComplexity(p.scopePrefix)
	if p.scopePrefix == "" || p.scopePrefix == "*" || len(p.complexity.compounds) < 2 {
		return p.scopePrefix, fallback
	}
	last := len(p.complexity.compounds) - 1
	combinator := p.complexity.combinators[last-1]
	if combinator != ' ' && combinator != '>' {
		return p.scopePrefix, fallback
	}
	right := trimCSSWhitespace(p.complexity.compounds[last].source)
	left := trimCSSWhitespace(p.complexity.compounds[last-1].source)
	if right != p.scopePrefix || left == "" || left == "*" || positiveCompoundPrefix(left) != left {
		return p.scopePrefix, fallback
	}
	separator := " "
	if combinator == '>' {
		separator = ">"
	}
	scope := left + separator + right
	group, err := cascadia.ParseGroup(scope)
	if err != nil || len(group) != 1 {
		return p.scopePrefix, fallback
	}
	return scope, selectorComplexity{
		compounds:   []compoundComplexity{p.complexity.compounds[last-1], p.complexity.compounds[last]},
		combinators: []byte{combinator},
	}
}

// compileAncestorChain prepares attribute-sensitive descendant/child selectors
// and selectors with repeated descendant searches for bounded matching.
// Cascadia remains authoritative for each compound; evaluating relationships
// ourselves avoids recursive backtracking and lets work be charged against the
// attributes of each node actually inspected.
func compileAncestorChain(complexity selectorComplexity, memory *resourceguard.Memory) []cascadia.Matcher {
	if len(complexity.combinators) == 0 {
		return nil
	}
	descendants := 0
	for _, combinator := range complexity.combinators {
		if combinator != ' ' && combinator != '>' {
			return nil
		}
		if combinator == ' ' {
			descendants++
		}
	}
	// Tag-only selectors with at most one descendant search have a cheap exact
	// Cascadia bound and do not need per-node attribute accounting.
	if descendants < 2 && !complexity.attributeSensitive() {
		return nil
	}
	matchers := make([]cascadia.Matcher, len(complexity.compounds))
	for i, compound := range complexity.compounds {
		group, err := cascadia.ParseGroupWithMemory(compound.source, memory)
		if err != nil || len(group) != 1 {
			return nil
		}
		matchers[i] = group[0]
	}
	return matchers
}

type selectorMatchContext struct {
	elements map[*html.Node]elementPreparation
}

type selectorRef struct {
	rule, branch int
	sequence     int
}

type selectorIndex struct {
	universal       []selectorRef
	tags            map[string][]selectorRef
	ids             map[string][]selectorRef
	classes         map[string][]selectorRef
	ancestorTags    map[string][]selectorRef
	ancestorIDs     map[string][]selectorRef
	ancestorClasses map[string][]selectorRef
	count           int
	ancestorCount   int
}

func planSelectorList(source string, nextSequence *int, memory *resourceguard.Memory) []selectorPlan {
	var plans []selectorPlan
	start, brackets, parens := 0, 0, 0
	var quote byte
	appendBranch := func(end int) {
		branch := trimCSSWhitespace(source[start:end])
		if branch == "" {
			return
		}
		if plan, keep := planSelectorBranch(branch, *nextSequence, memory); keep {
			plans = append(plans, plan)
			(*nextSequence)++
		}
	}
	for i := 0; i < len(source); i++ {
		c := source[i]
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
			if brackets == 0 {
				parens++
			}
		case ')':
			if brackets == 0 && parens > 0 {
				parens--
			}
		case ',':
			if brackets == 0 && parens == 0 {
				appendBranch(i)
				start = i + 1
			}
		}
	}
	appendBranch(len(source))
	return plans
}

func planSelectorBranch(branch string, sequence int, memory *resourceguard.Memory) (selectorPlan, bool) {
	supported, inactive := true, false
	generatedPseudo := false
	brackets, parens, combinators := 0, 0, 0
	compoundStart, rightmostStart := 0, 0
	var quote byte
	complexity := selectorComplexity{}
	var compoundPrefixes []string
	finishCompound := func(end int) {
		part := trimCSSWhitespace(branch[compoundStart:end])
		if part != "" {
			complexity.compounds = append(complexity.compounds, selectorCompoundComplexity(part))
			compoundPrefixes = append(compoundPrefixes, positiveCompoundPrefix(part))
		}
	}
	for i := 0; i < len(branch); i++ {
		c := branch[i]
		if c == '\\' {
			if i+1 >= len(branch) {
				supported = false
			} else {
				i++
			}
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
		if c == ']' {
			if brackets == 0 {
				supported = false
			} else {
				brackets--
			}
			continue
		}
		if brackets > 0 {
			continue
		}
		if c == '(' {
			parens++
			continue
		}
		if c == ')' {
			if parens == 0 {
				supported = false
			} else {
				parens--
			}
			continue
		}
		if parens > 0 {
			continue
		}
		if c == '|' {
			supported = false
			continue
		}
		if c == ':' {
			nameStart := i + 1
			nameEnd := nameStart
			for nameEnd < len(branch) && isSelectorNameByte(branch[nameEnd]) {
				nameEnd++
			}
			name := asciiLower(branch[nameStart:nameEnd])
			if (name == "before" || name == "after") && nameEnd == len(branch) {
				// Both the modern ::before/::after spelling and the legacy
				// single-colon spelling are valid. Restrict this marker to a
				// terminal pseudo-element; escaped colons and pseudos nested in a
				// functional selector never reach this branch.
				generatedPseudo = i == 0 || branch[i-1] != ':' || i == 1 || branch[i-2] != ':'
			}
			switch name {
			case "hover", "focus", "focus-visible", "focus-within", "active", "visited":
				inactive = true
			case "root":
			case "not":
				if nameEnd >= len(branch) || branch[nameEnd] != '(' {
					supported = false
					continue
				}
				end := strings.IndexByte(branch[nameEnd+1:], ')')
				if end < 0 {
					supported = false
					continue
				}
				arg := branch[nameEnd+1 : nameEnd+1+end]
				if strings.ContainsAny(arg, ":(),>+~ \t\r\n") {
					supported = false
				}
				i = nameEnd + end + 1
			default:
				supported = false
			}
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' {
			j := i + 1
			for j < len(branch) && strings.ContainsRune(" \t\r\n\f", rune(branch[j])) {
				j++
			}
			prevExplicit := i > 0 && strings.ContainsRune(">+~", rune(branch[i-1]))
			nextExplicit := j < len(branch) && strings.ContainsRune(">+~", rune(branch[j]))
			if !prevExplicit && !nextExplicit && trimCSSWhitespace(branch[compoundStart:i]) != "" && j < len(branch) {
				finishCompound(i)
				complexity.combinators = append(complexity.combinators, ' ')
				combinators++
				compoundStart, rightmostStart = j, j
			}
			i = j - 1
			continue
		}
		if c == '>' || c == '+' || c == '~' {
			finishCompound(i)
			complexity.combinators = append(complexity.combinators, c)
			combinators++
			j := i + 1
			for j < len(branch) && strings.ContainsRune(" \t\r\n\f", rune(branch[j])) {
				j++
			}
			compoundStart, rightmostStart = j, j
			i = j - 1
		}
	}
	finishCompound(len(branch))
	if quote != 0 || brackets != 0 || parens != 0 || combinators > 32 || len(complexity.compounds) != len(complexity.combinators)+1 {
		supported = false
	}
	if inactive {
		return selectorPlan{}, false
	}
	prefix := positiveCompoundPrefix(trimCSSWhitespace(branch[rightmostStart:]))
	key := selectorIndexKey(prefix)
	if key.kind == selectorUniversal {
		ancestorOnly := true
		for _, combinator := range complexity.combinators {
			ancestorOnly = ancestorOnly && (combinator == ' ' || combinator == '>')
		}
		if ancestorOnly {
			for i := len(compoundPrefixes) - 2; i >= 0; i-- {
				key = ancestorSelectorKey(selectorIndexKey(compoundPrefixes[i]))
				if key.kind != selectorUniversal {
					break
				}
			}
		}
	}
	foreignCaseType := false
	for _, compoundPrefix := range compoundPrefixes {
		if _, ok := canonicalSVGTypeSelector(compoundPrefix); ok {
			foreignCaseType = true
			break
		}
	}
	plan := selectorPlan{source: branch, sequence: sequence, complexity: complexity, execution: complexity, key: key, scopePrefix: prefix, generatedPseudo: generatedPseudo, foreignCaseType: foreignCaseType}
	if supported {
		group, err := cascadia.ParseGroupWithMemory(branch, memory)
		if err == nil && len(group) == 1 {
			plan.matcher = group[0]
			plan.specificity = group[0].Specificity()
			if foreignCaseType {
				plan.makeForeignCaseUncertain(memory)
				return plan, true
			}
			// The lightweight structural planner does not decode hexadecimal CSS
			// escapes. In particular, the optional whitespace terminating an
			// escape is not a descendant combinator. Leave escaped selectors to
			// Cascadia's authoritative matcher rather than compiling a potentially
			// different ancestor chain.
			if !strings.Contains(branch, `\`) {
				plan.ancestorChain = compileAncestorChain(complexity, memory)
			}
			return plan, true
		}
	}
	plan.makeUncertain(memory)
	return plan, true
}

var canonicalSVGTagNames = map[string]struct{}{
	"altGlyph": {}, "altGlyphDef": {}, "altGlyphItem": {},
	"animateColor": {}, "animateMotion": {}, "animateTransform": {},
	"clipPath": {}, "feBlend": {}, "feColorMatrix": {},
	"feComponentTransfer": {}, "feComposite": {}, "feConvolveMatrix": {},
	"feDiffuseLighting": {}, "feDisplacementMap": {}, "feDistantLight": {},
	"feFlood": {}, "feFuncA": {}, "feFuncB": {}, "feFuncG": {}, "feFuncR": {},
	"feGaussianBlur": {}, "feImage": {}, "feMerge": {}, "feMergeNode": {},
	"feMorphology": {}, "feOffset": {}, "fePointLight": {},
	"feSpecularLighting": {}, "feSpotLight": {}, "feTile": {}, "feTurbulence": {},
	"foreignObject": {}, "glyphRef": {}, "linearGradient": {},
	"radialGradient": {}, "textPath": {},
}

func canonicalSVGTypeSelector(prefix string) (string, bool) {
	if prefix == "" || prefix[0] == '.' || prefix[0] == '#' || prefix[0] == '*' || strings.Contains(prefix, "|") {
		return "", false
	}
	end := strings.IndexAny(prefix, ".#")
	if end < 0 {
		end = len(prefix)
	}
	name := prefix[:end]
	_, ok := canonicalSVGTagNames[name]
	return name, ok
}

func scopeSelectorComplexity(prefix string) selectorComplexity {
	return selectorComplexity{compounds: []compoundComplexity{selectorCompoundComplexity(prefix)}}
}

func ancestorSelectorKey(key selectorKey) selectorKey {
	switch key.kind {
	case selectorTag:
		key.kind = selectorAncestorTag
	case selectorID:
		key.kind = selectorAncestorID
	case selectorClass:
		key.kind = selectorAncestorClass
	default:
		return selectorKey{}
	}
	return key
}

func isSelectorNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func positiveCompoundPrefix(compound string) string {
	for i := 0; i < len(compound); i++ {
		if compound[i] == '\\' {
			i++
			continue
		}
		if compound[i] == ':' || compound[i] == '[' {
			return trimCSSWhitespace(compound[:i])
		}
		if compound[i] == '|' {
			// Cascadia does not implement CSS namespaces. A namespace prefix is
			// not an element name: s|text can only match an element whose local
			// name is text, never an HTML <s>. Retaining that local name gives
			// the uncertain plan a useful but still conservative candidate set.
			// Wildcards, escapes and the || column combinator cannot be narrowed
			// safely here and therefore use universal scope.
			start := i + 1
			if start >= len(compound) || compound[start] == '|' || compound[start] == '*' || compound[start] == '\\' {
				return ""
			}
			end := start
			for end < len(compound) && isSelectorNameByte(compound[end]) {
				end++
			}
			if end == start {
				return ""
			}
			// Foreign element names are case-sensitive. The existing HTML tag
			// index and Cascadia's type selector both fold names to lower case,
			// so retain a local-name constraint only when folding is a no-op.
			if local := compound[start:end]; local != asciiLower(local) {
				return ""
			}
			return asciiLower(compound[start:end])
		}
	}
	return trimCSSWhitespace(compound)
}

var universalScopeMatcher cascadia.Matcher = cascadia.Selector(func(*html.Node) bool { return true })

func compileConservativeScope(prefix string, memory *resourceguard.Memory) cascadia.Matcher {
	if prefix == "" || prefix == "*" {
		return universalScopeMatcher
	}
	group, err := cascadia.ParseGroupWithMemory(prefix, memory)
	if err != nil || len(group) != 1 {
		return universalScopeMatcher
	}
	return group[0]
}

func selectorIndexKey(prefix string) selectorKey {
	if prefix == "" || prefix == "*" || strings.ContainsAny(prefix, "\\|[") {
		return selectorKey{}
	}
	var tag, id, class string
	for i := 0; i < len(prefix); {
		kind := byte(0)
		if prefix[i] == '#' || prefix[i] == '.' {
			kind = prefix[i]
			i++
		}
		start := i
		for i < len(prefix) && isSelectorNameByte(prefix[i]) {
			i++
		}
		if start == i {
			return selectorKey{}
		}
		value := prefix[start:i]
		switch kind {
		case '#':
			id = value
		case '.':
			if class == "" {
				class = value
			}
		default:
			if tag != "" {
				return selectorKey{}
			}
			tag = asciiLower(value)
		}
	}
	if id != "" {
		return selectorKey{kind: selectorID, value: id}
	}
	if class != "" {
		return selectorKey{kind: selectorClass, value: class}
	}
	if tag != "" {
		return selectorKey{kind: selectorTag, value: tag}
	}
	return selectorKey{}
}

type ancestorChainState struct {
	matched uint64
	seen    uint64
}

type ancestorStateEntry struct {
	node  *html.Node
	state ancestorChainState
}

func ancestorChainNeedsMap(complexity selectorComplexity) bool {
	descendants := 0
	for _, combinator := range complexity.combinators {
		if combinator == ' ' {
			descendants++
		}
	}
	return descendants > 1
}

// matchAncestorChain evaluates descendant/child selector chains in bounded
// dynamic-programming time. Cascadia's combined matcher recursively retries
// earlier compounds for every possible ancestor and can therefore perform
// binomial work for a chain of descendant combinators. Cached prefix states
// make each (plan,node) pair linear in the number of compounds, and all work
// is interruptibly charged.
func (s *sheet) matchAncestorChain(plan *selectorPlan, n *html.Node, context selectorMatchContext, budget *cpuGuard) (bool, bool) {
	if len(plan.ancestorChain) != len(plan.complexity.compounds) || len(plan.ancestorChain) != len(plan.complexity.combinators)+1 {
		return false, false
	}
	ancestorCount := max(s.index.ancestorCount, plan.ancestorCache+1)
	mapStates := ancestorChainNeedsMap(plan.complexity)
	var states map[*html.Node]ancestorChainState
	var recent *ancestorStateEntry
	if mapStates {
		if len(s.runtime.ancestorStates) < ancestorCount {
			if !s.memory.Reserve(int64(ancestorCount) * int64(unsafe.Sizeof(map[*html.Node]ancestorChainState{}))) {
				return false, false
			}
			s.runtime.ancestorStates = make([]map[*html.Node]ancestorChainState, ancestorCount)
		}
		states = s.runtime.ancestorStates[plan.ancestorCache]
	} else {
		if len(s.runtime.ancestorRecent) < ancestorCount {
			if !s.memory.Reserve(int64(ancestorCount) * int64(unsafe.Sizeof(ancestorStateEntry{}))) {
				return false, false
			}
			s.runtime.ancestorRecent = make([]ancestorStateEntry, ancestorCount)
		}
		recent = &s.runtime.ancestorRecent[plan.ancestorCache]
	}
	nodes := s.runtime.ancestorNodes[:0]
	parentState := ancestorChainState{}
	for current := n; current != nil; current = current.Parent {
		if current.Type != html.ElementNode {
			continue
		}
		if !budget.check() {
			return false, false
		}
		if mapStates {
			if state, cached := states[current]; cached {
				parentState = state
				break
			}
		} else if recent.node == current {
			parentState = recent.state
			break
		}
		nodes = append(nodes, current)
	}
	s.runtime.ancestorNodes = nodes
	match := func(index int, node *html.Node) (bool, bool) {
		if !budget.check() {
			return false, false
		}
		return s.matchSelector(plan.ancestorChain[index], node)
	}
	for nodeIndex := len(nodes) - 1; nodeIndex >= 0; nodeIndex-- {
		node := nodes[nodeIndex]
		state := ancestorChainState{}
		matched, complete := match(0, node)
		if !complete {
			return false, false
		}
		if matched {
			state.matched = 1
		}
		for combinatorIndex, combinator := range plan.complexity.combinators {
			compoundIndex := combinatorIndex + 1
			predecessor := uint64(1) << combinatorIndex
			eligible := combinator == ' ' && parentState.seen&predecessor != 0 || combinator == '>' && parentState.matched&predecessor != 0
			if !eligible {
				continue
			}
			matched, complete := match(compoundIndex, node)
			if !complete {
				return false, false
			}
			if matched {
				state.matched |= uint64(1) << compoundIndex
			}
		}
		state.seen = parentState.seen | state.matched
		parentState = state
		// A node without element children can never be encountered as an
		// ancestor of a later match. Tree collection records this once so cache
		// admission never repeatedly scans attacker-controlled child lists.
		// Tests and internal callers without prepared metadata cache
		// conservatively; the shared cache-unit ceiling still bounds retention.
		hasElementChild, complete := preparedHasElementChild(node, context.elements, budget)
		if !complete {
			return false, false
		}
		if hasElementChild {
			if mapStates && s.memory.Reserve(48) {
				if states == nil {
					if !s.memory.Reserve(128) {
						continue
					}
					states = make(map[*html.Node]ancestorChainState)
					s.runtime.ancestorStates[plan.ancestorCache] = states
				}
				states[node] = state
			} else if !mapStates {
				*recent = ancestorStateEntry{node: node, state: state}
			}
		}
	}
	final := uint64(1) << (len(plan.ancestorChain) - 1)
	return parentState.matched&final != 0, true
}

func (s *sheet) buildSelectorIndex() {
	// Rules without any declaration understood by the extractor cannot affect
	// presentation. Removing them also prevents no-op selectors from consuming
	// matching work or match-cache memory.
	original := s.rules
	kept := original[:0]
	for _, rule := range original {
		if len(rule.decls) != 0 && ruleHasEffectiveSelectorPlan(&rule) {
			kept = append(kept, rule)
		}
	}
	clear(original[len(kept):])
	s.rules = kept
	index := selectorIndex{
		tags: map[string][]selectorRef{}, ids: map[string][]selectorRef{}, classes: map[string][]selectorRef{},
		ancestorTags: map[string][]selectorRef{}, ancestorIDs: map[string][]selectorRef{}, ancestorClasses: map[string][]selectorRef{},
	}
	planCount := 0
	for i := range s.rules {
		planCount += len(s.rules[i].plans)
	}
	if !s.memory.Reserve(int64(planCount)*(int64(unsafe.Sizeof(selectorRef{}))+48) + 768) {
		s.abandonCascade()
		return
	}
	for ruleIndex := range s.rules {
		for branchIndex := range s.rules[ruleIndex].plans {
			plan := &s.rules[ruleIndex].plans[branchIndex]
			if harmlessGeneratedPseudoPlan(plan, s.rules[ruleIndex].decls) {
				continue
			}
			ref := selectorRef{rule: ruleIndex, branch: branchIndex, sequence: plan.sequence}
			index.count = max(index.count, plan.sequence+1)
			if plan.ancestorChain != nil {
				plan.ancestorCache = index.ancestorCount
				index.ancestorCount++
			}
			switch plan.key.kind {
			case selectorTag:
				index.tags[plan.key.value] = append(index.tags[plan.key.value], ref)
			case selectorID:
				index.ids[plan.key.value] = append(index.ids[plan.key.value], ref)
			case selectorClass:
				index.classes[plan.key.value] = append(index.classes[plan.key.value], ref)
			case selectorAncestorTag:
				index.ancestorTags[plan.key.value] = append(index.ancestorTags[plan.key.value], ref)
			case selectorAncestorID:
				index.ancestorIDs[plan.key.value] = append(index.ancestorIDs[plan.key.value], ref)
			case selectorAncestorClass:
				index.ancestorClasses[plan.key.value] = append(index.ancestorClasses[plan.key.value], ref)
			default:
				index.universal = append(index.universal, ref)
			}
		}
	}
	s.index = index
	s.runtime.matchCaches = nil
	s.runtime.ancestorRecent = nil
	s.runtime.ancestorStates = nil
	s.runtime.attributeCandidates = nil
}

// A generated pseudo-element has no existing text of its own. A rule whose
// only retained effect is display:none therefore cannot alter the visibility
// of text in the source document. Keep every other generated-pseudo rule
// uncertain: ::before and ::after can create painted boxes and overlay source
// text, and another relevant declaration may override display within the rule.
func harmlessGeneratedPseudoPlan(plan *selectorPlan, decls []declaration) bool {
	if !plan.generatedPseudo || len(decls) != 1 {
		return false
	}
	d := &decls[0]
	return d.prop == display && d.custom == "" && !d.shorthand && !d.unsupported &&
		d.prepared != nil && d.prepared.status == valueResolved &&
		d.prepared.value.Known && d.prepared.value.Text == "none"
}

func ruleHasEffectiveSelectorPlan(rule *rule) bool {
	for i := range rule.plans {
		if !harmlessGeneratedPseudoPlan(&rule.plans[i], rule.decls) {
			return true
		}
	}
	return false
}

func (s *sheet) attributeCandidateBuckets(node *html.Node, budget *cpuGuard) (selectorAttributeCandidates, bool) {
	if len(node.Attr) == 0 {
		return selectorAttributeCandidates{}, true
	}
	if cached, ok := s.runtime.attributeCandidates[node]; ok {
		return cached, true
	}
	var cached selectorAttributeCandidates
	if budget != nil && !budget.check() {
		return cached, false
	}
	var id, classes string
	var idSeen, classesSeen bool
	for _, attribute := range node.Attr {
		switch attribute.Key {
		case "id":
			if !idSeen {
				id, idSeen = attribute.Val, true
			}
		case "class":
			if !classesSeen {
				classes, classesSeen = attribute.Val, true
			}
		}
		if idSeen && classesSeen {
			break
		}
	}
	appendIndexed := func(value string, direct, ancestor map[string][]selectorRef) bool {
		lookups := 0
		if len(direct) != 0 {
			lookups++
		}
		if len(ancestor) != 0 {
			lookups++
		}
		if budget != nil && lookups != 0 && !budget.check() {
			return false
		}
		if bucket := direct[value]; len(bucket) != 0 {
			cached.direct = append(cached.direct, bucket)
		}
		if bucket := ancestor[value]; len(bucket) != 0 {
			cached.ancestor = append(cached.ancestor, bucket)
		}
		return true
	}
	if id != "" && !appendIndexed(id, s.index.ids, s.index.ancestorIDs) {
		return selectorAttributeCandidates{}, false
	}
	if classes != "" {
		if budget != nil && !budget.check() {
			return selectorAttributeCandidates{}, false
		}
		for start := 0; start < len(classes); {
			for start < len(classes) && isCSSSpace(classes[start]) {
				start++
			}
			end := start
			for end < len(classes) && !isCSSSpace(classes[end]) {
				end++
			}
			if end > start && !appendIndexed(classes[start:end], s.index.classes, s.index.ancestorClasses) {
				return selectorAttributeCandidates{}, false
			}
			start = end
		}
	}
	cacheBytes := int64(64 + (len(cached.direct)+len(cached.ancestor))*int(unsafe.Sizeof([]selectorRef{})))
	if s.runtime.attributeCandidates == nil {
		if s.memory.Reserve(cacheBytes + 128) {
			s.runtime.attributeCandidates = make(map[*html.Node]selectorAttributeCandidates)
			s.runtime.attributeCandidates[node] = cached
		}
		return cached, true
	}
	if s.memory.Reserve(cacheBytes) {
		s.runtime.attributeCandidates[node] = cached
	}
	return cached, true
}

func (s *sheet) hasAncestorSelectorIndex() bool {
	return len(s.index.ancestorTags) != 0 || len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0
}

func preparedHasElementChild(node *html.Node, elements map[*html.Node]elementPreparation, budget *cpuGuard) (bool, bool) {
	if elements != nil {
		return elements[node].hasElementChild, true
	}
	// Package-level matcher tests can operate without a parsedDocument. Keep
	// that path bounded too rather than reintroducing an uncharged child scan.
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if !budget.check() {
			return false, false
		}
		if child.Type == html.ElementNode {
			return true, true
		}
	}
	return false, true
}

// activateAncestorBuckets records the current element's ancestor-index keys
// for its children. Attribute parsing is still charged once through the
// existing bounded cache. Bucket activation itself replaces the previously
// uncharged parent-pointer walk and does not alter the match-work contract.
func (s *sheet) activateAncestorBuckets(node *html.Node, budget *cpuGuard) (selectorAncestorActivation, bool) {
	var activation selectorAncestorActivation
	if !s.runtime.activeAncestors.enabled || !s.hasAncestorSelectorIndex() {
		return activation, true
	}
	tag := node.Data
	if node.Namespace != "" {
		tag = asciiLower(tag)
	}
	activation.tag = s.index.ancestorTags[tag]
	if len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0 {
		attributes, complete := s.attributeCandidateBuckets(node, budget)
		if !complete {
			return selectorAncestorActivation{}, false
		}
		activation.attributes = attributes.ancestor
	}
	s.runtime.activeAncestors.add(activation.tag)
	for _, bucket := range activation.attributes {
		s.runtime.activeAncestors.add(bucket)
	}
	return activation, true
}

func (s *sheet) deactivateAncestorBuckets(activation selectorAncestorActivation) {
	if !s.runtime.activeAncestors.enabled {
		return
	}
	s.runtime.activeAncestors.remove(activation.tag)
	for _, bucket := range activation.attributes {
		s.runtime.activeAncestors.remove(bucket)
	}
}

// collectCandidates builds the union of relevant selector-index buckets. A
// selector plan belongs to exactly one bucket, so the first reference also
// serves as that bucket's stable identity. Marking before append prevents a
// repeated ancestor key from expanding the same bucket at every tree level.
func (s *sheet) collectCandidates(n *html.Node, budget *cpuGuard) ([]selectorRef, bool) {
	if s.index.count == 0 {
		return nil, true
	}
	if len(s.runtime.candidateMarks) < s.index.count {
		if !s.memory.Reserve(int64(s.index.count) * int64(unsafe.Sizeof(uint32(0)))) {
			return nil, false
		}
		s.runtime.candidateMarks = make([]uint32, s.index.count)
	}
	s.runtime.candidateGeneration++
	if s.runtime.candidateGeneration == 0 {
		clear(s.runtime.candidateMarks)
		s.runtime.candidateGeneration = 1
	}
	generation := s.runtime.candidateGeneration
	refs := s.runtime.candidateScratch[:0]
	appendBucket := func(bucket []selectorRef) bool {
		if len(bucket) == 0 || s.runtime.candidateMarks[bucket[0].sequence] == generation {
			return true
		}
		if budget != nil && !budget.check() {
			return false
		}
		for _, ref := range bucket {
			if s.runtime.candidateMarks[ref.sequence] == generation {
				continue
			}
			s.runtime.candidateMarks[ref.sequence] = generation
			refs = append(refs, ref)
		}
		return true
	}
	tag := n.Data
	if n.Namespace != "" {
		tag = asciiLower(tag)
	}
	if !appendBucket(s.index.universal) || !appendBucket(s.index.tags[tag]) {
		s.runtime.candidateScratch = refs
		return nil, false
	}
	if len(s.index.ids) != 0 || len(s.index.classes) != 0 {
		attributes, complete := s.attributeCandidateBuckets(n, budget)
		if !complete {
			s.runtime.candidateScratch = refs
			return nil, false
		}
		for _, bucket := range attributes.direct {
			if !appendBucket(bucket) {
				s.runtime.candidateScratch = refs
				return nil, false
			}
		}
	}
	if s.runtime.activeAncestors.enabled {
		for _, bucket := range s.runtime.activeAncestors.buckets {
			if !appendBucket(bucket) {
				s.runtime.candidateScratch = refs
				return nil, false
			}
		}
	} else if s.hasAncestorSelectorIndex() {
		for ancestor := n.Parent; ancestor != nil; ancestor = ancestor.Parent {
			if ancestor.Type != html.ElementNode {
				continue
			}
			ancestorTag := ancestor.Data
			if ancestor.Namespace != "" {
				ancestorTag = asciiLower(ancestorTag)
			}
			if !appendBucket(s.index.ancestorTags[ancestorTag]) {
				s.runtime.candidateScratch = refs
				return nil, false
			}
			if len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0 {
				attributes, complete := s.attributeCandidateBuckets(ancestor, budget)
				if !complete {
					s.runtime.candidateScratch = refs
					return nil, false
				}
				for _, bucket := range attributes.ancestor {
					if !appendBucket(bucket) {
						s.runtime.candidateScratch = refs
						return nil, false
					}
				}
			}
		}
	}
	// No sort is required: candidate.beats compares declaration importance,
	// inline origin, specificity and source order explicitly. Keeping discovery
	// order avoids an O(n log n) phase without changing cascade results.
	s.runtime.candidateScratch = refs
	return refs, true
}

func isCSSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}
