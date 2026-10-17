package htmlextract

import (
	"strings"

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
	p.scope, p.execution = p.conservativeScope(memory)
	p.matcher = nil
	p.ancestorChain = nil
	p.specificity = cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}
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
func (p *selectorPlan) conservativeScope(memory *resourceguard.Memory) (cascadia.Matcher, selectorComplexity) {
	fallback := scopeSelectorComplexity(p.scopePrefix)
	if p.scopePrefix == "" || p.scopePrefix == "*" || len(p.complexity.compounds) < 2 {
		return compileConservativeScope(p.scopePrefix, memory), fallback
	}
	last := len(p.complexity.compounds) - 1
	combinator := p.complexity.combinators[last-1]
	if combinator != ' ' && combinator != '>' {
		return compileConservativeScope(p.scopePrefix, memory), fallback
	}
	right := trimCSSWhitespace(p.complexity.compounds[last].source)
	left := trimCSSWhitespace(p.complexity.compounds[last-1].source)
	if right != p.scopePrefix || left == "" || left == "*" || positiveCompoundPrefix(left) != left {
		return compileConservativeScope(p.scopePrefix, memory), fallback
	}
	separator := " "
	if combinator == '>' {
		separator = ">"
	}
	scope := left + separator + right
	group, err := cascadia.ParseGroupWithMemory(scope, memory)
	if err != nil || len(group) != 1 {
		return compileConservativeScope(p.scopePrefix, memory), fallback
	}
	return group[0], selectorComplexity{
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

func planSelectorList(source string, nextSequence *int, memory *resourceguard.Memory, remainingBranches int) (plans []selectorPlan, branches int, exceeded bool) {
	start, brackets, parens := 0, 0, 0
	var quote byte
	appendBranch := func(end int) {
		branch := trimCSSWhitespace(source[start:end])
		if branch == "" {
			return
		}
		if branches >= remainingBranches {
			exceeded = true
			return
		}
		branches++
		if plan, keep := planSelectorBranch(branch, *nextSequence, memory); keep {
			plans = append(plans, plan)
			(*nextSequence)++
		}
	}
	for i := 0; i < len(source) && !exceeded; i++ {
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
	if !exceeded {
		appendBranch(len(source))
	}
	return plans, branches, exceeded
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
