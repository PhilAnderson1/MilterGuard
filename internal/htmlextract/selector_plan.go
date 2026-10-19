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

type compoundComplexity = cascadia.CompoundMetadata

// Ancestor matching records one compound per bit in ancestorChainState.
const maxAncestorChainCompounds = 64

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
// exits. Maintaining this state avoids walking the parent chain for every node.
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

func (a *activeAncestorBuckets) reset(selectorCount int, memory *resourceguard.Memory) bool {
	if len(a.counts) < selectorCount {
		if !memory.Reserve(int64(selectorCount) * (2*int64(unsafe.Sizeof(int(0))) + int64(unsafe.Sizeof([]selectorRef{})))) {
			return false
		}
		a.buckets = make([][]selectorRef, 0, selectorCount)
		a.counts = make([]int, selectorCount)
		a.positions = make([]int, selectorCount)
	} else {
		clear(a.counts)
		clear(a.positions)
	}
	clear(a.buckets)
	a.buckets = a.buckets[:0]
	return true
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

func (c selectorComplexity) attributeSensitive() bool {
	for _, compound := range c.compounds {
		if compound.AttributeSensitive {
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
	p.scope = p.conservativeScope(memory)
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
	name := p.complexity.compounds[len(p.complexity.compounds)-1].OriginalTypeName
	if _, ok := canonicalSVGTagNames[name]; !ok {
		name = ""
	}
	if name == "" {
		name, _ = canonicalSVGTypeSelector(p.scopePrefix)
	}
	if name != "" {
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
	p.scope = p.complexity.compounds[len(p.complexity.compounds)-1].PositiveMatcher
	if p.scope == nil {
		p.scope = compileConservativeScope(p.scopePrefix, memory)
	}
}

// conservativeScope retains only conditions that are necessary for the full
// selector to match. In particular, an understood final descendant or child
// relationship is safe to preserve even when an earlier, expensive part of
// the selector has to be abandoned. This prevents a rule such as
// "u + .body .product img" from degrading all the way to every img element.
func (p *selectorPlan) conservativeScope(memory *resourceguard.Memory) cascadia.Matcher {
	rightmost := p.complexity.compounds[len(p.complexity.compounds)-1]
	rightMatcher := rightmost.PositiveMatcher
	if rightMatcher == nil {
		rightMatcher = compileConservativeScope(p.scopePrefix, memory)
	}

	if len(p.complexity.compounds) < 2 {
		return rightMatcher
	}
	last := len(p.complexity.compounds) - 1
	combinator := p.complexity.combinators[last-1]
	if combinator != ' ' && combinator != '>' {
		return rightMatcher
	}
	left := p.complexity.compounds[last-1]
	if !rightmost.FullyPositive || !left.FullyPositive || left.PositiveMatcher == nil {
		return rightMatcher
	}
	scope := cascadia.CombinePositiveMatchers(left.PositiveMatcher, rightMatcher, combinator)
	if scope == nil {
		return rightMatcher
	}
	return scope
}

// compileAncestorChain prepares attribute-sensitive descendant/child selectors
// and selectors with repeated descendant searches for bounded matching.
// Cascadia remains authoritative for each compound; evaluating relationships
// ourselves avoids recursive backtracking and samples cancellation while
// inspecting each node and compound.
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
	if !memory.Reserve(int64(len(complexity.compounds)) * int64(unsafe.Sizeof([1]cascadia.Matcher{}))) {
		return nil
	}
	matchers := make([]cascadia.Matcher, len(complexity.compounds))
	for i, compound := range complexity.compounds {
		if compound.Matcher == nil {
			return nil
		}
		matchers[i] = compound.Matcher
	}
	return matchers
}

func selectorComplexityFromMetadata(metadata cascadia.SelectorMetadata) selectorComplexity {
	return selectorComplexity{compounds: metadata.Compounds, combinators: metadata.Combinators}
}

func localSelectorKey(key cascadia.IndexKey) selectorKey {
	switch key.Kind {
	case cascadia.IndexTag:
		return selectorKey{kind: selectorTag, value: key.Value}
	case cascadia.IndexID:
		return selectorKey{kind: selectorID, value: key.Value}
	case cascadia.IndexClass:
		return selectorKey{kind: selectorClass, value: key.Value}
	default:
		return selectorKey{}
	}
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

func planSelectorList(source string, nextSequence *int, memory *resourceguard.Memory, remainingBranches int) ([]selectorPlan, int, bool) {
	plans, branches, exceeded, _ := planSelectorListWithStop(source, nextSequence, memory, remainingBranches, nil)
	return plans, branches, exceeded
}

func planSelectorListWithStop(source string, nextSequence *int, memory *resourceguard.Memory, remainingBranches int, shouldStop func() bool) (plans []selectorPlan, branches int, exceeded, stopped bool) {
	iterator := cascadia.NewSelectorListIteratorWithStop(source, shouldStop)
	for {
		branch, ok := iterator.Next()
		if !ok {
			break
		}
		if branches >= remainingBranches {
			exceeded = true
			break
		}
		branches++
		if plan, keep := planSelectorBranch(branch, *nextSequence, memory); keep {
			var admitted bool
			plans, admitted = growSlice(plans, 1, memory)
			if !admitted {
				return plans, branches, false, iterator.Stopped()
			}
			plans = append(plans, plan)
			(*nextSequence)++
		}
	}
	return plans, branches, exceeded, iterator.Stopped()
}

func planSelectorBranch(branch string, sequence int, memory *resourceguard.Memory) (selectorPlan, bool) {
	group, err := cascadia.ParseGroupWithPseudoElementsAndMemory(branch, memory)
	if memory.Exhausted() {
		return selectorPlan{}, false
	}
	if err == nil && len(group) == 1 {
		metadata, err := cascadia.MetadataWithMemory(group[0], memory)
		if err != nil {
			return selectorPlan{}, false
		}
		if metadata.Inactive {
			return selectorPlan{}, false
		}
		plan := planCompiledSelector(branch, sequence, group[0], metadata, memory)
		if !metadata.Supported {
			plan.makeUncertain(memory)
		}
		return plan, true
	}

	fallback, fallbackErr := cascadia.ConservativeFallbackWithMemory(branch, memory)
	if fallbackErr != nil {
		return selectorPlan{}, false
	}
	compound := compoundComplexity{FullyPositive: true}
	plan := selectorPlan{
		source:          branch,
		complexity:      selectorComplexity{compounds: []compoundComplexity{compound}},
		key:             localSelectorKey(fallback.Key),
		scopePrefix:     fallback.PositiveSource,
		sequence:        sequence,
		generatedPseudo: fallback.GeneratedPseudo,
	}
	if _, ok := canonicalSVGTagNames[fallback.OriginalTypeName]; ok {
		plan.foreignCaseType = true
		plan.makeForeignCaseUncertain(memory)
	} else {
		plan.makeUncertain(memory)
	}
	return plan, true
}

func planCompiledSelector(branch string, sequence int, selector cascadia.Sel, metadata cascadia.SelectorMetadata, memory *resourceguard.Memory) selectorPlan {
	complexity := selectorComplexityFromMetadata(metadata)
	rightmost := metadata.Compounds[len(metadata.Compounds)-1]
	plan := selectorPlan{
		source:          branch,
		matcher:         selector,
		specificity:     selector.Specificity(),
		complexity:      complexity,
		key:             localSelectorKey(rightmost.Key),
		sequence:        sequence,
		generatedPseudo: metadata.PseudoElement != "",
	}
	if plan.key.kind == selectorUniversal {
		ancestorOnly := true
		for _, combinator := range metadata.Combinators {
			ancestorOnly = ancestorOnly && (combinator == ' ' || combinator == '>')
		}
		if ancestorOnly {
			for i := len(metadata.Compounds) - 2; i >= 0; i-- {
				plan.key = ancestorSelectorKey(localSelectorKey(metadata.Compounds[i].Key))
				if plan.key.kind != selectorUniversal {
					break
				}
			}
		}
	}
	for _, compound := range metadata.Compounds {
		if _, ok := canonicalSVGTagNames[compound.OriginalTypeName]; ok {
			plan.foreignCaseType = true
			break
		}
	}
	if plan.foreignCaseType {
		plan.makeForeignCaseUncertain(memory)
		return plan
	}
	plan.ancestorChain = compileAncestorChain(complexity, memory)
	if len(plan.ancestorChain) > maxAncestorChainCompounds {
		plan.makeUncertain(memory)
	}
	return plan
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
