package htmlextract

import (
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// Conservative estimates for retained selector maps and their entries. Slice
// and struct payloads whose sizes are known continue to use unsafe.Sizeof.
const (
	ancestorStateEntryBytes     int64 = 48
	ancestorStateMapBytes       int64 = 128
	selectorIndexMapEntryBytes  int64 = 48
	selectorIndexMapsBytes      int64 = 768
	attributeCandidateBaseBytes int64 = 64
	attributeCandidateMapBytes  int64 = 128
)

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
			if mapStates && s.memory.Reserve(ancestorStateEntryBytes) {
				if states == nil {
					if !s.memory.Reserve(ancestorStateMapBytes) {
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
	if !s.memory.Reserve(int64(planCount)*(int64(unsafe.Sizeof(selectorRef{}))+selectorIndexMapEntryBytes) + selectorIndexMapsBytes) {
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
	cacheBytes := attributeCandidateBaseBytes + int64(len(cached.direct)+len(cached.ancestor))*int64(unsafe.Sizeof([]selectorRef{}))
	if s.runtime.attributeCandidates == nil {
		if s.memory.Reserve(cacheBytes + attributeCandidateMapBytes) {
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
