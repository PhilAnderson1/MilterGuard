package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
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
// samples cooperative cancellation.
func (s *sheet) matchAncestorChain(plan *selectorPlan, n *html.Node, context selectorMatchContext, budget *cpuGuard) (bool, bool) {
	if len(plan.ancestorChain) != len(plan.complexity.compounds) || len(plan.ancestorChain) != len(plan.complexity.combinators)+1 {
		return false, false
	}
	ancestorCount := max(s.index.ancestorCount, plan.ancestorCache+1)
	mapStates := ancestorChainNeedsMap(plan.complexity)
	var states map[*html.Node]ancestorChainState
	var recent *ancestorStateEntry
	if mapStates {
		if len(s.runtime.ancestorStates) >= ancestorCount {
			states = s.runtime.ancestorStates[plan.ancestorCache].View()
		}
	} else {
		if len(s.runtime.ancestorRecent) < ancestorCount {

			if recent, ok := resourceguard.TryMakeSlice[ancestorStateEntry](s.memory, ancestorCount, ancestorCount); ok {
				s.runtime.ancestorRecent = recent
			}

		}
		if len(s.runtime.ancestorRecent) >= ancestorCount {
			recent = &s.runtime.ancestorRecent[plan.ancestorCache]
		}
	}
	nodes := s.runtime.ancestorNodes[:0]
	parentState := ancestorChainState{}
	for current := n; current != nil; current = current.Parent {
		if current.Type != html.ElementNode {
			continue
		}

		budget.check()

		if mapStates {

			if state, cached := states[current]; cached {
				parentState = state
				break
			}

		} else if recent != nil && recent.node == current {
			parentState = recent.state
			break
		}

		nodes = growSlice(nodes, 1, s.memory, s.shouldStop)

		nodes = append(nodes, current)
	}
	s.runtime.ancestorNodes = nodes
	match := func(index int, node *html.Node) bool {
		budget.check()

		return s.matchSelector(plan.ancestorChain[index], node)
	}
	for nodeIndex := len(nodes) - 1; nodeIndex >= 0; nodeIndex-- {
		node := nodes[nodeIndex]
		state := ancestorChainState{}
		matched := match(0, node)

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
			matched := match(compoundIndex, node)

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
		hasElementChild := preparedHasElementChild(node, context.elements, budget)

		if hasElementChild {
			if mapStates {
				if len(s.runtime.ancestorStates) < ancestorCount {
					grown, ok := resourceguard.TryMakeSlice[resourceguard.Table[*html.Node, ancestorChainState]](s.memory, ancestorCount, ancestorCount)
					if !ok {
						continue
					}
					copy(grown, s.runtime.ancestorStates)
					s.runtime.ancestorStates = grown
				}
				cache := &s.runtime.ancestorStates[plan.ancestorCache]
				if cache.TrySet(s.memory, node, state) {
					states = cache.View()
				}
			} else if recent != nil {
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
	var index selectorIndex
	var buckets [6]resourceguard.Table[string, []selectorRef]
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
			bucket := -1
			switch plan.key.kind {
			case selectorTag:
				bucket = 0
			case selectorID:
				bucket = 1
			case selectorClass:
				bucket = 2
			case selectorAncestorTag:
				bucket = 3
			case selectorAncestorID:
				bucket = 4
			case selectorAncestorClass:
				bucket = 5
			}
			if bucket < 0 {
				index.universal = resourceguard.Append(s.memory, index.universal, s.shouldStop, ref)
			} else {
				{
					table := &buckets[bucket]
					refs, _ := table.Get(plan.key.value)
					refs = resourceguard.Append(s.memory, refs, s.shouldStop, ref)

					table.Set(s.memory, plan.key.value, refs)
				}
			}
		}
	}
	index.tags, index.ids, index.classes = buckets[0].View(), buckets[1].View(), buckets[2].View()
	index.ancestorTags, index.ancestorIDs, index.ancestorClasses = buckets[3].View(), buckets[4].View(), buckets[5].View()
	s.index = index
	s.runtime.matchCaches = nil
	s.runtime.ancestorRecent = nil
	s.runtime.ancestorStates = nil
	s.runtime.attributeCandidates.Release()
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

func (s *sheet) attributeCandidateBuckets(node *html.Node, budget *cpuGuard) selectorAttributeCandidates {
	var result selectorAttributeCandidates
	needID := len(s.index.ids) != 0 || len(s.index.ancestorIDs) != 0
	needClass := len(s.index.classes) != 0 || len(s.index.ancestorClasses) != 0
	if len(node.Attr) == 0 || !needID && !needClass {
		return result
	}

	if cached, ok := s.runtime.attributeCandidates.View()[node]; ok {
		return cached
	}

	budget.check()

	if len(s.runtime.attributeMarks) < s.index.count {
		s.runtime.attributeMarks = resourceguard.MakeSlice[uint32](s.memory, s.index.count, s.index.count)
	}
	s.runtime.attributeGeneration++
	if s.runtime.attributeGeneration == 0 {
		clear(s.runtime.attributeMarks)
		s.runtime.attributeGeneration = 1
	}
	generation := s.runtime.attributeGeneration
	appendBucket := func(out *[][]selectorRef, bucket []selectorRef) {
		if len(bucket) == 0 || s.runtime.attributeMarks[bucket[0].sequence] == generation {
			return
		}
		s.runtime.attributeMarks[bucket[0].sequence] = generation
		grown := growSlice(*out, 1, s.memory, s.shouldStop)

		*out = append(grown, bucket)
		return
	}
	appendIndexed := func(value string, direct, ancestor map[string][]selectorRef) {
		budget.check()
		appendBucket(&result.direct, direct[value])
		appendBucket(&result.ancestor, ancestor[value])
		return
	}
	var id, classes string
	idSeen, classSeen := !needID, !needClass
	for _, attribute := range node.Attr {
		budget.check()

		switch attribute.Key {
		case "id":
			if !idSeen {
				id, idSeen = attribute.Val, true
			}
		case "class":
			if !classSeen {
				classes, classSeen = attribute.Val, true
			}
		}
		if idSeen && classSeen {
			break
		}
	}

	if id != "" {
		appendIndexed(id, s.index.ids, s.index.ancestorIDs)
	}

	for start := 0; start < len(classes); {
		for start < len(classes) && isCSSSpace(classes[start]) {
			budget.check()

			start++
		}
		end := start
		for end < len(classes) && !isCSSSpace(classes[end]) {
			budget.check()

			end++
		}

		if end > start {
			appendIndexed(classes[start:end], s.index.classes, s.index.ancestorClasses)
		}

		start = end
	}
	// Negative entries only pay off when another viewing case or ancestor
	// activation may reuse this lookup. Positive entries also avoid reallocation.
	if len(result.direct)+len(result.ancestor) == 0 && !s.runtime.cacheMatches && !s.hasAncestorSelectorIndex() {
		return result
	}

	s.runtime.attributeCandidates.Set(s.memory, node, result)

	return result
}

func (s *sheet) hasAncestorSelectorIndex() bool {
	return len(s.index.ancestorTags) != 0 || len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0
}

func preparedHasElementChild(node *html.Node, elements map[*html.Node]elementPreparation, budget *cpuGuard) bool {
	if elements != nil {
		return elements[node].hasElementChild
	}
	// Package-level matcher tests can operate without a parsedDocument. Keep
	// that path bounded too rather than reintroducing an uncharged child scan.
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		budget.check()

		if child.Type == html.ElementNode {
			return true
		}
	}
	return false
}

// activateAncestorBuckets records the current element's ancestor-index keys
// for its children. Attribute parsing is reused through the bounded cache,
// avoiding a parent-pointer walk during candidate collection.
func (s *sheet) activateAncestorBuckets(node *html.Node, budget *cpuGuard) selectorAncestorActivation {
	var activation selectorAncestorActivation
	if !s.runtime.activeAncestors.enabled || !s.hasAncestorSelectorIndex() {
		return activation
	}
	tag := node.Data
	if node.Namespace != "" {
		tag = asciiLowerWithBudget(tag, budget)
	}
	activation.tag = s.index.ancestorTags[tag]
	if len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0 {
		attributes := s.attributeCandidateBuckets(node, budget)

		activation.attributes = attributes.ancestor
	}
	s.runtime.activeAncestors.add(activation.tag)
	for _, bucket := range activation.attributes {
		s.runtime.activeAncestors.add(bucket)
	}
	return activation
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
func (s *sheet) collectCandidates(n *html.Node, budget *cpuGuard) []selectorRef {
	if s.index.count == 0 {
		return nil
	}
	if len(s.runtime.candidateMarks) < s.index.count {
		s.runtime.candidateMarks = resourceguard.MakeSlice[uint32](s.memory, s.index.count, s.index.count)
	}
	s.runtime.candidateGeneration++
	if s.runtime.candidateGeneration == 0 {
		clear(s.runtime.candidateMarks)
		s.runtime.candidateGeneration = 1
	}
	generation := s.runtime.candidateGeneration
	refs := s.runtime.candidateScratch[:0]
	appendBucket := func(bucket []selectorRef) {
		if len(bucket) == 0 || s.runtime.candidateMarks[bucket[0].sequence] == generation {
			return
		}

		if budget != nil {
			budget.check()
		}

		s.runtime.candidateMarks[bucket[0].sequence] = generation
		refs = growSlice(refs, len(bucket), s.memory, s.shouldStop)

		for _, ref := range bucket {
			budget.check()

			refs = append(refs, ref)
		}
		return
	}
	tag := n.Data
	if n.Namespace != "" {
		tag = asciiLowerWithBudget(tag, budget)
	}

	appendBucket(s.index.universal)
	appendBucket(s.index.tags[tag])

	if len(s.index.ids) != 0 || len(s.index.classes) != 0 {
		attributes := s.attributeCandidateBuckets(n, budget)

		for _, bucket := range attributes.direct {
			appendBucket(bucket)
		}
	}
	if s.runtime.activeAncestors.enabled {
		for _, bucket := range s.runtime.activeAncestors.buckets {
			appendBucket(bucket)
		}
	} else if s.hasAncestorSelectorIndex() {
		panic("htmlextract: ancestor selector index not activated")
	}

	// No sort is required: candidate.beats compares declaration importance,
	// inline origin, specificity and source order explicitly. Keeping discovery
	// order avoids an O(n log n) phase without changing cascade results.
	s.runtime.candidateScratch = refs
	return refs
}

func isCSSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}
