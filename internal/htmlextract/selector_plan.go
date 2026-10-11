package htmlextract

import (
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

const siblingMatchWeight int64 = 10

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
	base, classes, ids, attributes int64
}

type selectorAttributeProfile struct {
	classes, ids, attributes int64
}

const selectorBytesPerWorkUnit = 16
const selectorAttributesPerWorkUnit = 16

func selectorByteWork(bytes int) int64 {
	return int64(bytes / selectorBytesPerWorkUnit)
}

func selectorAttributeCountWork(attributes int) int64 {
	return int64(attributes / selectorAttributesPerWorkUnit)
}

func (p *selectorAttributeProfile) observe(n *html.Node) {
	if n.Type != html.ElementNode {
		return
	}
	classWork := selectorAttributeCountWork(len(n.Attr))
	idWork := classWork
	attributeWork := classWork
	for _, attribute := range n.Attr {
		attributeWork += selectorByteWork(len(attribute.Key) + len(attribute.Val) + 1)
		switch attribute.Key {
		case "class":
			classWork += selectorByteWork(len(attribute.Val))
		case "id":
			idWork += selectorByteWork(len(attribute.Val))
		}
	}
	p.classes = max(p.classes, classWork)
	p.ids = max(p.ids, idWork)
	p.attributes = max(p.attributes, attributeWork)
}

func selectorCompoundComplexity(part string) compoundComplexity {
	complexity := compoundComplexity{base: int64(len(part) + 1)}
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
				complexity.attributes++
			}
			brackets++
		case ']':
			if brackets > 0 {
				brackets--
			}
		case '.':
			if brackets == 0 {
				complexity.classes++
			}
		case '#':
			if brackets == 0 {
				complexity.ids++
			}
		}
	}
	return complexity
}

func (c selectorComplexity) attributeSensitive() bool {
	for _, compound := range c.compounds {
		if compound.classes != 0 || compound.ids != 0 || compound.attributes != 0 {
			return true
		}
	}
	return false
}

func selectorCompoundCost(compound compoundComplexity, profile selectorAttributeProfile, limit int64) int64 {
	cap := limit + 1
	cost := compound.base
	for _, term := range []struct{ count, weight int64 }{
		{compound.classes, profile.classes},
		{compound.ids, profile.ids},
		{compound.attributes, profile.attributes},
	} {
		if term.count <= 0 || term.weight <= 0 {
			continue
		}
		if term.count > cap/term.weight {
			return cap
		}
		value := term.count * term.weight
		if cost >= cap || value >= cap || cost > cap-value {
			return cap
		}
		cost += value
	}
	return cost
}

type selectorPlan struct {
	source      string
	matcher     cascadia.Sel
	scope       cascadia.Sel
	specificity cascadia.Specificity
	complexity  selectorComplexity
	execution   selectorComplexity
	key         selectorKey
	scopePrefix string
	cost        int64
	bound       int64
	sequence    int
	uncertain   bool
	matches     map[*html.Node]uint8
}

func (p *selectorPlan) makeUncertain() {
	p.uncertain = true
	p.scope = compileConservativeScope(p.scopePrefix)
	p.matcher = nil
	p.specificity = cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}
	p.execution = scopeSelectorComplexity(p.scopePrefix)
}

type selectorMatchContext struct {
	current, path, document selectorAttributeProfile
	depth, nodes            int
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
}

func planSelectorList(source string, nextSequence *int) []selectorPlan {
	var plans []selectorPlan
	start, brackets, parens := 0, 0, 0
	var quote byte
	appendBranch := func(end int) {
		branch := strings.TrimSpace(source[start:end])
		if branch == "" {
			return
		}
		if plan, keep := planSelectorBranch(branch, *nextSequence); keep {
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

func planSelectorBranch(branch string, sequence int) (selectorPlan, bool) {
	supported, inactive := true, false
	brackets, parens, combinators := 0, 0, 0
	compoundStart, rightmostStart := 0, 0
	var quote byte
	complexity := selectorComplexity{}
	var compoundPrefixes []string
	finishCompound := func(end int) {
		part := strings.TrimSpace(branch[compoundStart:end])
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
			name := strings.ToLower(branch[nameStart:nameEnd])
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
			if !prevExplicit && !nextExplicit && strings.TrimSpace(branch[compoundStart:i]) != "" && j < len(branch) {
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
	prefix := positiveCompoundPrefix(strings.TrimSpace(branch[rightmostStart:]))
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
	plan := selectorPlan{source: branch, sequence: sequence, complexity: complexity, execution: complexity, key: key, scopePrefix: prefix}
	if supported {
		group, err := cascadia.ParseGroup(branch)
		if err == nil && len(group) == 1 {
			plan.matcher = group[0]
			plan.specificity = group[0].Specificity()
			return plan, true
		}
	}
	plan.makeUncertain()
	return plan, true
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
			return strings.TrimSpace(compound[:i])
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
			if local := compound[start:end]; local != strings.ToLower(local) {
				return ""
			}
			return strings.ToLower(compound[start:end])
		}
	}
	return strings.TrimSpace(compound)
}

func compileConservativeScope(prefix string) cascadia.Sel {
	if prefix == "" || prefix == "*" {
		group, _ := cascadia.ParseGroup("*")
		return group[0]
	}
	group, err := cascadia.ParseGroup(prefix)
	if err != nil || len(group) != 1 {
		group, _ = cascadia.ParseGroup("*")
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
			tag = strings.ToLower(value)
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

func plannedSelectorCost(c selectorComplexity, profile selectorAttributeProfile, depth, nodes int, limit int64) int64 {
	if len(c.compounds) == 0 || len(c.compounds) != len(c.combinators)+1 {
		return limit + 1
	}
	cap := limit + 1
	add := func(a, b int64) int64 {
		if a >= cap || b >= cap || a > cap-b {
			return cap
		}
		return a + b
	}
	mul := func(a, b int64) int64 {
		if a <= 0 || b <= 0 {
			return 1
		}
		if a >= cap || b >= cap || a > cap/b {
			return cap
		}
		return a * b
	}
	cost := selectorCompoundCost(c.compounds[0], profile, limit)
	for i, combinator := range c.combinators {
		factor := int64(1)
		switch combinator {
		case ' ':
			factor = int64(depth + 1)
		case '+', '~':
			factor = mul(int64(nodes+1), siblingMatchWeight)
		}
		cost = add(selectorCompoundCost(c.compounds[i+1], profile, limit), mul(cost, factor))
	}
	return cost
}

func selectorExecutionCost(c selectorComplexity, profile selectorAttributeProfile, depth, nodes int, limit int64) int64 {
	cost := int64(1)
	for _, compound := range c.compounds {
		compoundCost := selectorCompoundCost(compound, profile, limit)
		if compoundCost > limit-cost {
			return limit + 1
		}
		cost += compoundCost
	}
	for _, combinator := range c.combinators {
		var extra int64
		switch combinator {
		case ' ':
			extra = int64(depth + 1)
		case '+', '~':
			extra = int64(nodes+1) * siblingMatchWeight
		}
		if extra > limit-cost {
			return limit + 1
		}
		cost += extra
	}
	return cost
}

func selectorMatchCost(plan *selectorPlan, context selectorMatchContext, limit int64) int64 {
	if !plan.execution.attributeSensitive() {
		return plan.cost
	}
	profile := context.current
	if len(plan.execution.combinators) > 0 {
		profile = context.path
		for _, combinator := range plan.execution.combinators {
			if combinator == '+' || combinator == '~' {
				profile = context.document
				break
			}
		}
	}
	bound := plannedSelectorCost(plan.execution, profile, context.depth, context.nodes, limit)
	if bound > limit {
		return bound
	}
	structural := plannedSelectorCost(plan.execution, selectorAttributeProfile{}, context.depth, context.nodes, limit)
	extra := bound - structural
	if extra < 0 || plan.cost > limit-extra {
		return limit + 1
	}
	return plan.cost + extra
}

func (s *sheet) buildSelectorIndex(depth, nodes int) {
	// Rules without any declaration understood by the extractor cannot affect
	// presentation. Removing them also prevents no-op selectors from consuming
	// matching work or match-cache memory.
	kept := s.rules[:0]
	for _, rule := range s.rules {
		if len(rule.decls) != 0 {
			kept = append(kept, rule)
		}
	}
	s.rules = kept
	index := selectorIndex{
		tags: map[string][]selectorRef{}, ids: map[string][]selectorRef{}, classes: map[string][]selectorRef{},
		ancestorTags: map[string][]selectorRef{}, ancestorIDs: map[string][]selectorRef{}, ancestorClasses: map[string][]selectorRef{},
	}
	for ruleIndex := range s.rules {
		for branchIndex := range s.rules[ruleIndex].plans {
			plan := &s.rules[ruleIndex].plans[branchIndex]
			plan.matches = nil
			if plan.uncertain {
				plan.cost = selectorExecutionCost(plan.execution, selectorAttributeProfile{}, 0, 1, s.limits.MatchWork)
			} else {
				plan.bound = plannedSelectorCost(plan.complexity, selectorAttributeProfile{}, depth, nodes, s.limits.MatchWork)
				plan.cost = selectorExecutionCost(plan.complexity, selectorAttributeProfile{}, depth, nodes, s.limits.MatchWork)
				if plan.bound > s.limits.MatchWork {
					plan.makeUncertain()
					plan.cost = selectorExecutionCost(plan.execution, selectorAttributeProfile{}, 0, 1, s.limits.MatchWork)
				}
			}
			ref := selectorRef{rule: ruleIndex, branch: branchIndex, sequence: plan.sequence}
			index.count = max(index.count, plan.sequence+1)
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
	s.matchCacheEntries = 0
}

func (s *sheet) candidates(n *html.Node) []selectorRef {
	refs, _ := s.collectCandidates(n, nil)
	return refs
}

// collectCandidates builds the union of relevant selector-index buckets. A
// selector plan belongs to exactly one bucket, so the first reference also
// serves as that bucket's stable identity. Marking before append prevents a
// repeated ancestor key from expanding the same bucket at every tree level.
func (s *sheet) collectCandidates(n *html.Node, budget *matchBudget) ([]selectorRef, bool) {
	if s.index.count == 0 {
		return nil, true
	}
	if len(s.candidateMarks) < s.index.count {
		s.candidateMarks = make([]uint32, s.index.count)
	}
	s.candidateGeneration++
	if s.candidateGeneration == 0 {
		clear(s.candidateMarks)
		s.candidateGeneration = 1
	}
	generation := s.candidateGeneration
	refs := s.candidateScratch[:0]
	appendBucket := func(bucket []selectorRef) bool {
		if len(bucket) == 0 || s.candidateMarks[bucket[0].sequence] == generation {
			return true
		}
		if budget != nil && !budget.spend(int64(len(bucket))) {
			return false
		}
		for _, ref := range bucket {
			if s.candidateMarks[ref.sequence] == generation {
				continue
			}
			s.candidateMarks[ref.sequence] = generation
			refs = append(refs, ref)
		}
		return true
	}
	appendAttributes := func(node *html.Node, idIndex, classIndex map[string][]selectorRef) bool {
		if len(idIndex) == 0 && len(classIndex) == 0 {
			return true
		}
		if budget != nil && len(node.Attr) != 0 && !budget.spend(int64(len(node.Attr))) {
			return false
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
		if id != "" && !appendBucket(idIndex[id]) {
			return false
		}
		if classes != "" {
			if budget != nil && !budget.spend(1+selectorByteWork(len(classes))) {
				return false
			}
			for start := 0; start < len(classes); {
				for start < len(classes) && isCSSSpace(classes[start]) {
					start++
				}
				end := start
				for end < len(classes) && !isCSSSpace(classes[end]) {
					end++
				}
				if end > start && !appendBucket(classIndex[classes[start:end]]) {
					return false
				}
				start = end
			}
		}
		return true
	}
	if !appendBucket(s.index.universal) || !appendBucket(s.index.tags[n.Data]) {
		s.candidateScratch = refs
		return nil, false
	}
	if len(s.index.ids) != 0 || len(s.index.classes) != 0 {
		if !appendAttributes(n, s.index.ids, s.index.classes) {
			s.candidateScratch = refs
			return nil, false
		}
	}
	for ancestor := n.Parent; ancestor != nil; ancestor = ancestor.Parent {
		if ancestor.Type != html.ElementNode {
			continue
		}
		if !appendBucket(s.index.ancestorTags[ancestor.Data]) {
			s.candidateScratch = refs
			return nil, false
		}
		if len(s.index.ancestorIDs) != 0 || len(s.index.ancestorClasses) != 0 {
			if !appendAttributes(ancestor, s.index.ancestorIDs, s.index.ancestorClasses) {
				s.candidateScratch = refs
				return nil, false
			}
		}
	}
	// No sort is required: candidate.beats compares declaration importance,
	// inline origin, specificity and source order explicitly. Keeping discovery
	// order avoids an O(n log n) phase without changing cascade results.
	s.candidateScratch = refs
	return refs, true
}

func isCSSSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f'
}
