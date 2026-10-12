package htmlextract

import (
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// Applying a declaration entails validity checks, cascade comparison and
// candidate storage; weight it above a simple selector-index lookup.
const declarationApplyWeight int64 = 16

// Every element/viewing-case traversal copies and resolves a fixed-size Style,
// candidate arrays and frame state even when no stylesheet selector is
// relevant. Benchmarks put that fixed work at roughly 100 simple selector
// operations; use a power-of-two conservative weight.
const elementTraversalWork int64 = 128

// Go maps have substantial per-entry overhead. Bound cached selector results
// independently of the CPU-work budget so one message has a predictable
// memory ceiling. Matching continues normally after the cache is full.
const maxMatchCacheEntries = 100_000

type mediaCacheKey struct {
	width    float64
	fallback bool
}

func (s *sheet) mediaStates(width float64, fallback bool, work *matchBudget) ([]uint8, bool) {
	key := mediaCacheKey{width: width, fallback: fallback}
	if states := s.mediaCache[key]; states != nil {
		return states, true
	}
	if s.mediaCache == nil {
		s.mediaCache = make(map[mediaCacheKey][]uint8)
	}
	var cost int64
	for i := range s.rules {
		cost += s.rules[i].mediaStateWork(fallback)
	}
	if cost > 0 && work != nil && !work.spend(cost) {
		return nil, false
	}
	states := make([]uint8, len(s.rules))
	for i := range s.rules {
		states[i] = uint8(s.rules[i].mediaState(width, fallback))
	}
	s.mediaCache[key] = states
	return states, true
}

type matchBudget struct {
	limit     int64
	used      int64
	exhausted bool
}

func (b *matchBudget) spend(cost int64) bool {
	if cost < 1 {
		cost = 1
	}
	if b.exhausted || b.limit < 0 || b.used > b.limit || cost > b.limit-b.used {
		b.exhausted = true
		return false
	}
	b.used += cost
	return true
}

func unresolvedStyle() Style {
	return Style{}
}

func (s *sheet) cacheMatch(plan *selectorPlan, n *html.Node, matched bool) {
	if !s.cacheMatches || s.matchCacheEntries >= maxMatchCacheEntries {
		return
	}
	if plan.matches == nil {
		plan.matches = make(map[*html.Node]uint8)
	}
	plan.matches[n] = 1
	if matched {
		plan.matches[n] = 2
	}
	s.matchCacheEntries++
}

type candidate struct {
	d           declaration
	set, inline bool
	spec        cascadia.Specificity
}

type layoutCandidate struct {
	d           *declaration
	set, inline bool
	spec        cascadia.Specificity
}

func (c candidate) beats(old candidate) bool {
	if !old.set {
		return true
	}
	if c.d.important != old.d.important {
		return c.d.important
	}
	if c.inline != old.inline {
		return c.inline
	}
	if c.spec != old.spec {
		return old.spec.Less(c.spec)
	}
	return c.d.order >= old.d.order
}

func (c layoutCandidate) beats(old layoutCandidate) bool {
	if !old.set {
		return true
	}
	if c.d.important != old.d.important {
		return c.d.important
	}
	if c.inline != old.inline {
		return c.inline
	}
	if c.spec != old.spec {
		return old.spec.Less(c.spec)
	}
	return c.d.order >= old.d.order
}
func resolvedDeclaration(d declaration, parent, root Style, vars *variableScope, budget *expressionBudget) (Value, int) {
	if d.unsupported {
		return Value{Text: d.value}, 2
	}
	if d.prepared != nil {
		return d.prepared.value, d.prepared.status
	}
	hadVar := d.hasVars
	v := substitute(d, vars, budget)
	if v.status == 0 {
		return resolve(d.prop, "unset", parent, root)
	}
	if v.status == 2 {
		return Value{Text: d.value}, 2
	}
	if len(v.text) > maxValueBytes {
		return Value{Text: d.value}, 2
	}
	value := strings.ToLower(strings.TrimSpace(v.text))
	if d.shorthand {
		ds := backgroundDeclarations(value, d.important, d.order)
		for _, x := range ds {
			if x.prop == d.prop {
				value = x.value
				if x.unsupported {
					return Value{Text: value}, 2
				}
			}
		}
	}
	var out Value
	var status int
	if (d.prop == fontSize || d.prop == opacity) && isMath(value) {
		if !hadVar && d.tokensReady && d.valueStatus == 1 {
			out, status = evalMathTokens(d.prop, value, d.valueTokens, parent, root, budget)
		} else {
			out, status = evalMath(d.prop, value, parent, root, budget)
		}
	} else {
		out, status = resolve(d.prop, value, parent, root)
	}
	if status == 0 && hadVar {
		return resolve(d.prop, "unset", parent, root)
	}
	return out, status
}
func (s *sheet) elementStyle(n *html.Node, parent, root Style, parentVars *variableScope, inline []declaration, width float64, fallback bool, selectorContext selectorMatchContext, matches *matchBudget, budget *expressionBudget) (Style, *variableScope, bool, bool, error) {
	if s.cascadeIncomplete || s.workIncomplete {
		if s.workIncomplete {
			matches.exhausted = true
		}
		return unresolvedStyle(), parentVars, false, false, nil
	}
	// Once shared style-analysis work is exhausted, every remaining element is
	// unresolved. Avoid any further style copies or candidate construction.
	if matches.exhausted {
		return unresolvedStyle(), parentVars, false, false, nil
	}
	if !matches.spend(elementTraversalWork) {
		return unresolvedStyle(), parentVars, false, false, nil
	}
	st := initial()
	for i := range st {
		if inherits(i) {
			st[i] = parent[i]
		}
	}
	var wins [properties]candidate
	var layoutWins [layoutProperties]layoutCandidate
	var vars map[string]candidate
	apply := func(ds []declaration, spec cascadia.Specificity, inl, uncertain bool) bool {
		// Reserve the complete declaration-list cost before changing the
		// cascade. A failed reservation must not leave a partially applied
		// style that appears trustworthy.
		if len(ds) > 0 && !matches.spend(int64(len(ds))*declarationApplyWeight) {
			return false
		}
		for declarationIndex := range ds {
			d := ds[declarationIndex]
			if d.custom == "" && !d.unsupported {
				if d.validityReady && d.validity == 0 {
					continue
				}
				if !d.validityReady && !d.hasVars && !d.shorthand {
					_, status := resolvedDeclaration(d, parent, root, parentVars, budget)
					if status == 0 {
						continue
					}
				}
			}
			if d.custom != "" {
				d.unsupported = d.unsupported || uncertain
				c := candidate{d: d, set: true, inline: inl, spec: spec}
				if vars == nil {
					vars = map[string]candidate{}
				}
				if c.beats(vars[d.custom]) {
					vars[d.custom] = c
				}
			} else if d.prop >= properties {
				c := layoutCandidate{d: &ds[declarationIndex], set: true, inline: inl, spec: spec}
				index := d.prop - properties
				if c.beats(layoutWins[index]) {
					layoutWins[index] = c
				}
			} else {
				d.unsupported = d.unsupported || uncertain
				c := candidate{d: d, set: true, inline: inl, spec: spec}
				if c.beats(wins[d.prop]) {
					wins[d.prop] = c
				}
			}
		}
		return true
	}
	matchIncomplete := func() (Style, *variableScope, bool, bool, error) {
		return unresolvedStyle(), parentVars, false, false, nil
	}
	if !apply(prepareDeclarations(legacyDeclarations(n)), cascadia.Specificity{}, false, false) {
		return matchIncomplete()
	}
	mediaStates, complete := s.mediaStates(width, fallback, matches)
	if !complete {
		return matchIncomplete()
	}
	refs, complete := s.collectCandidates(n, matches)
	if !complete {
		return matchIncomplete()
	}
	for _, ref := range refs {
		r := &s.rules[ref.rule]
		plan := &r.plans[ref.branch]
		state := int(mediaStates[ref.rule])
		if state == mediaNo {
			continue
		}
		matched, cached := false, false
		if s.cacheMatches {
			state := plan.matches[n]
			matched, cached = state == 2, state != 0
		}
		if !cached {
			if !matches.spend(selectorMatchCost(plan, selectorContext, matches.limit)) {
				return matchIncomplete()
			}
			if plan.uncertain {
				matched = plan.scope.Match(n)
			} else {
				matched = plan.matcher.Match(n)
			}
			s.cacheMatch(plan, n, matched)
		}
		if matched {
			if plan.uncertain {
				if !apply(r.decls, plan.specificity, false, true) {
					return matchIncomplete()
				}
			} else {
				if !apply(r.decls, plan.specificity, false, state == mediaUnknown) {
					return matchIncomplete()
				}
			}
		}
	}
	if !apply(inline, cascadia.Specificity{}, true, false) {
		return matchIncomplete()
	}
	var defs map[string]declaration
	if len(vars) > 0 {
		defs = map[string]declaration{}
		for n, c := range vars {
			defs[n] = c.d
		}
	}
	scope := buildVariables(parentVars, defs, budget)
	for i := 0; i < properties; i++ {
		c := wins[i]
		if c.set {
			v, status := resolvedDeclaration(c.d, parent, root, scope, budget)
			if status == 2 {
				v.Known = false
			}
			st[i] = v
		}
	}
	if st[background].Text == "currentcolor" {
		st[background] = st[color]
	}
	layoutUncertain := layoutVisibilityUncertain(&layoutWins, st, parent, root, scope, budget)
	return st, scope, layoutUncertain, wins[display].set, nil
}
