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
	if states := s.runtime.mediaCache[key]; states != nil {
		return states, true
	}
	if s.runtime.mediaCache == nil {
		s.runtime.mediaCache = make(map[mediaCacheKey][]uint8)
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
	s.runtime.mediaCache[key] = states
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
	if !s.runtime.cacheMatches || s.runtime.matchCacheEntries >= maxMatchCacheEntries {
		return
	}
	if s.runtime.matchCaches == nil {
		s.runtime.matchCaches = make([]map[*html.Node]uint8, s.index.count)
	}
	cache := s.runtime.matchCaches[plan.sequence]
	if cache == nil {
		cache = make(map[*html.Node]uint8)
		s.runtime.matchCaches[plan.sequence] = cache
	}
	cache[n] = 1
	if matched {
		cache[n] = 2
	}
	s.runtime.matchCacheEntries++
}

type candidate struct {
	d               *declaration
	property        int
	set, inline     bool
	uncertainOrigin bool
	spec            cascadia.Specificity
}

type layoutCandidate = candidate

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

type evaluationContext struct {
	parent, root *Style
	vars         *variableScope
	budget       *expressionBudget
}

type mediaEvaluation struct {
	width    float64
	fallback bool
	ready    bool
	complete bool
	states   []uint8
}

type elementStyleResult struct {
	style           Style
	variables       *variableScope
	layoutUncertain bool
	displayDeclared bool
}

func (m *mediaEvaluation) evaluate(s *sheet, work *matchBudget) ([]uint8, bool) {
	if !m.ready {
		m.states, m.complete = s.mediaStates(m.width, m.fallback, work)
		m.ready = true
	}
	return m.states, m.complete
}

func resolvedDeclaration(d *declaration, property int, uncertainOrigin bool, context evaluationContext, resolveUnsupported bool) (Value, valueStatus) {
	if (d.unsupported || uncertainOrigin) && !resolveUnsupported {
		return Value{Text: d.value}, 2
	}
	if d.prepared != nil {
		return d.prepared.value, d.prepared.status
	}
	hadVar := d.hasVars
	v := substitute(d, context.vars, context.budget)
	if v.status == valueInvalid {
		return resolve(property, "unset", context.parent, context.root)
	}
	if v.status == valueUnsupported {
		return Value{Text: d.value}, 2
	}
	if len(v.text) > maxValueBytes {
		return Value{Text: d.value}, 2
	}
	value := strings.ToLower(strings.TrimSpace(v.text))
	if d.shorthand {
		ds := backgroundDeclarations(value, d.important, d.order)
		for _, x := range ds {
			if x.prop == property {
				value = x.value
				if x.unsupported {
					return Value{Text: value}, 2
				}
			}
		}
	}
	var out Value
	var status valueStatus
	if (property == fontSize || property == opacity) && isMath(value) {
		if !hadVar && d.tokensReady && d.valueStatus == valueResolved {
			out, status = evalMathTokens(property, value, d.valueTokens, context.parent, context.root, context.budget)
		} else {
			out, status = evalMath(property, value, context.parent, context.root, context.budget)
		}
	} else {
		out, status = resolve(property, value, context.parent, context.root)
	}
	if status == valueInvalid && hadVar {
		return resolve(property, "unset", context.parent, context.root)
	}
	return out, status
}
func (s *sheet) elementStyle(n *html.Node, parent, root *Style, parentVars *variableScope, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, matches *matchBudget, budget *expressionBudget) elementStyleResult {
	if s.cascadeIncomplete || s.workIncomplete {
		if s.workIncomplete {
			matches.exhausted = true
		}
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	// Once shared style-analysis work is exhausted, every remaining element is
	// unresolved. Avoid any further style copies or candidate construction.
	if matches.exhausted {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	if !matches.spend(elementTraversalWork) {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
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
	context := evaluationContext{parent: parent, root: root, vars: parentVars, budget: budget}
	// Parsed declaration slices are immutable and stable for the duration of
	// evaluation. Winners retain references plus per-use property/uncertainty
	// metadata instead of copying and modifying complete declarations.
	apply := func(ds []declaration, spec cascadia.Specificity, inl, uncertain bool) bool {
		// Reserve the complete declaration-list cost before changing the
		// cascade. A failed reservation must not leave a partially applied
		// style that appears trustworthy.
		applications := len(ds)
		for i := range ds {
			if ds[i].prop == allShorthandProperty {
				applications += declarationProperties - 1
			}
		}
		if applications > 0 && !matches.spend(int64(applications)*declarationApplyWeight) {
			return false
		}
		applyProperty := func(d *declaration, property int) {
			c := candidate{d: d, property: property, set: true, inline: inl, uncertainOrigin: uncertain, spec: spec}
			if property >= properties {
				index := property - properties
				if c.beats(layoutWins[index]) {
					layoutWins[index] = c
				}
				return
			}
			if c.beats(wins[property]) {
				wins[property] = c
			}
		}
		for declarationIndex := range ds {
			d := &ds[declarationIndex]
			if d.custom == "" && !d.unsupported {
				if d.validityReady && d.validity == 0 {
					continue
				}
				if !d.validityReady && !d.hasVars && !d.shorthand {
					_, status := resolvedDeclaration(d, d.prop, false, context, false)
					if status == valueInvalid {
						continue
					}
				}
			}
			if d.custom != "" {
				c := candidate{d: d, property: d.prop, set: true, inline: inl, uncertainOrigin: uncertain, spec: spec}
				if vars == nil {
					vars = map[string]candidate{}
				}
				if c.beats(vars[d.custom]) {
					vars[d.custom] = c
				}
			} else if d.prop == allShorthandProperty {
				for property := 0; property < declarationProperties; property++ {
					applyProperty(d, property)
				}
			} else {
				applyProperty(d, d.prop)
			}
		}
		return true
	}
	matchIncomplete := func() elementStyleResult {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	if !apply(legacy, cascadia.Specificity{}, false, false) {
		return matchIncomplete()
	}
	mediaStates, complete := media.evaluate(s, matches)
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
		if s.runtime.cacheMatches && plan.sequence < len(s.runtime.matchCaches) {
			state := s.runtime.matchCaches[plan.sequence][n]
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
	var defs map[string]variableDefinition
	if len(vars) > 0 {
		defs = map[string]variableDefinition{}
		for n, c := range vars {
			defs[n] = variableDefinition{declaration: c.d, uncertainOrigin: c.uncertainOrigin}
		}
	}
	scope := buildVariables(parentVars, defs, budget)
	context.vars = scope
	for i := 0; i < properties; i++ {
		c := wins[i]
		if c.set {
			v, status := resolvedDeclaration(c.d, c.property, c.uncertainOrigin, context, false)
			if status == valueUnsupported {
				v.Known = false
			}
			st[i] = v
		}
	}
	if st[background].Text == "currentcolor" {
		st[background] = st[color]
	}
	layoutUncertain := layoutVisibilityUncertain(&layoutWins, &st, context)
	return elementStyleResult{
		style: st, variables: scope, layoutUncertain: layoutUncertain,
		displayDeclared: wins[display].set,
	}
}
