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
	style                        Style
	variables                    *variableScope
	layoutUncertain              bool
	displayDeclared              bool
	alternateColourSchemeReasons concealmentReason
}

type cascadeWinners struct {
	properties                   [properties]candidate
	layout                       [layoutProperties]layoutCandidate
	variables                    map[string]candidate
	alternateColourSchemeReasons concealmentReason
	alternateColourSchemeVars    map[string]bool
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
		return Value{Text: d.value}, valueUnsupported
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
		return Value{Text: d.value}, valueUnsupported
	}
	if len(v.text) > maxValueBytes {
		return Value{Text: d.value}, valueUnsupported
	}
	value := strings.ToLower(strings.TrimSpace(v.text))
	if d.shorthand {
		if property == overflowX || property == overflowY {
			values, ok, uncertain := overflowShorthandValues(value)
			if !ok {
				return Value{}, valueInvalid
			}
			value = values[property-overflowX]
			if uncertain {
				return Value{Text: value}, valueUnsupported
			}
		} else {
			ds := backgroundDeclarations(value, d.important, d.order)
			for _, x := range ds {
				if x.prop == property {
					value = x.value
					if x.unsupported {
						return Value{Text: value}, valueUnsupported
					}
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

// collectCascade identifies the declarations that win the CSS cascade for one
// element. It reserves each declaration list's complete cost before mutating
// the result so an exhausted work budget can never expose partial winners.
func (s *sheet) collectCascade(n *html.Node, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, matches *matchBudget, context evaluationContext) (cascadeWinners, bool) {
	var winners cascadeWinners
	// Parsed declaration slices are immutable and stable for the duration of
	// evaluation. Winners retain references plus per-use property/uncertainty
	// metadata instead of copying and modifying complete declarations.
	apply := func(ds []declaration, spec cascadia.Specificity, inl, uncertain, colourSchemeDependent, retain bool) bool {
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
				if c.beats(winners.layout[index]) {
					winners.layout[index] = c
				}
				return
			}
			if c.beats(winners.properties[property]) {
				winners.properties[property] = c
			}
		}
		for declarationIndex := range ds {
			d := &ds[declarationIndex]
			if d.custom == "" && !d.unsupported {
				if d.validityReady && d.validity == valueInvalid {
					continue
				}
				if !d.validityReady && !d.hasVars && !d.shorthand {
					_, status := resolvedDeclaration(d, d.prop, false, context, false)
					if status == valueInvalid {
						continue
					}
				}
			}
			if colourSchemeDependent {
				if d.custom != "" {
					if winners.alternateColourSchemeVars == nil {
						winners.alternateColourSchemeVars = make(map[string]bool)
					}
					winners.alternateColourSchemeVars[d.custom] = true
				} else {
					winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(d)
				}
			}
			if !retain {
				continue
			}
			if d.custom != "" {
				c := candidate{d: d, property: d.prop, set: true, inline: inl, uncertainOrigin: uncertain, spec: spec}
				if winners.variables == nil {
					winners.variables = map[string]candidate{}
				}
				if c.beats(winners.variables[d.custom]) {
					winners.variables[d.custom] = c
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
	if !apply(legacy, cascadia.Specificity{}, false, false, false, true) {
		return cascadeWinners{}, false
	}
	mediaStates, complete := media.evaluate(s, matches)
	if !complete {
		return cascadeWinners{}, false
	}
	refs, complete := s.collectCandidates(n, matches)
	if !complete {
		return cascadeWinners{}, false
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
			if plan.uncertain {
				if !matches.spend(selectorMatchCost(plan, selectorContext, matches.limit)) {
					return cascadeWinners{}, false
				}
				matched = plan.scope.Match(n)
			} else if plan.ancestorChain != nil {
				var complete bool
				matched, complete = s.matchAncestorChain(plan, n, selectorContext, matches)
				if !complete {
					return cascadeWinners{}, false
				}
			} else {
				if !matches.spend(selectorMatchCost(plan, selectorContext, matches.limit)) {
					return cascadeWinners{}, false
				}
				matched = plan.matcher.Match(n)
			}
			s.cacheMatch(plan, n, matched)
		}
		if matched {
			if state == mediaAlternateColourScheme {
				if !apply(r.decls, plan.specificity, false, false, true, false) {
					return cascadeWinners{}, false
				}
			} else if plan.uncertain {
				if !apply(r.decls, plan.specificity, false, true, state == mediaYesColourScheme, true) {
					return cascadeWinners{}, false
				}
			} else {
				if !apply(r.decls, plan.specificity, false, state == mediaUnknown, state == mediaYesColourScheme, true) {
					return cascadeWinners{}, false
				}
			}
		}
	}
	if !apply(inline, cascadia.Specificity{}, true, false, false, true) {
		return cascadeWinners{}, false
	}
	return winners, true
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
	context := evaluationContext{parent: parent, root: root, vars: parentVars, budget: budget}
	winners, complete := s.collectCascade(n, legacy, inline, media, selectorContext, matches, context)
	if !complete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	var defs map[string]variableDefinition
	if len(winners.variables) > 0 {
		defs = map[string]variableDefinition{}
		for n, c := range winners.variables {
			defs[n] = variableDefinition{declaration: c.d, uncertainOrigin: c.uncertainOrigin}
		}
	}
	scope := buildVariables(parentVars, defs, winners.alternateColourSchemeVars, budget)
	context.vars = scope
	for i := 0; i < properties; i++ {
		c := winners.properties[i]
		if c.set {
			if declarationUsesColourSchemeVariable(c.d, scope) {
				winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(c.d)
			}
			v, status := resolvedDeclaration(c.d, c.property, c.uncertainOrigin, context, false)
			if status == valueUnsupported {
				v.Known = false
			}
			st[i] = v
		}
	}
	for i := range winners.layout {
		if c := winners.layout[i]; c.set && declarationUsesColourSchemeVariable(c.d, scope) {
			winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(c.d)
		}
	}
	if st[background].Text == "currentcolor" {
		st[background] = st[color]
	}
	layoutUncertain := layoutVisibilityUncertain(&winners.layout, &st, context)
	return elementStyleResult{
		style: st, variables: scope, layoutUncertain: layoutUncertain,
		displayDeclared:              winners.properties[display].set,
		alternateColourSchemeReasons: winners.alternateColourSchemeReasons,
	}
}

func alternateColourSchemeEffects(d *declaration) concealmentReason {
	if d.prop == allShorthandProperty {
		return reasonDisplayNone | reasonVisibilityHidden | reasonVisibilityCollapse |
			reasonOpacity | reasonFontSize | reasonColour | reasonEmptyClip | reasonContentVisibility
	}
	switch d.prop {
	case display:
		return reasonDisplayNone
	case visibility:
		return reasonVisibilityHidden | reasonVisibilityCollapse
	case contentVisibility:
		return reasonContentVisibility
	case opacity:
		return reasonOpacity
	case fontSize:
		return reasonFontSize
	case color, background, backgroundImage, filter, blend, backdropFilter,
		backgroundBlend, maskImage, backgroundClip, textShadow, textFill, textStroke:
		return reasonColour
	case clip, clipPath, overflowX, overflowY, width, height, maxWidth, maxHeight,
		left, top, right, bottom, textIndent, marginTop, marginRight, marginBottom,
		marginLeft, zoom, transform, position:
		return reasonEmptyClip
	default:
		return 0
	}
}

func declarationUsesColourSchemeVariable(d *declaration, scope *variableScope) bool {
	if d == nil || !d.hasVars {
		return false
	}
	for _, name := range d.variableDependencies {
		if scope.colourSchemeDependent(name) {
			return true
		}
	}
	return false
}
