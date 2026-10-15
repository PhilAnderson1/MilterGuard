package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// Applying a declaration entails validity checks, cascade comparison and
// candidate storage; weight it above a simple selector-index lookup.
const declarationApplyWeight int64 = 16

// Full resolution constructs cascade candidates and resolves presentation and
// layout. Elements with no candidate selectors or local declarations need only
// defaults and inheritance; charge that smaller path separately. Selector
// discovery/matching and declaration application retain their own charges.
const elementTraversalWork int64 = 128
const elementInheritanceWork int64 = 48

// Cache units are weighted retained records, not bytes: a match or ancestor
// result costs one unit, while an attribute result also charges each retained
// selector-bucket slice header. Go map buckets and allocator overhead vary by
// release and entry mix, so 100,000 units represent several to low tens of MiB,
// plus selector-count-bounded outer tables. Matching continues without caching
// after the shared per-document limit is full.
const maxMatchCacheUnits = 100_000

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
	hasConditions := false
	for i := range s.rules {
		cost += s.rules[i].mediaStateWork(fallback)
		hasConditions = hasConditions || s.rules[i].conditions != nil
	}
	if cost > 0 && work != nil && !work.spend(cost) {
		return nil, false
	}
	states := make([]uint8, len(s.rules))
	var frameStates map[*conditionFrame]conditionFrameState
	if hasConditions {
		frameStates = make(map[*conditionFrame]conditionFrameState)
	}
	for i := range s.rules {
		light, dark := evaluateConditionFrame(s.rules[i].conditions, width, fallback, frameStates)
		states[i] = uint8(combinedMediaState(light, dark))
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
	if !s.runtime.cacheMatches || s.runtime.matchCacheUnits >= maxMatchCacheUnits {
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
	s.runtime.matchCacheUnits++
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
	variableMemo *declarationScopeMemo
}

type declarationScopeMemo struct {
	declaration                 *declaration
	scope                       *variableScope
	substitution                variableValue
	substitutionReady           bool
	colourSchemeDependent       bool
	colourSchemeDependencyReady bool
}

func (m *declarationScopeMemo) selectKey(d *declaration, scope *variableScope) {
	if m.declaration == d && m.scope == scope {
		return
	}
	m.declaration = d
	m.scope = scope
	m.substitution = variableValue{}
	m.substitutionReady = false
	m.colourSchemeDependent = false
	m.colourSchemeDependencyReady = false
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
	elementGeometryConcealed     bool
	clipsDescendantsX            bool
	clipsDescendantsY            bool
	offsetWithinClippedAncestorX bool
	offsetWithinClippedAncestorY bool
	displayDeclared              bool
	alternateColourSchemeReasons concealmentReason
	animationActive              bool
}

type cascadeWinners struct {
	properties                   [properties]candidate
	layout                       [layoutProperties]layoutCandidate
	variables                    map[string]candidate
	alternateColourSchemeReasons concealmentReason
	alternateColourSchemeVars    map[string]bool
	animation                    candidate
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
	v := context.substitute(d)
	if v.status == valueInvalid {
		return resolve(property, "unset", context.parent, context.root)
	}
	if v.status == valueUnsupported {
		return Value{Text: d.value}, valueUnsupported
	}
	if len(v.text) > maxValueBytes {
		return Value{Text: d.value}, valueUnsupported
	}
	value := normalizeCSSKeyword(v.text)
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

func (c evaluationContext) substitute(d *declaration) variableValue {
	if !d.hasVars || c.variableMemo == nil {
		return substitute(d, c.vars, c.budget)
	}
	memo := c.variableMemo
	memo.selectKey(d, c.vars)
	if memo.substitutionReady {
		return memo.substitution
	}
	memo.substitution = substitute(d, c.vars, c.budget)
	memo.substitutionReady = true
	return memo.substitution
}

// collectCascade identifies the declarations that win the CSS cascade for one
// element. It reserves each declaration list's complete cost before mutating
// the result so an exhausted work budget can never expose partial winners.
func (s *sheet) collectCascade(n *html.Node, refs []selectorRef, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, matches *matchBudget, context evaluationContext) (cascadeWinners, bool) {
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
			if property == animationProperty {
				if c.beats(winners.animation) {
					winners.animation = c
				}
				return
			}
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
					if s.runtime.variableScratch == nil {
						s.runtime.variableScratch = make(map[string]candidate)
					} else {
						clear(s.runtime.variableScratch)
					}
					winners.variables = s.runtime.variableScratch
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
			} else if plan.uncertain || r.uncertainOrigin {
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
	// Expression exhaustion makes all subsequent computed values unknowable.
	// Stop before cascade collection and variable-scope allocation; unresolved
	// styles conservatively produce visibility-uncertain output.
	if budget.exhausted {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	if !matches.spend(elementInheritanceWork) {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	st := initial()
	for i := range st {
		if inherits(i) {
			st[i] = parent[i]
		}
	}
	refs, complete := s.collectCandidates(n, matches)
	if !complete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	if len(refs) == 0 && len(legacy) == 0 && len(inline) == 0 {
		// No declarations can affect this element. Preserve inherited computed
		// values (including uncertainty) and the variable scope without building
		// cascade winners or resolving layout/animations. Ancestor presentation
		// effects are carried separately by viewingCaseFrame.
		return elementStyleResult{style: st, variables: parentVars}
	}
	if !matches.spend(elementTraversalWork - elementInheritanceWork) {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	variableMemo := declarationScopeMemo{}
	context := evaluationContext{parent: parent, root: root, vars: parentVars, budget: budget, variableMemo: &variableMemo}
	winners, complete := s.collectCascade(n, refs, legacy, inline, media, selectorContext, matches, context)
	if !complete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	scope := buildVariables(parentVars, winners.variables, winners.alternateColourSchemeVars, budget)
	// Variable scopes never retain the cascade map, so it can be reused by the
	// next element even when expression evaluation was abandoned.
	if winners.variables != nil {
		s.runtime.variableScratch = winners.variables
	}
	if budget.exhausted {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	context.vars = scope
	for i := 0; i < properties; i++ {
		c := winners.properties[i]
		if c.set {
			if declarationUsesColourSchemeVariable(c.d, scope, budget, context.variableMemo) {
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
		if c := winners.layout[i]; c.set && declarationUsesColourSchemeVariable(c.d, scope, budget, context.variableMemo) {
			winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(c.d)
		}
	}
	if st[background].Text == "currentcolor" {
		st[background] = st[color]
	}
	layout := layoutVisibility(&winners.layout, &st, context, n)
	animationActive := s.potentiallyActiveAnimation(winners.animation, context, matches)
	return elementStyleResult{
		style: st, variables: scope, layoutUncertain: layout.uncertain, elementGeometryConcealed: layout.elementConcealed,
		clipsDescendantsX: layout.clipsX, clipsDescendantsY: layout.clipsY,
		offsetWithinClippedAncestorX: layout.offsetX, offsetWithinClippedAncestorY: layout.offsetY,
		displayDeclared:              winners.properties[display].set,
		alternateColourSchemeReasons: winners.alternateColourSchemeReasons,
		animationActive:              animationActive,
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
		left, top, right, bottom, textIndent, letterSpacing, wordSpacing, lineHeight,
		marginTop, marginRight, marginBottom,
		marginLeft, zoom, transform, position:
		return reasonEmptyClip
	default:
		return 0
	}
}

func declarationUsesColourSchemeVariable(d *declaration, scope *variableScope, budget *expressionBudget, memo *declarationScopeMemo) bool {
	if d == nil || !d.hasVars {
		return false
	}
	if memo != nil {
		memo.selectKey(d, scope)
		if memo.colourSchemeDependencyReady {
			return memo.colourSchemeDependent
		}
	}
	dependent := false
	for _, name := range d.variableDependencies {
		if scope.colourSchemeDependent(name, budget) {
			dependent = true
			break
		}
	}
	if memo != nil {
		memo.colourSchemeDependent = dependent
		memo.colourSchemeDependencyReady = true
	}
	return dependent
}
