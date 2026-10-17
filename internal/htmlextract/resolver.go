package htmlextract

import (
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// These conservative estimates cover Go map buckets and per-entry overhead
// which unsafe.Sizeof cannot observe through a map value.
const (
	mediaCacheMapBytes      int64 = 128
	mediaStateSliceOverhead int64 = 48
	matchCacheMapBytes      int64 = 128
	matchCacheEntryBytes    int64 = 32
)

type mediaCacheKey struct {
	width    float64
	fallback bool
}

func (s *sheet) matchSelector(m cascadia.Matcher, n *html.Node) (bool, bool) {
	if s.selectorControl == nil {
		s.selectorControl = cascadia.NewMatchControl(s.shouldStop)
	}
	matched, stopped := s.selectorControl.Match(m, n)
	if stopped {
		s.stopped = true
		return false, false
	}
	return matched, true
}

func (s *sheet) mediaStates(width float64, fallback bool, work *cpuGuard) ([]uint8, bool) {
	if !s.prepareMediaGroups() {
		return nil, false
	}
	key := mediaCacheKey{width: width, fallback: fallback}
	if states := s.runtime.mediaCache[key]; states != nil {
		return states, true
	}
	if s.runtime.mediaCache == nil {
		if !s.memory.Reserve(mediaCacheMapBytes) {
			return nil, false
		}
		s.runtime.mediaCache = make(map[mediaCacheKey][]uint8)
	}
	if work != nil && !work.check() {
		return nil, false
	}
	if !s.memory.Reserve(int64(len(s.runtime.mediaGroups)) + mediaStateSliceOverhead) {
		return nil, false
	}
	states := make([]uint8, len(s.runtime.mediaGroups))
	var frameStates map[*conditionFrame]conditionFrameState
	if len(s.runtime.mediaGroups) > 1 {
		if !s.memory.Reserve(mediaFrameStateMapBytes) {
			return nil, false
		}
		frameStates = make(map[*conditionFrame]conditionFrameState)
		// Reserve each distinct frame before evaluation can populate the map.
		for _, group := range s.runtime.mediaGroups {
			for f := group; f != nil; f = f.parent {
				if _, seen := frameStates[f]; seen {
					break
				}
				if !work.check() || !s.memory.Reserve(mediaFrameSetEntryBytes) {
					return nil, false
				}
				frameStates[f] = conditionFrameState{}
			}
		}
		clear(frameStates)
	}
	for i, group := range s.runtime.mediaGroups {
		if !work.check() {
			return nil, false
		}
		light, dark := evaluateConditionFrame(group, width, fallback, frameStates, work)
		states[i] = uint8(combinedMediaState(light, dark))
	}
	if work.stopNow(false) {
		return nil, false
	}
	s.runtime.mediaCache[key] = states
	return states, true
}

func unresolvedStyle() Style {
	return Style{}
}

func (s *sheet) cacheMatch(plan *selectorPlan, n *html.Node, matched bool) {
	if !s.runtime.cacheMatches {
		return
	}
	if s.runtime.matchCaches != nil {
		cache := s.runtime.matchCaches[plan.sequence]
		if state, exists := cache[n]; exists {
			if matched {
				cache[n] = 2
			} else if state == 0 {
				cache[n] = 1
			}
			return
		}
	}
	// A full cache remains useful for its existing entries. New combinations
	// are evaluated normally instead of growing attacker-controlled maps.
	if s.runtime.matchCacheEntries >= maxMatchCacheEntries {
		return
	}
	if s.runtime.matchCaches == nil {
		if !s.memory.Reserve(int64(s.index.count) * int64(unsafe.Sizeof(map[*html.Node]uint8{}))) {
			return
		}
		s.runtime.matchCaches = make([]map[*html.Node]uint8, s.index.count)
	}
	cache := s.runtime.matchCaches[plan.sequence]
	if cache == nil {
		if !s.memory.Reserve(matchCacheMapBytes) {
			return
		}
		cache = make(map[*html.Node]uint8)
		s.runtime.matchCaches[plan.sequence] = cache
	}
	if !s.memory.Reserve(matchCacheEntryBytes) {
		return
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
	budget       *cpuGuard
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

func (m *mediaEvaluation) evaluate(s *sheet, work *cpuGuard) ([]uint8, bool) {
	if !m.ready {
		m.states, m.complete = s.mediaStates(m.width, m.fallback, work)
		m.ready = true
	}
	return m.states, m.complete
}

type declarationResolution struct {
	uncertainOrigin  bool
	allowUnsupported bool
}

func resolvedDeclaration(d *declaration, property int, context evaluationContext, options declarationResolution) (Value, valueStatus) {
	if (d.unsupported || options.uncertainOrigin) && !options.allowUnsupported {
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
			ds := backgroundDeclarations(value, d.important, d.order, context.budget)
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
		out, status = resolveWithBudget(property, value, context.parent, context.root, context.budget)
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

// collectCascade identifies winning declarations privately. Interrupted scans
// discard partial winners rather than exposing a partially trusted cascade.
func (s *sheet) collectCascade(n *html.Node, refs []selectorRef, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, work *cpuGuard, context evaluationContext) (cascadeWinners, bool) {
	var winners cascadeWinners
	type cascadeSource struct {
		specificity           cascadia.Specificity
		inline                bool
		uncertain             bool
		colourSchemeDependent bool
		retain                bool
	}
	// Parsed declaration slices are immutable and stable for the duration of
	// evaluation. Winners retain references plus per-use property/uncertainty
	// metadata instead of copying and modifying complete declarations.
	apply := func(ds []declaration, source cascadeSource) bool {
		// Check before and during the list; partial winners remain private.
		if len(ds) > 0 && !work.check() {
			return false
		}
		applyProperty := func(d *declaration, property int) {
			c := candidate{d: d, property: property, set: true, inline: source.inline, uncertainOrigin: source.uncertain, spec: source.specificity}
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
			if !work.check() {
				return false
			}
			d := &ds[declarationIndex]
			if d.custom == "" && !d.unsupported {
				if d.validityReady && d.validity == valueInvalid {
					continue
				}
				if !d.validityReady && !d.hasVars && !d.shorthand {
					_, status := resolvedDeclaration(d, d.prop, context, declarationResolution{})
					if status == valueInvalid {
						continue
					}
				}
			}
			if source.colourSchemeDependent {
				if d.custom != "" {
					if winners.alternateColourSchemeVars == nil {
						if !s.memory.Reserve(128) {
							return false
						}
						winners.alternateColourSchemeVars = make(map[string]bool)
					}
					if !winners.alternateColourSchemeVars[d.custom] && !s.memory.Reserve(variableAlternateEntryBytes) {
						return false
					}
					winners.alternateColourSchemeVars[d.custom] = true
				} else {
					winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(d)
				}
			}
			if !source.retain {
				continue
			}
			if d.custom != "" {
				c := candidate{d: d, property: d.prop, set: true, inline: source.inline, uncertainOrigin: source.uncertain, spec: source.specificity}
				if winners.variables == nil {
					if s.runtime.variableScratch == nil {
						if !s.memory.Reserve(128) {
							return false
						}
						s.runtime.variableScratch = make(map[string]candidate)
					} else {
						clear(s.runtime.variableScratch)
					}
					winners.variables = s.runtime.variableScratch
				}
				if c.beats(winners.variables[d.custom]) {
					if _, exists := winners.variables[d.custom]; !exists && len(winners.variables) >= s.runtime.variableScratchCapacity {
						if !s.memory.Reserve(96) {
							return false
						}
						s.runtime.variableScratchCapacity++
					}
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
	if !apply(legacy, cascadeSource{retain: true}) {
		return cascadeWinners{}, false
	}
	mediaStates, complete := media.evaluate(s, work)
	if !complete {
		return cascadeWinners{}, false
	}
	for _, ref := range refs {
		if !work.check() {
			return cascadeWinners{}, false
		}
		r := &s.rules[ref.rule]
		plan := &r.plans[ref.branch]
		state := int(mediaStates[r.mediaGroup])
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
				if !work.check() {
					return cascadeWinners{}, false
				}
				var complete bool
				matched, complete = s.matchSelector(plan.scope, n)
				if !complete {
					return cascadeWinners{}, false
				}
			} else if plan.ancestorChain != nil {
				var complete bool
				matched, complete = s.matchAncestorChain(plan, n, selectorContext, work)
				if !complete {
					return cascadeWinners{}, false
				}
			} else {
				if !work.check() {
					return cascadeWinners{}, false
				}
				var complete bool
				matched, complete = s.matchSelector(plan.matcher, n)
				if !complete {
					return cascadeWinners{}, false
				}
			}
			s.cacheMatch(plan, n, matched)
		}
		if matched {
			if state == mediaAlternateColourScheme {
				if !apply(r.decls, cascadeSource{specificity: plan.specificity, colourSchemeDependent: true}) {
					return cascadeWinners{}, false
				}
			} else if plan.uncertain || r.uncertainOrigin {
				if !apply(r.decls, cascadeSource{specificity: plan.specificity, uncertain: true, colourSchemeDependent: state == mediaYesColourScheme, retain: true}) {
					return cascadeWinners{}, false
				}
			} else {
				if !apply(r.decls, cascadeSource{specificity: plan.specificity, uncertain: state == mediaUnknown, colourSchemeDependent: state == mediaYesColourScheme, retain: true}) {
					return cascadeWinners{}, false
				}
			}
		}
	}
	if !apply(inline, cascadeSource{inline: true, retain: true}) {
		return cascadeWinners{}, false
	}
	return winners, true
}

func (s *sheet) elementStyle(n *html.Node, parent, root *Style, parentVars *variableScope, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, work *cpuGuard) elementStyleResult {
	if s.cascadeIncomplete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	if !work.check() {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	st := initial()
	for i := range st {
		if inherits(i) {
			st[i] = parent[i]
		}
	}
	refs, complete := s.collectCandidates(n, work)
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
	if !work.check() {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	variableMemo := declarationScopeMemo{}
	context := evaluationContext{parent: parent, root: root, vars: parentVars, budget: work, variableMemo: &variableMemo}
	winners, complete := s.collectCascade(n, refs, legacy, inline, media, selectorContext, work, context)
	if !complete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	scope := buildVariables(parentVars, winners.variables, winners.alternateColourSchemeVars, work)
	// Variable scopes never retain the cascade map, so it can be reused by the
	// next element even when expression evaluation was abandoned.
	if winners.variables != nil {
		s.runtime.variableScratch = winners.variables
	}
	if work.stopped {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	context.vars = scope
	for i := 0; i < properties; i++ {
		c := winners.properties[i]
		if c.set {
			if declarationUsesColourSchemeVariable(c.d, scope, work, context.variableMemo) {
				winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(c.d)
			}
			v, status := resolvedDeclaration(c.d, c.property, context, declarationResolution{uncertainOrigin: c.uncertainOrigin})
			if status == valueUnsupported {
				v.Known = false
			}
			st[i] = v
		}
	}
	for i := range winners.layout {
		if c := winners.layout[i]; c.set && declarationUsesColourSchemeVariable(c.d, scope, work, context.variableMemo) {
			winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(c.d)
		}
	}
	if st[background].Text == "currentcolor" {
		st[background] = st[color]
	}
	layout := layoutVisibility(&winners.layout, &st, context, n)
	animationActive := s.potentiallyActiveAnimation(winners.animation, context, work)
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

func declarationUsesColourSchemeVariable(d *declaration, scope *variableScope, budget *cpuGuard, memo *declarationScopeMemo) bool {
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
