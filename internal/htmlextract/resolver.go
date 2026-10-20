package htmlextract

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type mediaCacheKey struct {
	width    float64
	fallback bool
}

func (s *sheet) matchSelector(m cascadia.Matcher, n *html.Node) bool {
	if s.selectorControl == nil {
		s.selectorControl = cascadia.NewMatchControlWithMemory(s.shouldStop, s.memory)
	}
	return s.selectorControl.Match(m, n)
}

func (s *sheet) mediaStates(width float64, fallback bool, work *cpuGuard) []uint8 {
	s.prepareMediaGroups()

	key := mediaCacheKey{width: width, fallback: fallback}

	if states := s.runtime.mediaCache.View()[key]; states != nil {
		return states
	}

	if work != nil {
		work.check()
	}

	states := makeBudgetedBytes(len(s.runtime.mediaGroups), s.memory)

	var admittedFrames resourceguard.Table[*conditionFrame, conditionFrameState]
	if len(s.runtime.mediaGroups) > 1 {
		for _, group := range s.runtime.mediaGroups {
			for f := group; f != nil; f = f.parent {

				if _, seen := admittedFrames.Get(f); seen {
					break
				}

				work.check()

				admittedFrames.Set(s.memory, f, conditionFrameState{})
			}
		}
	}
	// Evaluation writes only keys enumerated and admitted above.
	frameStates := admittedFrames.View()
	clear(frameStates)
	for i, group := range s.runtime.mediaGroups {
		work.check()

		light, dark := evaluateConditionFrame(group, width, fallback, frameStates, work)
		states[i] = uint8(combinedMediaState(light, dark))
	}

	s.runtime.mediaCache.Set(s.memory, key, states)

	return states
}

func unresolvedStyle() Style {
	return Style{}
}

func (s *sheet) cacheMatch(plan *selectorPlan, n *html.Node, matched bool) {
	if !s.runtime.cacheMatches {
		return
	}
	exists := false
	if s.runtime.matchCaches != nil {
		_, exists = s.runtime.matchCaches[plan.sequence].Get(n)
	}
	if !exists && s.runtime.matchCacheEntries >= maxMatchCacheEntries {
		return
	}
	state := uint8(1)
	if matched {
		state = 2
	}
	if resourceguard.TryCacheEntry(s.memory, &s.runtime.matchCaches, s.index.count, plan.sequence, n, state) && !exists {
		s.runtime.matchCacheEntries++
	}
}

type candidate struct {
	d                     *declaration
	property              int
	set, inline           bool
	uncertainOrigin       bool
	colourSchemeDependent bool
	spec                  cascadia.Specificity
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
	parent, root      *Style
	currentFontNumber float64
	currentFontKnown  bool
	vars              *variableScope
	budget            *cpuGuard
	variableMemo      *declarationScopeMemo
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
	stableDisplayNone            bool
	fontScaleUncertain           bool
	textLayout, textLayoutSet    [3]bool
}

type cascadeWinners struct {
	properties                   [properties]candidate
	alternateProperties          [properties]candidate
	layout                       [layoutProperties]layoutCandidate
	ordinaryMargins              [8]candidate
	nonzeroConditionalMargins    uint8
	variables                    map[string]candidate
	alternateColourSchemeReasons concealmentReason
	alternateColourSchemeVars    resourceguard.Table[string, bool]
	alternateVariables           resourceguard.Table[string, candidate]
	animation                    candidate
}

func (m *mediaEvaluation) evaluate(s *sheet, work *cpuGuard) []uint8 {
	if !m.ready {
		m.states = s.mediaStates(m.width, m.fallback, work)
		m.ready = true
	}
	return m.states
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
		v := d.prepared.value
		if property == lineHeight && d.prepared.status == valueResolved {
			v = computedLineHeight(v, context.currentFontNumber, context.currentFontKnown, context.budget)
		}
		return v, d.prepared.status
	}
	hadVar := d.hasVars
	v := context.substitute(d)
	if v.status == valueInvalid {
		if d.edgeCount != 0 {
			return resolve(property, "initial", context.parent, context.root)
		}
		return resolve(property, "unset", context.parent, context.root)
	}
	if v.status == valueUnsupported {
		return Value{Text: d.value}, valueUnsupported
	}
	value := normalizeCSSKeywordWithBudget(v.text, context.budget)

	if d.shorthand {
		if d.edgeCount != 0 {
			values, ok, uncertain := marginShorthandValuesWithBudget(value, context.budget)
			if d.edgeCount == 2 && !uncertain {
				var scratch [4]string
				ok = ok && len(splitCSSWhitespace(value, scratch[:])) <= 2
			}
			if !ok {
				return resolve(property, "initial", context.parent, context.root)
			}
			if uncertain {
				return Value{Text: value}, valueUnsupported
			}
			value = values[d.edgeIndex]
		} else if property == overflowX || property == overflowY {
			values, ok, uncertain := overflowShorthandValues(value)
			if !ok {
				return Value{}, valueInvalid
			}
			value = values[property-overflowX]
			if uncertain {
				return Value{Text: value}, valueUnsupported
			}
		} else {
			{
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
	}
	var out Value
	var status valueStatus
	if (property == fontSize || property == opacity) && isMath(value) {
		if !hadVar && d.tokensReady && d.valueStatus == valueResolved {
			out, status = evalPreparedMathTokens(property, value, d.valueTokens, d.mathLiterals, context.parent, context.root, context.budget)
		} else {
			out, status = evalMath(property, value, context.parent, context.root, context.budget)
		}
	} else {
		out, status = resolveWithBudget(property, value, context.parent, context.root, context.budget)
	}
	if status == valueInvalid && hadVar {
		return resolve(property, "unset", context.parent, context.root)
	}
	if property == lineHeight && status == valueResolved && value != "inherit" && value != "unset" {
		out = computedLineHeight(out, context.currentFontNumber, context.currentFontKnown, context.budget)
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
	var hasColourSchemeDeclarations bool
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
	apply := func(ds []declaration, source cascadeSource) {
		// Check before and during the list; partial winners remain private.
		if len(ds) > 0 {
			work.check()
		}

		applyProperty := func(d *declaration, property int) {
			c := candidate{d: d, property: property, set: true, inline: source.inline, uncertainOrigin: source.uncertain, spec: source.specificity, colourSchemeDependent: source.colourSchemeDependent}
			if source.colourSchemeDependent && !source.retain && property < properties {
				if c.beats(winners.alternateProperties[property]) {
					winners.alternateProperties[property] = c
				}
				return
			}
			if property == animationProperty {
				if c.beats(winners.animation) {
					winners.animation = c
				}
				return
			}
			if property >= properties {
				index := property - properties

				if m := marginIndex(property); m >= 0 {
					if !c.uncertainOrigin {
						if c.beats(winners.ordinaryMargins[m]) {
							winners.ordinaryMargins[m] = c
						}
					} else if d.prepared == nil || d.prepared.status != valueResolved || !d.prepared.value.Known || d.prepared.value.Number != 0 || d.prepared.value.Text == "auto" {
						// Only literal, context-independent zero conditional margins
						// are eligible. Preserve uncertainty for every other branch.
						winners.nonzeroConditionalMargins |= 1 << m
					}
				}

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
			work.check()

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
				hasColourSchemeDeclarations = true
				if d.custom != "" {
					c := candidate{d: d, property: d.prop, set: true, inline: source.inline, uncertainOrigin: source.uncertain, spec: source.specificity, colourSchemeDependent: true}
					if c.beats(winners.alternateVariables.View()[d.custom]) {
						winners.alternateVariables.Set(s.memory, d.custom, c)
					}
				} else {
					if !source.retain && d.prop < properties && d.prop >= 0 {
						applyProperty(d, d.prop)
					}
					if !source.retain && d.prop == allShorthandProperty {
						for p := 0; p < properties; p++ {
							applyProperty(d, p)
						}
					}
					if d.prop >= properties && d.prop != allShorthandProperty {
						winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(d)
					}
				}
			}
			if !source.retain {
				continue
			}
			if d.custom != "" {
				c := candidate{d: d, property: d.prop, set: true, inline: source.inline, uncertainOrigin: source.uncertain, spec: source.specificity, colourSchemeDependent: source.colourSchemeDependent}
				if winners.variables == nil {
					s.runtime.variableScratch.Reset()
				}
				if c.beats(winners.variables[d.custom]) {
					s.runtime.variableScratch.Set(s.memory, d.custom, c)
				}
				winners.variables = s.runtime.variableScratch.View()
			} else if d.prop == allShorthandProperty {
				for property := 0; property < declarationProperties; property++ {
					applyProperty(d, property)
				}
			} else {
				applyProperty(d, d.prop)
			}
		}
		return
	}

	apply(legacy, cascadeSource{retain: true})

	mediaStates := media.evaluate(s, work)

	for _, ref := range refs {
		work.check()

		r := &s.rules[ref.rule]
		plan := &r.plans[ref.branch]
		state := int(mediaStates[r.mediaGroup])
		if state == mediaNo {
			continue
		}
		matched, cached := false, false
		if s.runtime.cacheMatches && plan.sequence < len(s.runtime.matchCaches) {
			state := s.runtime.matchCaches[plan.sequence].View()[n]
			matched, cached = state == 2, state != 0
		}
		if !cached {
			if plan.uncertain {
				work.check()
				matched = s.matchSelector(plan.scope, n)
			} else if plan.ancestorChain != nil {
				var complete bool
				matched, complete = s.matchAncestorChain(plan, n, selectorContext, work)
				if !complete {
					return cascadeWinners{}, false
				}
			} else {
				work.check()
				matched = s.matchSelector(plan.matcher, n)
			}

			s.cacheMatch(plan, n, matched)
		}
		if matched {
			if state == mediaAlternateColourScheme {
				apply(r.decls, cascadeSource{specificity: plan.specificity, colourSchemeDependent: true})
			} else if plan.uncertain || r.uncertainOrigin {
				apply(r.decls, cascadeSource{specificity: plan.specificity, uncertain: true, colourSchemeDependent: state == mediaYesColourScheme, retain: true})
			} else {
				apply(r.decls, cascadeSource{specificity: plan.specificity, uncertain: state == mediaUnknown, colourSchemeDependent: state == mediaYesColourScheme, retain: true})
			}
		}
	}

	apply(inline, cascadeSource{inline: true, retain: true})

	if hasColourSchemeDeclarations {
		for name, alternate := range winners.alternateVariables.View() {
			work.check()

			c := winners.variables[name]
			if c.set && c.colourSchemeDependent || alternate.beats(c) {
				winners.alternateColourSchemeVars.Set(s.memory, name, true)
			}
		}
		for p, c := range winners.properties {
			alternate := winners.alternateProperties[p]
			if c.set && c.colourSchemeDependent || alternate.set && alternate.beats(c) {
				winners.alternateColourSchemeReasons |= alternateColourSchemeEffects(&declaration{prop: p})
			}
		}
	}
	return winners, true
}

func (s *sheet) elementStyle(n *html.Node, parent, root *Style, parentVars *variableScope, legacy, inline []declaration, media *mediaEvaluation, selectorContext selectorMatchContext, work *cpuGuard) elementStyleResult {
	if s.cascadeIncomplete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}

	work.check()

	st := initial()
	for i := range st {
		if inherits(i) {
			st[i] = parent[i]
		}
	}
	// UA presentation differs across email clients. Unknown defaults are
	// overridable by author declarations through the normal cascade.
	if n.Namespace == "" {
		switch n.Data {
		case "a", "area":
			if hasAttr(n, "href") {
				st[color] = Value{Text: "link-default", Known: true, RGBA: RGBA{B: 238.0 / 255, A: 1}}
			}
		case "h1", "h2", "h3", "h4", "h5", "h6", "small", "big", "sub", "sup":
			value := "smaller"
			switch n.Data {
			case "h1":
				value = "2em"
			case "h2":
				value = "1.5em"
			case "h3":
				value = "1.17em"
			case "h4":
				value = "1em"
			case "h5":
				value = ".83em"
			case "h6":
				value = ".67em"
			case "big":
				value = "larger"
			}
			st[fontSize], _ = resolveWithBudget(fontSize, value, parent, root, work)
		case "dialog":
			if !hasAttr(n, "open") {
				st[display] = Value{Text: "native-closed"}
			}
		case "datalist", "rp":
			st[display] = Value{Text: "native-hidden"}
		}
	}
	refs := s.collectCandidates(n, work)

	if len(refs) == 0 && len(legacy) == 0 && len(inline) == 0 {
		// No declarations can affect this element. Preserve inherited computed
		// values (including uncertainty) and the variable scope without building
		// cascade winners or resolving layout/animations. Ancestor presentation
		// effects are carried separately by viewingCaseFrame.
		return elementStyleResult{style: st, variables: parentVars}
	}

	work.check()

	// Resolution is sequential; reuse scratch rather than allocating a memo
	// for every element and viewing case. Never retain a previous element's key.
	variableMemo := &s.runtime.variableMemo
	*variableMemo = declarationScopeMemo{}
	context := evaluationContext{parent: parent, root: root, vars: parentVars, budget: work, variableMemo: variableMemo}
	winners, complete := s.collectCascade(n, refs, legacy, inline, media, selectorContext, work, context)
	if !complete {
		return elementStyleResult{style: unresolvedStyle(), variables: parentVars}
	}
	scope := buildVariables(parentVars, winners.variables, winners.alternateColourSchemeVars.View(), work)
	// Variable scopes never retain the cascade map, so it can be reused by the
	// next element even when expression evaluation was abandoned.
	if winners.variables != nil {
		// variableScratch already owns the borrowed winners map.
	}

	context.vars = scope
	for i := 0; i < properties; i++ {
		c := winners.properties[i]
		if i == lineHeight {
			context.currentFontNumber = st[fontSize].Number
			context.currentFontKnown = st[fontSize].Known
		}
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
	marginRoot := root
	if n.Namespace == "" && n.Data == "html" {
		marginRoot = &st
	}
	for i := range winners.layout {
		c := &winners.layout[i]

		if m := marginIndex(i + properties); m >= 0 && c.uncertainOrigin && winners.nonzeroConditionalMargins&(1<<m) == 0 {
			ordinary := resolveLayoutCandidate(&winners.ordinaryMargins[m], context)
			if !extremeOrUnresolvedMargin(ordinary, &st, marginRoot) {
				c.uncertainOrigin = false
			}
		}

	}
	layout := layoutVisibility(&winners.layout, &st, context, n)
	animationActive := s.potentiallyActiveAnimation(winners.animation, context, work)
	// A literal display:none on this element is independent of animation on
	// another element. Do not make this claim for inherited or variable values.
	displayWinner := winners.properties[display]
	stableDisplayNone := st[display].Known && st[display].Text == "none" && !animationActive &&
		winners.alternateColourSchemeReasons&reasonDisplayNone == 0 && displayWinner.set &&
		!displayWinner.d.hasVars && equalASCIIFold(trimCSSWhitespace(displayWinner.d.value), "none")
	return elementStyleResult{
		style: st, variables: scope, layoutUncertain: layout.uncertain, elementGeometryConcealed: layout.elementConcealed,
		clipsDescendantsX: layout.clipsX, clipsDescendantsY: layout.clipsY,
		offsetWithinClippedAncestorX: layout.offsetX, offsetWithinClippedAncestorY: layout.offsetY,
		displayDeclared:              winners.properties[display].set,
		alternateColourSchemeReasons: winners.alternateColourSchemeReasons,
		animationActive:              animationActive,
		stableDisplayNone:            stableDisplayNone,
		fontScaleUncertain:           layout.fontScaleUncertain,
		textLayout:                   layout.textLayout, textLayoutSet: layout.textLayoutSet,
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
	case fontSize, fontSizeAdjust:
		return reasonFontSize
	case scale, transform, zoom:
		return reasonFontSize | reasonEmptyClip | reasonColour
	case translate, rotate:
		return reasonEmptyClip | reasonColour
	case color, background, backgroundImage, filter, blend, backdropFilter,
		backgroundBlend, maskImage, backgroundClip, textShadow, textFill, textStroke:
		return reasonColour
	case clip, clipPath, overflowX, overflowY, overflowInline, overflowBlock, width, height, maxWidth, maxHeight,
		left, top, right, bottom, textIndent, letterSpacing, wordSpacing, lineHeight,
		marginTop, marginRight, marginBottom,
		marginLeft, position:
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

// marginIndex keeps the two contiguous margin property groups in a small fixed array.
func marginIndex(property int) int {
	if property >= marginTop && property <= marginLeft {
		return property - marginTop
	}
	if property >= marginInlineStart && property <= marginBlockEnd {
		return 4 + property - marginInlineStart
	}
	return -1
}
