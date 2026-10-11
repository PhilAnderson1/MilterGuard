package htmlextract

import (
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// Applying a declaration entails validity checks, cascade comparison and
// candidate storage; weight it above a simple selector-index lookup.
const declarationApplyWeight int64 = 16

// Go maps have substantial per-entry overhead. Bound cached selector results
// independently of the CPU-work budget so one message has a predictable
// memory ceiling. Matching continues normally after the cache is full.
const maxMatchCacheEntries = 100_000

type mediaCacheKey struct {
	width    float64
	fallback bool
}

func (s *sheet) mediaStates(width float64, fallback bool) []uint8 {
	key := mediaCacheKey{width: width, fallback: fallback}
	if states := s.mediaCache[key]; states != nil {
		return states
	}
	if s.mediaCache == nil {
		s.mediaCache = make(map[mediaCacheKey][]uint8)
	}
	states := make([]uint8, len(s.rules))
	for i := range s.rules {
		states[i] = uint8(s.rules[i].mediaState(width, fallback))
	}
	s.mediaCache[key] = states
	return states
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
	if len(v.text) > maxResolvedValueBytes {
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
func (s *sheet) elementStyle(n *html.Node, parent, root Style, parentVars *variableScope, inline []declaration, width float64, fallback bool, matches *matchBudget, budget *expressionBudget) (Style, *variableScope, error) {
	if s.cascadeIncomplete || s.workIncomplete {
		if s.workIncomplete {
			matches.exhausted = true
		}
		return unresolvedStyle(), parentVars, nil
	}
	// Once shared matching work is exhausted, every remaining element is
	// unresolved. Avoid rebuilding and sorting its candidate-rule list merely
	// to fail the first budget charge again.
	if matches.exhausted {
		return unresolvedStyle(), parentVars, nil
	}
	st := initial()
	for i := range st {
		if inherits(i) {
			st[i] = parent[i]
		}
	}
	var wins [properties]candidate
	var vars map[string]candidate
	apply := func(ds []declaration, spec cascadia.Specificity, inl, uncertain bool) bool {
		// Reserve the complete declaration-list cost before changing the
		// cascade. A failed reservation must not leave a partially applied
		// style that appears trustworthy.
		if len(ds) > 0 && !matches.spend(int64(len(ds))*declarationApplyWeight) {
			return false
		}
		for _, d := range ds {
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
			d.unsupported = d.unsupported || uncertain
			c := candidate{d: d, set: true, inline: inl, spec: spec}
			if d.custom != "" {
				if vars == nil {
					vars = map[string]candidate{}
				}
				if c.beats(vars[d.custom]) {
					vars[d.custom] = c
				}
			} else if c.beats(wins[d.prop]) {
				wins[d.prop] = c
			}
		}
		return true
	}
	matchIncomplete := func() (Style, *variableScope, error) {
		return unresolvedStyle(), parentVars, nil
	}
	if !apply(prepareDeclarations(legacyDeclarations(n)), cascadia.Specificity{}, false, false) {
		return matchIncomplete()
	}
	mediaStates := s.mediaStates(width, fallback)
	for _, ref := range s.candidates(n) {
		r := &s.rules[ref.rule]
		plan := &r.plans[ref.branch]
		if !matches.spend(1) {
			return matchIncomplete()
		}
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
			if !matches.spend(plan.cost) {
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
	for i, c := range wins {
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
	return st, scope, nil
}
