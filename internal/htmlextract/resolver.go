package htmlextract

import (
	"strings"

	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

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
	hadVar := d.hasVars
	v := substitute(d, vars, budget)
	if v.status == 0 {
		return resolve(d.prop, "unset", parent, root)
	}
	if v.status == 2 {
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
		out, status = evalMath(d.prop, value, parent, root, budget)
	} else {
		out, status = resolve(d.prop, value, parent, root)
	}
	if status == 0 && hadVar {
		return resolve(d.prop, "unset", parent, root)
	}
	return out, status
}
func (s *sheet) elementStyle(n *html.Node, parent, root Style, parentVars *variableScope, inline []declaration, width float64, fallback bool, matches *matchBudget, budget *expressionBudget) (Style, *variableScope, error) {
	if s.cascadeIncomplete {
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
	apply := func(ds []declaration, spec cascadia.Specificity, inl, uncertain bool) {
		for _, d := range ds {
			if d.custom == "" && !d.unsupported && !d.hasVars && !d.shorthand {
				_, status := resolvedDeclaration(d, parent, root, parentVars, budget)
				if status == 0 {
					continue
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
	}
	apply(legacyDeclarations(n), cascadia.Specificity{}, false, false)
	matchIncomplete := func() (Style, *variableScope, error) {
		return unresolvedStyle(), parentVars, nil
	}
	mediaStates := s.mediaStates(width, fallback)
	for ruleNumber := range s.rules {
		r := s.rules[ruleNumber]
		// Charge the rule visit before inspecting its media state. Otherwise an
		// attacker can retain an element-by-rule scan using only inactive rules.
		if !matches.spend(1) {
			return matchIncomplete()
		}
		state := int(mediaStates[ruleNumber])
		if state == mediaNo {
			continue
		}
		if r.uncertainSelector {
			// The complete selector may or may not match. Its retained selector
			// group is a conservative target scope, so declarations need not
			// contaminate elements that the original selector could never match.
			for i, sel := range r.selectors {
				if !matches.spend(r.costs[i]) {
					return matchIncomplete()
				}
				if sel.Match(n) {
					// Maximal specificity prevents a lower-specificity rule from
					// creating false confidence. Inline precedence is unchanged.
					apply(r.decls, cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}, false, true)
					break
				}
			}
			continue
		}
		for i, sel := range r.selectors {
			// The recovered rightmost compound is a necessary (but not
			// sufficient) condition for the complete selector. Most elements
			// fail it immediately in Cascadia too; charge only that cheap test
			// and avoid assigning full ancestor/sibling-search cost to it.
			if !matches.spend(r.scopeCosts[i]) {
				return matchIncomplete()
			}
			if !r.fallbackScopes[i].Match(n) {
				continue
			}
			if !matches.spend(r.costs[i]) {
				return matchIncomplete()
			}
			if sel.Match(n) {
				apply(r.decls, sel.Specificity(), false, state == mediaUnknown)
			}
		}
	}
	apply(inline, cascadia.Specificity{}, true, false)
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
