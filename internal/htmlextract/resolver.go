package htmlextract

import (
	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
	"strings"
)

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
	hadVar := hasVariables(d.value)
	v := substitute(d.value, vars, budget)
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
func (s *sheet) elementStyle(n *html.Node, parent, root Style, parentVars *variableScope, inline []declaration, width float64, fallback bool, work *int64, budget *expressionBudget) (Style, *variableScope, error) {
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
			if d.custom == "" && !d.unsupported && !hasVariables(d.value) && !d.shorthand {
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
	for _, r := range s.rules {
		state := r.mediaState(width, fallback)
		if state == mediaNo {
			continue
		}
		if r.uncertainSelector {
			// The complete selector may or may not match. Its retained selector
			// group is a conservative target scope, so declarations need not
			// contaminate elements that the original selector could never match.
			for i, sel := range r.selectors {
				if r.costs[i] <= s.limits.MatchWork-*work {
					*work += r.costs[i]
				} else {
					s.warn("selector match work exhausted; affected declarations unresolved")
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
			if !r.fallbackScopes[i].Match(n) {
				if r.scopeCosts[i] <= s.limits.MatchWork-*work {
					*work += r.scopeCosts[i]
				} else {
					s.warn("selector match work exhausted; affected declarations unresolved")
				}
				continue
			}
			if r.costs[i] > s.limits.MatchWork-*work {
				// Visibility resolution may hit its work limit without losing
				// extracted text. Retain a conservative target scope for the
				// skipped selector instead of abandoning the entire DOM and
				// making every passage uncertain.
				s.warn("selector match work exhausted; affected declarations unresolved")
				if r.fallbackScopes[i].Match(n) {
					apply(r.decls, cascadia.Specificity{1<<30 - 1, 1<<30 - 1, 1<<30 - 1}, false, true)
				}
				continue
			}
			*work += r.costs[i]
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
				s.warn("unsupported/unresolved value: " + names[i] + ":" + c.d.value)
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
