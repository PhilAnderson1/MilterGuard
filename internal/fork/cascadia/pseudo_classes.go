package cascadia

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/atom"
)

// This file implements the pseudo classes selectors,
// which share the implementation of PseudoElement() and Specificity()

type abstractPseudoClass struct{}

func (s abstractPseudoClass) Specificity() Specificity {
	return Specificity{0, 1, 0}
}

func (c abstractPseudoClass) PseudoElement() string {
	return ""
}

type relativePseudoClassSelector struct {
	name  string // one of "not", "has", "haschild"
	match SelectorGroup
}

func (s relativePseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s relativePseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	switch s.name {
	case "not":
		// matches elements that do not match a.
		matched := matchResource(s.match, n, guard)
		return !matched && (guard == nil || !guard.stopped)
	case "has":
		//  matches elements with any descendant that matches a.
		return hasDescendantMatchResource(n, s.match, guard)
	case "haschild":
		// matches elements with a child that matches a.
		return hasChildMatchResource(n, s.match, guard)
	default:
		panic("cascadia: unsupported relative pseudo class")
	}
}

// hasChildMatch returns whether n has any child that matches a.
func hasChildMatch(n *html.Node, a SelectorGroup) bool {
	return hasChildMatchResource(n, a, nil)
}

func hasChildMatchResource(n *html.Node, a SelectorGroup, guard *MatchControl) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if guard != nil && guard.stopped {
			return false
		}
		if matchResource(a, c, guard) {
			return true
		}
	}
	return false
}

// hasDescendantMatch performs a depth-first search of n's descendants,
// testing whether any of them match a. It returns true as soon as a match is
// found, or false if no match is found.
func hasDescendantMatch(n *html.Node, a SelectorGroup) bool {
	return hasDescendantMatchResource(n, a, nil)
}

func hasDescendantMatchResource(n *html.Node, a SelectorGroup, guard *MatchControl) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if guard.step() {
			return false
		}
		if matchResource(a, c, guard) || (c.Type == html.ElementNode && hasDescendantMatchResource(c, a, guard)) {
			return true
		}
	}
	return false
}

// Specificity returns the specificity of the most specific selectors
// in the pseudo-class arguments.
// See https://www.w3.org/TR/selectors/#specificity-rules
func (s relativePseudoClassSelector) Specificity() Specificity {
	var max Specificity
	for _, sel := range s.match {
		newSpe := sel.Specificity()
		if max.Less(newSpe) {
			max = newSpe
		}
	}
	return max
}

func (c relativePseudoClassSelector) PseudoElement() string {
	return ""
}

type nthPseudoClassSelector struct {
	abstractPseudoClass
	a, b         int
	last, ofType bool
}

func (s nthPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s nthPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if s.a == 0 {
		if s.last {
			return simpleNthLastChildMatchResource(s.b, s.ofType, n, guard)
		} else {
			return simpleNthChildMatchResource(s.b, s.ofType, n, guard)
		}
	}
	return nthChildMatchResource(s.a, s.b, s.last, s.ofType, n, guard)
}

// nthChildMatch implements :nth-child(an+b).
// If last is true, implements :nth-last-child instead.
// If ofType is true, implements :nth-of-type instead.
func nthChildMatch(a, b int, last, ofType bool, n *html.Node) bool {
	return nthChildMatchResource(a, b, last, ofType, n, nil)
}

func nthChildMatchResource(a, b int, last, ofType bool, n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}

	parent := n.Parent
	if parent == nil {
		return false
	}

	i := -1
	count := 0
	for c := parent.FirstChild; c != nil; c = c.NextSibling {
		if guard.step() {
			return false
		}
		if (c.Type != html.ElementNode) || (ofType && c.Data != n.Data) {
			continue
		}
		count++
		if c == n {
			i = count
			if !last {
				break
			}
		}
	}

	if i == -1 {
		// This shouldn't happen, since n should always be one of its parent's children.
		return false
	}

	if last {
		i = count - i + 1
	}

	i -= b
	if a == 0 {
		return i == 0
	}

	return i%a == 0 && i/a >= 0
}

// simpleNthChildMatch implements :nth-child(b).
// If ofType is true, implements :nth-of-type instead.
func simpleNthChildMatch(b int, ofType bool, n *html.Node) bool {
	return simpleNthChildMatchResource(b, ofType, n, nil)
}

func simpleNthChildMatchResource(b int, ofType bool, n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}

	parent := n.Parent
	if parent == nil {
		return false
	}

	count := 0
	for c := parent.FirstChild; c != nil; c = c.NextSibling {
		if guard.step() {
			return false
		}
		if c.Type != html.ElementNode || (ofType && c.Data != n.Data) {
			continue
		}
		count++
		if c == n {
			return count == b
		}
		if count >= b {
			return false
		}
	}
	return false
}

// simpleNthLastChildMatch implements :nth-last-child(b).
// If ofType is true, implements :nth-last-of-type instead.
func simpleNthLastChildMatch(b int, ofType bool, n *html.Node) bool {
	return simpleNthLastChildMatchResource(b, ofType, n, nil)
}

func simpleNthLastChildMatchResource(b int, ofType bool, n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}

	parent := n.Parent
	if parent == nil {
		return false
	}

	count := 0
	for c := parent.LastChild; c != nil; c = c.PrevSibling {
		if guard.step() {
			return false
		}
		if c.Type != html.ElementNode || (ofType && c.Data != n.Data) {
			continue
		}
		count++
		if c == n {
			return count == b
		}
		if count >= b {
			return false
		}
	}
	return false
}

type onlyChildPseudoClassSelector struct {
	abstractPseudoClass
	ofType bool
}

// Match implements :only-child.
// If `ofType` is true, it implements :only-of-type instead.
func (s onlyChildPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s onlyChildPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}

	parent := n.Parent
	if parent == nil {
		return false
	}

	count := 0
	for c := parent.FirstChild; c != nil; c = c.NextSibling {
		if guard.step() {
			return false
		}
		if (c.Type != html.ElementNode) || (s.ofType && c.Data != n.Data) {
			continue
		}
		count++
		if count > 1 {
			return false
		}
	}

	return count == 1
}

type inputPseudoClassSelector struct {
	abstractPseudoClass
}

// Matches input, select, textarea and button elements.
func (s inputPseudoClassSelector) Match(n *html.Node) bool {
	return n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea" || n.Data == "button")
}

type emptyElementPseudoClassSelector struct {
	abstractPseudoClass
}

// Matches empty elements.
func (s emptyElementPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s emptyElementPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if guard.step() {
			return false
		}
		switch c.Type {
		case html.ElementNode:
			return false
		case html.TextNode:
			if !nonBlankAttribute(c.Data, guard) {
				continue
			} else {
				return false
			}
		}
	}

	return true
}

type rootPseudoClassSelector struct {
	abstractPseudoClass
}

// Match implements :root
func (s rootPseudoClassSelector) Match(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}
	if n.Parent == nil {
		return false
	}
	return n.Parent.Type == html.DocumentNode
}

func hasAttr(n *html.Node, attr string) bool {
	return hasAttributeResource(n, attr, nil)
}

func hasAttrResource(n *html.Node, attr string, guard *MatchControl) bool {
	return hasAttributeResource(n, attr, guard)
}

type linkPseudoClassSelector struct {
	abstractPseudoClass
}

// Match implements :link
func (s linkPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s linkPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	return (n.DataAtom == atom.A || n.DataAtom == atom.Area || n.DataAtom == atom.Link) && hasAttrResource(n, "href", guard)
}

type langPseudoClassSelector struct {
	abstractPseudoClass
	lang string
}

func (s langPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s langPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	// Account every recursive ancestor visit. Selector-controlled loops and
	// recursion must advance the guard so cooperative cancellation cannot be
	// bypassed by a long traversal that performs no other guarded work.
	if guard.step() {
		return false
	}
	own := matchAttributeResource(n, "lang", func(val string) bool {
		return equalAttribute(val, s.lang, false, guard) || len(val) > len(s.lang) && val[len(s.lang)] == '-' && equalAttribute(val[:len(s.lang)], s.lang, false, guard)
	}, guard)
	if n.Parent == nil {
		return own
	}
	return own || s.matchResource(n.Parent, guard)
}

type enabledPseudoClassSelector struct {
	abstractPseudoClass
}

func (s enabledPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s enabledPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	switch n.DataAtom {
	case atom.A, atom.Area, atom.Link:
		return hasAttrResource(n, "href", guard)
	case atom.Optgroup, atom.Menuitem, atom.Fieldset:
		return !hasAttrResource(n, "disabled", guard)
	case atom.Button, atom.Input, atom.Select, atom.Textarea, atom.Option:
		return !hasAttrResource(n, "disabled", guard) && !inDisabledFieldsetResource(n, guard)
	}
	return false
}

type disabledPseudoClassSelector struct {
	abstractPseudoClass
}

func (s disabledPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s disabledPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	switch n.DataAtom {
	case atom.Optgroup, atom.Menuitem, atom.Fieldset:
		return hasAttrResource(n, "disabled", guard)
	case atom.Button, atom.Input, atom.Select, atom.Textarea, atom.Option:
		return hasAttrResource(n, "disabled", guard) || inDisabledFieldsetResource(n, guard)
	}
	return false
}

func hasLegendInPreviousSiblings(n *html.Node) bool {
	return hasLegendInPreviousSiblingsResource(n, nil)
}

func hasLegendInPreviousSiblingsResource(n *html.Node, guard *MatchControl) bool {
	for s := n.PrevSibling; s != nil; s = s.PrevSibling {
		if guard.step() {
			return false
		}
		if s.DataAtom == atom.Legend {
			return true
		}
	}
	return false
}

func inDisabledFieldset(n *html.Node) bool {
	return inDisabledFieldsetResource(n, nil)
}

func inDisabledFieldsetResource(n *html.Node, guard *MatchControl) bool {
	if guard.step() {
		return false
	}
	if n.Parent == nil {
		return false
	}
	if n.Parent.DataAtom == atom.Fieldset && hasAttrResource(n.Parent, "disabled", guard) &&
		(n.DataAtom != atom.Legend || hasLegendInPreviousSiblingsResource(n, guard)) {
		return true
	}
	return inDisabledFieldsetResource(n.Parent, guard)
}

type checkedPseudoClassSelector struct {
	abstractPseudoClass
}

func (s checkedPseudoClassSelector) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s checkedPseudoClassSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	switch n.DataAtom {
	case atom.Input, atom.Menuitem:
		return hasAttrResource(n, "checked", guard) && matchAttributeResource(n, "type", func(val string) bool {
			return equalAttribute(val, "checkbox", true, guard) || equalAttribute(val, "radio", true, guard)
		}, guard)
	case atom.Option:
		return hasAttrResource(n, "selected", guard)
	}
	return false
}
