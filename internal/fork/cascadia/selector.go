package cascadia

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Matcher is an opaque compiled predicate. Callers execute it through
// MatchControl so selector work cannot bypass resource checkpoints.
type Matcher interface {
	matchNode(n *html.Node) bool
}

// Sel is the interface for all the functionality provided by selectors.
type Sel interface {
	Matcher
	Specificity() Specificity

	// Returns a CSS input compiling to this selector.
	String() string

	// Returns a pseudo-element, or an empty string.
	PseudoElement() string
}

// MatcherFunc adapts a bounded single-node predicate for use through
// MatchControl. Tree traversal remains the caller's guarded responsibility.
type MatcherFunc func(*html.Node) bool

func (m MatcherFunc) matchNode(n *html.Node) bool { return m(n) }

type namespaceTypeMatcher struct{ foreignName, htmlName string }

func (m namespaceTypeMatcher) matchNode(n *html.Node) bool {
	if n.Type != html.ElementNode {
		return false
	}
	if n.Namespace == "" {
		return n.Data == m.htmlName
	}
	return n.Data == m.foreignName
}

// NewNamespaceTypeMatcherWithMemory creates a bounded single-node matcher for
// a case-sensitive foreign type and its normalized HTML spelling.
func NewNamespaceTypeMatcherWithMemory(foreignName, htmlName string, memory *resourceguard.Memory) Matcher {
	return resourceguard.New(memory, namespaceTypeMatcher{foreignName: foreignName, htmlName: htmlName})
}

// Parse parses a selector. Use `ParseWithPseudoElement`
// if you need support for pseudo-elements.
func Parse(sel string) (Sel, error) {
	if err := validateSelectorInput(sel); err != nil {
		return nil, err
	}
	p := &parser{s: sel}
	compiled, err := p.parseSelector()
	if err != nil {
		return nil, err
	}

	if p.i < len(sel) {
		return nil, ErrInvalidSelector
	}

	return compiled, nil
}

// ParseWithPseudoElement parses a single selector,
// with support for pseudo-element.
func ParseWithPseudoElement(sel string) (Sel, error) {
	if err := validateSelectorInput(sel); err != nil {
		return nil, err
	}
	p := &parser{s: sel, acceptPseudoElements: true}
	compiled, err := p.parseSelector()
	if err != nil {
		return nil, err
	}

	if p.i < len(sel) {
		return nil, ErrInvalidSelector
	}

	return compiled, nil
}

// ParseGroup parses a selector, or a group of selectors separated by commas.
// Use `ParseGroupWithPseudoElements`
// if you need support for pseudo-elements.
func ParseGroup(sel string) (SelectorGroup, error) {
	return ParseGroupWithMemory(sel, nil)
}

// ParseGroupWithMemory charges source retention, component storage, copied
// strings and substring tables. Structural limits independently bound work.
func ParseGroupWithMemory(sel string, memory *resourceguard.Memory) (SelectorGroup, error) {
	return parseGroup(sel, memory, false, false)
}

// ParseGroupWithPseudoElementsAndMemory parses a selector group including
// pseudo-elements and charges its compilation allocations to memory.
func ParseGroupWithPseudoElementsAndMemory(sel string, memory *resourceguard.Memory) (SelectorGroup, error) {
	return parseGroup(sel, memory, true, false)
}

// ParseCSSGroupWithMemory excludes non-CSS selector extensions, including nested ones.
// The caller validates ordinary list branches with SelectorListIterator.
func ParseCSSGroupWithMemory(sel string, memory *resourceguard.Memory) (SelectorGroup, error) {
	return parseGroup(sel, memory, true, true)
}

func parseGroup(sel string, memory *resourceguard.Memory, acceptPseudoElements, strictCSS bool) (result SelectorGroup, err error) {

	if err := validateSelectorInput(sel); err != nil {
		return nil, err
	}

	// Source substrings borrow the caller's immutable input; no allocation
	// occurs here and its storage is already owned by the caller.
	p := &parser{s: sel, acceptPseudoElements: acceptPseudoElements, strictCSS: strictCSS, memory: memory}
	compiled, err := p.parseSelectorGroup()
	if err != nil {
		return nil, err
	}

	if p.i < len(sel) {
		return nil, ErrInvalidSelector
	}

	return compiled, nil
}

// ParseGroupWithPseudoElements parses a selector, or a group of selectors separated by commas.
// It supports pseudo-elements.
func ParseGroupWithPseudoElements(sel string) (SelectorGroup, error) {
	return ParseGroupWithPseudoElementsAndMemory(sel, nil)
}

// CombinePositiveMatchers combines already compiled positive compounds for a
// conservative descendant, child, or sibling scope.
func CombinePositiveMatchers(left, right Matcher, combinator byte) Matcher {
	return CombinePositiveMatchersWithMemory(left, right, combinator, nil)
}

func CombinePositiveMatchersWithMemory(left, right Matcher, combinator byte, memory *resourceguard.Memory) Matcher {
	leftSelector, leftOK := left.(Sel)
	rightSelector, rightOK := right.(Sel)
	if !leftOK || !rightOK || combinator != ' ' && combinator != '>' && combinator != '+' && combinator != '~' {
		return nil
	}
	value := resourceguard.Box(memory, combinedSelector{first: leftSelector, combinator: combinator, second: rightSelector})

	return value.(Matcher)
}

type tagSelector struct {
	tag      string
	original string
}

// Matches elements with a given tag name.
func (t tagSelector) matchNode(n *html.Node) bool {
	return n.Type == html.ElementNode && n.Data == t.tag
}

func (c tagSelector) Specificity() Specificity {
	return Specificity{0, 0, 1}
}

func (c tagSelector) PseudoElement() string {
	return ""
}

type classSelector struct {
	class string
}

// Matches elements by class attribute.
func (t classSelector) matchNode(n *html.Node) bool {
	return t.matchResource(n, nil)
}

func (t classSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	return matchAttributeResource(n, "class", func(s string) bool {
		return matchIncludeResource(t.class, s, false, guard)
	}, guard)
}

func (c classSelector) Specificity() Specificity {
	return Specificity{0, 1, 0}
}

func (c classSelector) PseudoElement() string {
	return ""
}

type idSelector struct {
	id string
}

// Matches elements by id attribute.
func (t idSelector) matchNode(n *html.Node) bool {
	return t.matchResource(n, nil)
}

func (t idSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	return matchAttributeResource(n, "id", func(s string) bool {
		return s == t.id
	}, guard)
}

func (c idSelector) Specificity() Specificity {
	return Specificity{1, 0, 0}
}

func (c idSelector) PseudoElement() string {
	return ""
}

type attrSelector struct {
	key, val, operation string
	insensitive         bool
	failure             []int // immutable substring prefix table, prepared at compilation
}

// Matches elements by attribute value.
func (t attrSelector) matchNode(n *html.Node) bool {
	return t.matchResource(n, nil)
}

func (t attrSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if t.operation == "" {
		return hasAttributeResource(n, t.key, guard)
	}
	if n.Type != html.ElementNode {
		return false
	}
	for _, a := range n.Attr {
		guard.step()

		if a.Key != t.key {
			continue
		}
		matched := t.matchValue(a.Val, guard)
		if t.operation == "!=" {
			if matched {
				return false
			}
		} else if matched {
			return true
		}
	}
	return t.operation == "!="
}

func matchAttributeResource(n *html.Node, key string, f func(string) bool, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	for _, a := range n.Attr {
		guard.step()

		if a.Key == key && f(a.Val) {
			return true
		}
	}
	return false
}

func hasAttributeResource(n *html.Node, key string, guard *MatchControl) bool {
	if n.Type != html.ElementNode {
		return false
	}
	for _, attribute := range n.Attr {
		guard.step()

		if attribute.Key == key {
			return true
		}
	}
	return false
}

func foldASCII(value byte) byte {
	if 'A' <= value && value <= 'Z' {
		return value + ('a' - 'A')
	}
	return value
}

func (c attrSelector) Specificity() Specificity {
	return Specificity{0, 1, 0}
}

func (c attrSelector) PseudoElement() string {
	return ""
}

// see pseudo_classes.go for pseudo classes selectors

// on a static context, some selectors can't match anything
type neverMatchSelector struct {
	value string
}

func (s neverMatchSelector) matchNode(n *html.Node) bool {
	return false
}

func (s neverMatchSelector) Specificity() Specificity {
	return Specificity{0, 0, 0}
}

func (c neverMatchSelector) PseudoElement() string {
	return ""
}

type compoundSelector struct {
	selectors     []Sel
	pseudoElement string
}

// Matches elements if each sub-selectors matches.
func (t compoundSelector) matchNode(n *html.Node) bool {
	return t.matchResource(n, nil)
}

func (t compoundSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if len(t.selectors) == 0 {
		return n.Type == html.ElementNode
	}

	for _, sel := range t.selectors {
		if !matchResource(sel, n, guard) {
			return false
		}
	}
	return true
}

func (s compoundSelector) Specificity() Specificity {
	var out Specificity
	for _, sel := range s.selectors {
		out = out.Add(sel.Specificity())
	}
	if s.pseudoElement != "" {
		// https://drafts.csswg.org/selectors-3/#specificity
		out = out.Add(Specificity{0, 0, 1})
	}
	return out
}

func (c compoundSelector) PseudoElement() string {
	return c.pseudoElement
}

type combinedSelector struct {
	first      Sel
	combinator byte
	second     Sel
}

func (t combinedSelector) matchNode(n *html.Node) bool {
	return t.matchResource(n, nil)
}

func (t combinedSelector) matchResource(n *html.Node, guard *MatchControl) bool {
	if t.first == nil {
		return false // maybe we should panic
	}
	switch t.combinator {
	case 0:
		return matchResource(t.first, n, guard)
	case ' ':
		return descendantMatchResource(t.first, t.second, n, guard)
	case '>':
		return childMatchResource(t.first, t.second, n, guard)
	case '+':
		return siblingMatchResource(t.first, t.second, true, n, guard)
	case '~':
		return siblingMatchResource(t.first, t.second, false, n, guard)
	default:
		panic("unknown combinator")
	}
}

// matches an element if it matches d and has an ancestor that matches a.
func descendantMatch(a, d Matcher, n *html.Node) bool {
	return descendantMatchResource(a, d, n, nil)
}

func descendantMatchResource(a, d Matcher, n *html.Node, guard *MatchControl) bool {
	if !matchResource(d, n, guard) {
		return false
	}

	for p := n.Parent; p != nil; p = p.Parent {
		// matchResource samples once per visited ancestor.
		if matchResource(a, p, guard) {
			return true
		}
	}

	return false
}

// matches an element if it matches d and its parent matches a.
func childMatch(a, d Matcher, n *html.Node) bool {
	return childMatchResource(a, d, n, nil)
}

func childMatchResource(a, d Matcher, n *html.Node, guard *MatchControl) bool {
	return matchResource(d, n, guard) && n.Parent != nil && matchResource(a, n.Parent, guard)
}

// matches an element if it matches s2 and is preceded by an element that matches s1.
// If adjacent is true, the sibling must be immediately before the element.
func siblingMatch(s1, s2 Matcher, adjacent bool, n *html.Node) bool {
	return siblingMatchResource(s1, s2, adjacent, n, nil)
}

func siblingMatchResource(s1, s2 Matcher, adjacent bool, n *html.Node, guard *MatchControl) bool {
	if !matchResource(s2, n, guard) {
		return false
	}

	if adjacent {
		for n = n.PrevSibling; n != nil; n = n.PrevSibling {
			guard.step()

			if n.Type == html.TextNode || n.Type == html.CommentNode {
				continue
			}
			return matchResource(s1, n, guard)
		}
		return false
	}

	// Walk backwards looking for element that matches s1
	for c := n.PrevSibling; c != nil; c = c.PrevSibling {
		// matchResource samples once per visited sibling.
		if matchResource(s1, c, guard) {
			return true
		}
	}

	return false
}

func (s combinedSelector) Specificity() Specificity {
	spec := s.first.Specificity()
	if s.second != nil {
		spec = spec.Add(s.second.Specificity())
	}
	return spec
}

// on combinedSelector, a pseudo-element only makes sens on the last
// selector, although others increase specificity.
func (c combinedSelector) PseudoElement() string {
	if c.second == nil {
		return ""
	}
	return c.second.PseudoElement()
}

// A SelectorGroup is a list of selectors, which matches if any of the
// individual selectors matches.
type SelectorGroup []Sel

func (s SelectorGroup) matchNode(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s SelectorGroup) matchResource(n *html.Node, guard *MatchControl) bool {
	for _, sel := range s {
		if matchResource(sel, n, guard) {
			return true
		}
	}
	return false
}
