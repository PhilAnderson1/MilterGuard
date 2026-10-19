package cascadia

import (
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Matcher is the interface for basic selector functionality.
// Match returns whether a selector matches n.
type Matcher interface {
	Match(n *html.Node) bool
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
	defer recoverAllocation(&err)
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

// A Selector is a function which tells whether a node matches or not.
//
// This type is maintained for compatibility; I recommend using the newer and
// more idiomatic interfaces Sel and Matcher.
type Selector func(*html.Node) bool

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
	value, ok := resourceguard.Box(memory, combinedSelector{first: leftSelector, combinator: combinator, second: rightSelector})
	if !ok {
		return nil
	}
	return value.(Matcher)
}

// Compile parses a selector and returns, if successful, a Selector object
// that can be used to match against html.Node objects.
func Compile(sel string) (Selector, error) {
	compiled, err := ParseGroup(sel)
	if err != nil {
		return nil, err
	}

	return Selector(compiled.Match), nil
}

// MustCompile is like Compile, but panics instead of returning an error.
func MustCompile(sel string) Selector {
	compiled, err := Compile(sel)
	if err != nil {
		panic(err)
	}
	return compiled
}

// MatchAll returns a slice of the nodes that match the selector,
// from n and its children.
func (s Selector) MatchAll(n *html.Node) []*html.Node {
	return s.matchAllInto(n, nil)
}

func (s Selector) matchAllInto(n *html.Node, storage []*html.Node) []*html.Node {
	if s(n) {
		storage = append(storage, n)
	}

	for child := n.FirstChild; child != nil; child = child.NextSibling {
		storage = s.matchAllInto(child, storage)
	}

	return storage
}

func queryInto(n *html.Node, m Matcher, storage []*html.Node) []*html.Node {
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if m.Match(child) {
			storage = append(storage, child)
		}
		storage = queryInto(child, m, storage)
	}

	return storage
}

// QueryAll returns a slice of all the nodes that match m, from the descendants
// of n.
func QueryAll(n *html.Node, m Matcher) []*html.Node {
	return queryInto(n, m, nil)
}

// Match returns true if the node matches the selector.
func (s Selector) Match(n *html.Node) bool {
	return s(n)
}

// MatchFirst returns the first node that matches s, from n and its children.
func (s Selector) MatchFirst(n *html.Node) *html.Node {
	if s.Match(n) {
		return n
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		m := s.MatchFirst(c)
		if m != nil {
			return m
		}
	}
	return nil
}

// Query returns the first node that matches m, from the descendants of n.
// If none matches, it returns nil.
func Query(n *html.Node, m Matcher) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if m.Match(c) {
			return c
		}
		if matched := Query(c, m); matched != nil {
			return matched
		}
	}

	return nil
}

// Filter returns the nodes in nodes that match the selector.
func (s Selector) Filter(nodes []*html.Node) (result []*html.Node) {
	for _, n := range nodes {
		if s(n) {
			result = append(result, n)
		}
	}
	return result
}

// Filter returns the nodes that match m.
func Filter(nodes []*html.Node, m Matcher) (result []*html.Node) {
	for _, n := range nodes {
		if m.Match(n) {
			result = append(result, n)
		}
	}
	return result
}

type tagSelector struct {
	tag      string
	original string
}

// Matches elements with a given tag name.
func (t tagSelector) Match(n *html.Node) bool {
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
func (t classSelector) Match(n *html.Node) bool {
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
func (t idSelector) Match(n *html.Node) bool {
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
func (t attrSelector) Match(n *html.Node) bool {
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
		if guard.step() {
			return false
		}
		if a.Key != t.key {
			continue
		}
		matched := t.matchValue(a.Val, guard)
		if guard != nil && guard.stopped {
			return false
		}
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
		if guard.step() {
			return false
		}
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
		if guard.step() {
			return false
		}
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

func (s neverMatchSelector) Match(n *html.Node) bool {
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
func (t compoundSelector) Match(n *html.Node) bool {
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

func (t combinedSelector) Match(n *html.Node) bool {
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
		if guard != nil && guard.stopped {
			return false
		}
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
			if guard.step() {
				return false
			}
			if n.Type == html.TextNode || n.Type == html.CommentNode {
				continue
			}
			return matchResource(s1, n, guard)
		}
		return false
	}

	// Walk backwards looking for element that matches s1
	for c := n.PrevSibling; c != nil; c = c.PrevSibling {
		if guard != nil && guard.stopped {
			return false
		}
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

// Match returns true if the node matches one of the single selectors.
func (s SelectorGroup) Match(n *html.Node) bool {
	return s.matchResource(n, nil)
}

func (s SelectorGroup) matchResource(n *html.Node, guard *MatchControl) bool {
	for _, sel := range s {
		if guard != nil && guard.stopped {
			return false
		}
		if matchResource(sel, n, guard) {
			return true
		}
	}
	return false
}
