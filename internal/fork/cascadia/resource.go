package cascadia

import (
	"errors"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// ErrInvalidSelector reports rejected selector syntax without allocating diagnostics.
// ErrInvalidAttributeValue identifies a missing or malformed attribute value,
// rather than a selector feature this parser does not support.
var ErrInvalidAttributeValue = errors.New("cascadia: invalid attribute value")

// ErrInvalidAttributeOperator distinguishes non-CSS extensions from unsupported syntax.
var ErrInvalidAttributeOperator = errors.New("cascadia: invalid attribute operator")

var ErrInvalidSelector = errors.New("cascadia: invalid selector")

func selectorObject[T Sel](memory *resourceguard.Memory, value T) Sel {
	out := resourceguard.Box(memory, value)

	return out.(Sel)
}
func selectorSlice[T any](memory *resourceguard.Memory, length, capacity int) []T {
	out := resourceguard.MakeSlice[T](memory, length, capacity)

	return out
}
func selectorAppend[T any](memory *resourceguard.Memory, s []T, value T) []T {
	out := resourceguard.Append(memory, s, nil, value)

	return out
}

// MatchControl carries cooperative cancellation across successive selector
// matches so the caller's CPU-time check is sampled periodically across the
// complete cascade rather than once for every selector.
type MatchControl struct {
	sampler    resourceguard.StopSampler
	shouldStop func()
}

func NewMatchControl(shouldStop func()) *MatchControl {
	g := NewMatchControlWithMemory(shouldStop, nil)
	return g
}

// step samples the caller's relatively expensive CPU-time callback rather
// than invoking it for every simple selector operation.
func (g *MatchControl) step() {
	if g != nil {
		g.sampler.Check()
	}
}

// checkNow samples the caller at an operation checkpoint or within a long scan.
func (g *MatchControl) checkNow() {
	if g != nil && g.shouldStop != nil {
		g.shouldStop()
	}
}

// Match reports whether m matches n. Resource termination unwinds to the caller.
func (g *MatchControl) Match(m Matcher, n *html.Node) bool { return matchResource(m, n, g) }

type resourceMatcher interface {
	matchResource(*html.Node, *MatchControl) bool
}

func matchResource(m Matcher, n *html.Node, guard *MatchControl) bool {
	guard.step()

	if matcher, ok := m.(resourceMatcher); ok {
		return matcher.matchResource(n, guard)
	}

	return m.Match(n)
}

// MatchWithStop matches n while periodically invoking shouldStop from inside
// selector-controlled loops. Resource termination bypasses the match result.
func MatchWithStop(m Matcher, n *html.Node, shouldStop func()) bool {
	return NewMatchControl(shouldStop).Match(m, n)
}

// NewMatchControlWithMemory admits the state retained across selector matches.
func NewMatchControlWithMemory(stop func(), m *resourceguard.Memory) *MatchControl {
	return resourceguard.New(m, MatchControl{shouldStop: stop, sampler: resourceguard.NewStopSampler(256, stop)})
}
