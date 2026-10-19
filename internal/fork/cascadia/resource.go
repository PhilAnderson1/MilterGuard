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

var errSelectorMemory = errors.New("cascadia: memory limit exceeded")

type allocationAbort struct{}

func requireSelectorStorage(ok bool) {
	if !ok {
		panic(allocationAbort{})
	}
}
func selectorObject[T Sel](memory *resourceguard.Memory, value T) Sel {
	out, ok := resourceguard.Box(memory, value)
	requireSelectorStorage(ok)
	return out.(Sel)
}
func selectorSlice[T any](memory *resourceguard.Memory, length, capacity int) []T {
	out, ok := resourceguard.MakeSlice[T](memory, length, capacity)
	requireSelectorStorage(ok)
	return out
}
func selectorAppend[T any](memory *resourceguard.Memory, s []T, value T) []T {
	out, ok := resourceguard.Append(memory, s, nil, value)
	requireSelectorStorage(ok)
	return out
}

// Only allocation aborts are recovered; programming errors remain visible.
func recoverAllocation(err *error) {
	if value := recover(); value != nil {
		if _, ok := value.(allocationAbort); !ok {
			panic(value)
		}
		*err = errSelectorMemory
	}
}

// MatchControl carries cooperative cancellation across successive selector
// matches so the caller's CPU-time check is sampled periodically across the
// complete cascade rather than once for every selector.
type MatchControl struct {
	shouldStop func() bool
	steps      uint32
	stopped    bool
}

func NewMatchControl(shouldStop func() bool) *MatchControl {
	g, _ := NewMatchControlWithMemory(shouldStop, nil)
	return g
}

// step samples the caller's relatively expensive CPU-time callback rather
// than invoking it for every simple selector operation.
func (g *MatchControl) step() bool {
	if g == nil || g.stopped {
		return g != nil && g.stopped
	}
	g.steps++
	if g.steps == 1 || g.steps&255 == 0 {
		return g.checkNow()
	}
	return false
}

// checkNow samples the caller at an operation checkpoint or within a long scan.
func (g *MatchControl) checkNow() bool {
	if g == nil || g.stopped {
		return g != nil && g.stopped
	}
	g.stopped = g.shouldStop != nil && g.shouldStop()
	return g.stopped
}

// Match evaluates m and reports whether cooperative cancellation stopped the
// operation. Once stopped, the control remains stopped for later calls.
func (g *MatchControl) Match(m Matcher, n *html.Node) (matched, stopped bool) {
	matched = matchResource(m, n, g)
	return matched && !g.stopped, g.stopped
}

type resourceMatcher interface {
	matchResource(*html.Node, *MatchControl) bool
}

func matchResource(m Matcher, n *html.Node, guard *MatchControl) bool {
	if guard.step() {
		return false
	}
	if matcher, ok := m.(resourceMatcher); ok {
		return matcher.matchResource(n, guard)
	}
	return m.Match(n)
}

// MatchWithStop matches n while periodically invoking shouldStop from inside
// selector-controlled loops. stopped distinguishes cancellation from an
// ordinary non-match.
func MatchWithStop(m Matcher, n *html.Node, shouldStop func() bool) (matched, stopped bool) {
	return NewMatchControl(shouldStop).Match(m, n)
}

// NewMatchControlWithMemory admits the state retained across selector matches.
func NewMatchControlWithMemory(stop func() bool, m *resourceguard.Memory) (*MatchControl, bool) {
	return resourceguard.New(m, MatchControl{shouldStop: stop})
}
