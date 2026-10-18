package cascadia

import "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"

// MatchControl carries cooperative cancellation across successive selector
// matches so the caller's CPU-time check is sampled periodically across the
// complete cascade rather than once for every selector.
type MatchControl struct {
	shouldStop func() bool
	steps      uint32
	stopped    bool
}

func NewMatchControl(shouldStop func() bool) *MatchControl {
	return &MatchControl{shouldStop: shouldStop}
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

// checkNow samples the caller immediately before an operation whose cost is
// proportional to attacker-controlled input rather than to one matching step.
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
	return matched, g.stopped
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
