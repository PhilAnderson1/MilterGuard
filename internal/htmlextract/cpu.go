package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/resourceguard"

// cpuGuard samples the extraction's thread-CPU callback from loops owned by
// htmlextract. Parser-library loops use the same callback through their own
// guards.
type cpuGuard struct {
	shouldStop func() bool
	steps      uint32
	stopped    bool
	memory     *resourceguard.Memory
}

func (g *cpuGuard) check() bool {
	if g == nil {
		return true
	}
	if g.stopNow(false) {
		return false
	}
	g.steps++
	return !g.stopNow(g.steps == 1 || g.steps&255 == 0)
}

// stopNow is used directly by forked loops that already provide their own
// sampling interval. sampleExternal controls whether this call reads the
// thread-CPU callback; exhausted memory and a previously observed stop are
// always reported immediately.
func (g *cpuGuard) stopNow(sampleExternal bool) bool {
	if g == nil {
		return false
	}
	if g.stopped || g.memory != nil && g.memory.Exhausted() {
		return true
	}
	if sampleExternal && g.shouldStop != nil && g.shouldStop() {
		g.stopped = true
	}
	return g.stopped
}

func (g *cpuGuard) reserve(bytes int64) bool {
	return g == nil || g.memory == nil || g.memory.Reserve(bytes)
}

func (s *sheet) resourceBudget() *cpuGuard {
	if s.cpu != nil {
		return s.cpu
	}
	return &cpuGuard{memory: s.memory, shouldStop: s.shouldStop}
}
