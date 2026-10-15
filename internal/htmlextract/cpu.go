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
	if g.stopped {
		return false
	}
	if g.memory != nil && g.memory.Exhausted() {
		return false
	}
	g.steps++
	if g.steps == 1 || g.steps&255 == 0 {
		g.stopped = g.shouldStop != nil && g.shouldStop()
	}
	return !g.stopped
}

func (g *cpuGuard) reserve(bytes int64) bool {
	return g == nil || g.memory == nil || g.memory.Reserve(bytes)
}
