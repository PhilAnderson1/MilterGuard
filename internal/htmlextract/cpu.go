package htmlextract

import "github.com/PhilAnderson1/MilterGuard/internal/resourceguard"

// cpuGuard samples owned loops. Fork loops invoke checkpoint directly because
// they already control their own sampling interval.
type cpuGuard struct {
	sampler    resourceguard.StopSampler
	shouldStop func()
	memory     *resourceguard.Memory
}

func (g *cpuGuard) check() {
	if g != nil {
		g.sampler.Check()
	}
}
func (g *cpuGuard) checkpoint() {
	if g != nil && g.shouldStop != nil {
		g.shouldStop()
	}
}
func (s *sheet) resourceBudget() *cpuGuard {
	if s.cpu == nil {
		s.cpu = resourceguard.New(s.memory, cpuGuard{memory: s.memory, shouldStop: s.shouldStop, sampler: resourceguard.NewStopSampler(256, s.shouldStop)})
	}
	return s.cpu
}
func stopCPU(g *cpuGuard) { g.checkpoint() }
