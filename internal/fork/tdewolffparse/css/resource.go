package css

import (
	"errors"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// ErrUnsafeDelimiter reports an unmatched closing parenthesis or bracket that
// would otherwise corrupt the parser's recovery depth.
var ErrUnsafeDelimiter = errors.New("css: unsafe unmatched delimiter")

// ResourceLimits stops parsing when the shared allocation budget or external
// CPU guard is exhausted.
type ResourceLimits struct {
	ShouldStop func()
	Memory     *resourceguard.Memory
}

// ResourceLimitError identifies the parser resource that exceeded its limit.
type ResourceLimitError struct {
	Resource string
	Limit    int
}

func (e *ResourceLimitError) Error() string {
	return "css: resource limit exceeded"
}

// resourceAbort carries structural limits and unsafe syntax only. Shared CPU,
// memory and cancellation signals pass through the parser unchanged.
type resourceAbort struct{}

type resourceGuard struct {
	sampler resourceguard.StopSampler
	limits  ResourceLimits
}

func (g *resourceGuard) memory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.limits.Memory
}

func newResourceGuard(limits ResourceLimits) *resourceGuard {
	g := resourceguard.New(limits.Memory, resourceGuard{limits: limits, sampler: resourceguard.NewStopSampler(256, limits.ShouldStop)})

	return g
}
func (p *Parser) checkpoint() { p.checkWork() }

func (g *resourceGuard) step() {
	if g != nil {
		g.sampler.Check()
	}
}

// Storage is charged only when it is allocated, including complete replacement
// arrays. Borrowed tokens and reuse of existing buffers do not allocate.
func growParserSlice[T any](slice []T, additional int, p *Parser) []T {
	grown := resourceguard.GrowSliceFrom(p.guard.memory(), slice, additional, 4, p.checkpoint)

	return grown
}

func (g *resourceGuard) check() {
	if g != nil && g.limits.ShouldStop != nil {
		g.limits.ShouldStop()
	}
}
func (p *Parser) checkWork() { p.guard.check() }
func (p *Parser) lowerCopy(data []byte) []byte {
	// Own the copy here; chunking bounds both copying and casing work.
	out := resourceguard.MakeSlice[byte](p.guard.memory(), len(data), len(data))

	for start := 0; start < len(data); start += 1024 {
		if start > 0 {
			p.checkWork()
		}
		end := min(start+1024, len(data))
		copy(out[start:end], data[start:end])
		for i := start; i < end; i++ {
			if 'A' <= out[i] && out[i] <= 'Z' {
				out[i] += 'a' - 'A'
			}
		}
	}
	return out
}
