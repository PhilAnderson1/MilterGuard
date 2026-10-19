package css

import (
	"errors"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// ErrResourceStopped is returned when ResourceLimits.ShouldStop asks the CSS
// tokenizer or parser to stop processing the current input.
var ErrResourceStopped = errors.New("css: resource processing stopped")

// ErrUnsafeDelimiter reports an unmatched closing parenthesis or bracket that
// would otherwise corrupt the parser's recovery depth.
var ErrUnsafeDelimiter = errors.New("css: unsafe unmatched delimiter")

// ResourceLimits stops parsing when the shared allocation budget or external
// CPU guard is exhausted.
type ResourceLimits struct {
	ShouldStop func() bool
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

type resourceAbort struct{}

type resourceGuard struct {
	limits ResourceLimits
	steps  uint32
}

func (g *resourceGuard) memory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.limits.Memory
}
func (g *resourceGuard) allocationError() error {
	return &ResourceLimitError{"memory bytes", int(g.memory().Limit())}
}
func newResourceGuard(limits ResourceLimits) *resourceGuard {
	g, ok := resourceguard.New(limits.Memory, resourceGuard{limits: limits})
	if !ok {
		return &resourceGuard{limits: limits}
	}
	return g
}
func (p *Parser) checkpoint() bool { p.checkWork(); return false }
func (p *Parser) requireStorage(ok bool) {
	if !ok {
		p.abort(p.guard.allocationError())
	}
}

func (g *resourceGuard) step() error {
	if g == nil {
		return nil
	}
	g.steps++
	if g.limits.ShouldStop != nil && (g.steps == 1 || g.steps&255 == 0) && g.limits.ShouldStop() {
		return ErrResourceStopped
	}
	if g.limits.Memory.Exhausted() {
		return &ResourceLimitError{"memory bytes", int(g.limits.Memory.Limit())}
	}
	return nil
}

// Storage is charged only when it is allocated, including complete replacement
// arrays. Borrowed tokens and reuse of existing buffers do not allocate.
func growParserSlice[T any](slice []T, additional int, p *Parser) []T {
	grown, ok := resourceguard.GrowSliceFrom(p.guard.memory(), slice, additional, 4, p.checkpoint)
	p.requireStorage(ok)
	return grown
}

func (g *resourceGuard) check() error {
	if g == nil {
		return nil
	}
	if g.limits.Memory.Exhausted() {
		return &ResourceLimitError{"memory bytes", int(g.limits.Memory.Limit())}
	}
	if g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		return ErrResourceStopped
	}
	return nil
}
func (p *Parser) checkWork() {
	if err := p.guard.check(); err != nil {
		p.abort(err)
	}
}
func (p *Parser) lowerCopy(data []byte) []byte {
	// Own the copy here; chunking bounds both copying and casing work.
	out, ok := resourceguard.MakeSlice[byte](p.guard.memory(), len(data), len(data))
	p.requireStorage(ok)
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
