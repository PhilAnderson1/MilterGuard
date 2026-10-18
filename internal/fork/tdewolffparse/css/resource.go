package css

import (
	"errors"
	"unsafe"

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

func (g *resourceGuard) reserve(bytes int64) error {
	if g != nil && g.limits.Memory != nil && !g.limits.Memory.Reserve(bytes) {
		return &ResourceLimitError{"memory bytes", int(g.limits.Memory.Limit())}
	}
	return nil
}

func newResourceGuard(limits ResourceLimits) *resourceGuard {
	return &resourceGuard{limits: limits}
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
	if len(slice)+additional <= cap(slice) {
		return slice
	}
	capacity := max(len(slice)+additional, max(4, cap(slice)*2))
	var value T
	if err := p.guard.reserve(int64(capacity) * int64(unsafe.Sizeof(value))); err != nil {
		p.abort(err)
	}
	grown := make([]T, len(slice), capacity)
	copy(grown, slice)
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
	// The caller admits the copy; chunking bounds both copying and casing work.
	out := make([]byte, len(data))
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
