package css

import (
	"errors"
	"fmt"
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
	return fmt.Sprintf("css: resource limit: %s > %d", e.Resource, e.Limit)
}

type resourceAbort struct{}

type resourceGuard struct {
	limits   ResourceLimits
	stateCap int
	steps    uint32
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

func (g *resourceGuard) token(data []byte) error {
	if g == nil {
		return nil
	}
	g.steps++
	if g.limits.ShouldStop != nil && (g.steps == 1 || g.steps&255 == 0) && g.limits.ShouldStop() {
		return ErrResourceStopped
	}
	if err := g.reserve(int64(unsafe.Sizeof(Token{})) + int64(len(data))); err != nil {
		return err
	}
	return nil
}

func (g *resourceGuard) states(capacity int) error {
	if g == nil || capacity <= g.stateCap {
		return nil
	}
	err := g.reserve(int64(capacity-g.stateCap) * int64(unsafe.Sizeof(State(nil))))
	g.stateCap = capacity
	return err
}
