package html

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// ErrResourceStopped is returned when ResourceLimits.ShouldStop asks the
// tokenizer or tree builder to stop processing the current document.
var ErrResourceStopped = errors.New("html: resource processing stopped")

// ResourceLimits stops parsing when the shared allocation budget or external
// CPU guard is exhausted.
type ResourceLimits struct {
	ShouldStop func() bool
	Memory     *resourceguard.Memory
}

// ResourceLimitError identifies the parser resource that exceeded its limit.
type ResourceLimitError struct {
	Resource string
	Limit    int64
}

func (e *ResourceLimitError) Error() string {
	return fmt.Sprintf("html: resource limit: %s > %d", e.Resource, e.Limit)
}

type resourceAbort struct{ err error }

type resourceGuard struct {
	limits                     ResourceLimits
	bytes                      uint64
	oeCap, afeCap, templateCap int
}

func (g *resourceGuard) reserve(bytes int64) {
	if g != nil && g.limits.Memory != nil && !g.limits.Memory.Reserve(bytes) {
		panic(resourceAbort{&ResourceLimitError{"memory bytes", g.limits.Memory.Limit()}})
	}
}

func (g *resourceGuard) stop() {
	if g != nil && g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		panic(resourceAbort{ErrResourceStopped})
	}
}

func (g *resourceGuard) readByte() (err error) {
	if g == nil {
		return nil
	}
	if g.limits.Memory != nil && g.limits.Memory.Exhausted() {
		return &ResourceLimitError{"memory bytes", g.limits.Memory.Limit()}
	}
	g.bytes++
	if g.bytes&1023 == 0 && g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		return ErrResourceStopped
	}
	return nil
}

func (g *resourceGuard) node(n Node) {
	if g == nil {
		return
	}
	g.reserve(int64(unsafe.Sizeof(Node{})) + int64(len(n.Data)+len(n.Namespace)))
}

func (g *resourceGuard) attributes(n int) (err error) {
	if g == nil || n == 0 {
		return nil
	}
	g.reserve(int64(n) * int64(unsafe.Sizeof(Attribute{})))
	return nil
}

func (g *resourceGuard) tokenizerAttribute(keyBytes, valueBytes int) (err error) {
	if g == nil {
		return nil
	}
	// In addition to the retained key and value strings, each source attribute
	// grows the tokenizer's span slice, its name-deduplication map, or the
	// token's Attribute slice. Charge duplicate attributes too: their temporary
	// key allocations still contribute to the monotonic allocation budget.
	const structuralBytes = 64
	g.reserve(int64(keyBytes) + int64(valueBytes) + structuralBytes)
	return nil
}

func (g *resourceGuard) mustAttributes(n int) {
	if err := g.attributes(n); err != nil {
		panic(resourceAbort{err})
	}
}

func (g *resourceGuard) stacks(p *parser) {
	if g == nil {
		return
	}
	g.stop()
	if cap(p.oe) > g.oeCap {
		g.reserve(int64(cap(p.oe)-g.oeCap) * int64(unsafe.Sizeof((*Node)(nil))))
		g.oeCap = cap(p.oe)
	}
	if cap(p.afe) > g.afeCap {
		g.reserve(int64(cap(p.afe)-g.afeCap) * int64(unsafe.Sizeof((*Node)(nil))))
		g.afeCap = cap(p.afe)
	}
	if cap(p.templateStack) > g.templateCap {
		g.reserve(int64(cap(p.templateStack)-g.templateCap) * int64(unsafe.Sizeof(insertionMode(nil))))
		g.templateCap = cap(p.templateStack)
	}
}

func (g *resourceGuard) openElement(p *parser, next *Node) {
	// Stack growth is charged by stacks. This hook remains at the construction
	// point so upstream tree-builder changes cannot bypass the guard.
	if g != nil {
		g.stop()
	}
}

func (g *resourceGuard) textMerge(oldBytes, addedBytes int) {
	if g == nil || addedBytes == 0 {
		return
	}
	g.reserve(int64(oldBytes + addedBytes))
}

// ParseOptionResourceLimits installs direct tokenizer and tree-builder limits.
// If usage is non-nil it is updated as parsing proceeds, including on error.
func ParseOptionResourceLimits(limits ResourceLimits) ParseOption {
	return func(p *parser) {
		p.guard = &resourceGuard{limits: limits}
		if limits.Memory != nil {
			limits.Memory.Reserve(int64(cap(p.tokenizer.buf)))
		}
		p.tokenizer.guard = p.guard
	}
}
