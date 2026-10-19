package html

import (
	"errors"
	"io"
	"strings"

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

// NewTokenizerWithLimits applies shared allocation accounting and cooperative
// cancellation to a standalone tokenizer. Admission failures are reported by
// Next and Err, including failure to admit the initial buffer.
func NewTokenizerWithLimits(r io.Reader, limits ResourceLimits) *Tokenizer {

	g, ok := resourceguard.New(limits.Memory, resourceGuard{limits: limits})
	if !ok {
		return &Tokenizer{err: &ResourceLimitError{"memory bytes", limits.Memory.Limit()}}
	}
	return newTokenizer(r, "", g)
}

// ResourceLimitError identifies the parser resource that exceeded its limit.
type ResourceLimitError struct {
	Resource string
	Limit    int64
}

func (e *ResourceLimitError) Error() string {
	return "html: resource limit exceeded"
}

type resourceAbort struct{ err error }

type resourceGuard struct {
	limits     ResourceLimits
	bytes      uint64
	stopChecks uint32
	stopped    bool
}

func (g *resourceGuard) memory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.limits.Memory
}
func (g *resourceGuard) must(ok bool) {
	if !ok {
		panic(resourceAbort{&ResourceLimitError{"memory bytes", g.memory().Limit()}})
	}
}
func (g *resourceGuard) checkpoint() bool { g.check(); return false }

// The following helpers adapt the shared owners to this parser's private abort convention.
func newResourceNode(g *resourceGuard, value Node) *Node {
	n, ok := resourceguard.New(g.memory(), value)
	g.must(ok)
	return n
}
func makeResourceSlice[T any](length, capacity int, g *resourceGuard) []T {
	s, ok := resourceguard.MakeSlice[T](g.memory(), length, capacity)
	g.must(ok)
	return s
}

func (g *resourceGuard) stop() {
	if g == nil {
		return
	}
	if g.limits.Memory != nil && g.limits.Memory.Exhausted() {
		panic(resourceAbort{&ResourceLimitError{"memory bytes", g.limits.Memory.Limit()}})
	}
	g.stopChecks++
	if g.stopChecks != 1 && g.stopChecks&255 != 0 {
		return
	}
	if g.stopped || g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		g.stopped = true
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
	if g.stopped || g.bytes&1023 == 0 && g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		g.stopped = true
		return ErrResourceStopped
	}
	return nil
}

// growResourceSlice is only a failure-convention adapter; storage policy lives
// in resourceguard.
func growResourceSlice[T any](s []T, extra int, g *resourceGuard) []T {
	out, ok := resourceguard.GrowSlice(g.memory(), s, extra, g.checkpoint)
	g.must(ok)
	return out
}

// ParseOptionResourceLimits installs direct tokenizer and tree-builder limits.
func ParseOptionResourceLimits(limits ResourceLimits) ParseOption {
	return func(c *parseConfig) { c.limits = limits }
}

// check samples immediately inside a long byte scan. Operation-level callers
// use stop instead, so short tokens do not each incur a clock syscall.
func (g *resourceGuard) check() {
	if g == nil {
		return
	}
	if g.limits.Memory.Exhausted() {
		panic(resourceAbort{&ResourceLimitError{"memory bytes", g.limits.Memory.Limit()}})
	}
	if g.stopped || g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		g.stopped = true
		panic(resourceAbort{ErrResourceStopped})
	}
}

// initStringBuilder admits a fresh builder and reconciles allocator rounding
// before callers write into it. It must only be used with an empty builder.
func (g *resourceGuard) initStringBuilder(out *strings.Builder, size int) {
	g.must(resourceguard.GrowText(g.memory(), out, size, g.checkpoint))
}
func (g *resourceGuard) ownedString(data []byte) string {
	s, ok := resourceguard.CopyString(g.memory(), data, g.checkpoint)
	g.must(ok)
	return s
}
func (g *resourceGuard) makeBytes(size int) []byte {
	b, ok := resourceguard.MakeBytes(g.memory(), size)
	g.must(ok)
	return b
}
func (g *resourceGuard) copyBytes(data []byte) []byte {
	b, ok := resourceguard.CloneBytes(g.memory(), data, g.checkpoint)
	g.must(ok)
	return b
}
