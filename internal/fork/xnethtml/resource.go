package html

import (
	"errors"
	"io"
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

// NewTokenizerWithLimits applies shared allocation accounting and cooperative
// cancellation to a standalone tokenizer. Admission failures are reported by
// Next and Err, including failure to admit the initial buffer.
func NewTokenizerWithLimits(r io.Reader, limits ResourceLimits) *Tokenizer {
	const initialBytes = 4096 + int64(unsafe.Sizeof(Tokenizer{})) + int64(unsafe.Sizeof(resourceGuard{}))
	if !limits.Memory.Reserve(initialBytes) {
		return &Tokenizer{err: &ResourceLimitError{"memory bytes", limits.Memory.Limit()}}
	}
	z := NewTokenizer(r)
	z.guard = &resourceGuard{limits: limits}
	return z
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
}

func (g *resourceGuard) reserve(bytes int64) {
	if g != nil && g.limits.Memory != nil && !g.limits.Memory.Reserve(bytes) {
		panic(resourceAbort{&ResourceLimitError{"memory bytes", g.limits.Memory.Limit()}})
	}
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
	if g.limits.ShouldStop != nil && g.limits.ShouldStop() {
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

func (g *resourceGuard) node() {
	if g == nil {
		return
	}
	g.reserve(int64(unsafe.Sizeof(Node{})))
}

// Map allowances cover buckets, growth and allocator rounding; source key
// copies are charged separately. The entry allowance includes old bucket
// arrays replaced during growth, not just the final retained table. Cleared
// tokenizer maps retain their allowance.
const attributeMapBaseBytes int64 = 256
const attributeMapEntryBytes int64 = 128

func (g *resourceGuard) mustAttributes(n int) {
	g.reserve(int64(n) * int64(unsafe.Sizeof(Attribute{})))
}

// growResourceSlice reserves the entire new array before allocation. Old arrays
// remain charged: the budget measures monotonic allocation, not live storage.
func growResourceSlice[T any](s []T, extra int, g *resourceGuard) []T {
	if len(s)+extra <= cap(s) {
		return s
	}
	capacity := max(len(s)+extra, max(1, cap(s)*2))
	var value T
	g.reserve(int64(capacity) * int64(unsafe.Sizeof(value)))
	grown := make([]T, len(s), capacity)
	copy(grown, s)
	return grown
}

func (g *resourceGuard) textMerge(oldBytes, addedBytes int) {
	if g == nil || addedBytes == 0 {
		return
	}
	g.reserve(int64(oldBytes + addedBytes))
}

// ParseOptionResourceLimits installs direct tokenizer and tree-builder limits.
func ParseOptionResourceLimits(limits ResourceLimits) ParseOption {
	return func(p *parser) {
		p.guard = &resourceGuard{limits: limits}
		if limits.Memory != nil {
			p.guard.reserve(int64(cap(p.tokenizer.buf)))
		}
		p.tokenizer.guard = p.guard
	}
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
	if g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		panic(resourceAbort{ErrResourceStopped})
	}
}
