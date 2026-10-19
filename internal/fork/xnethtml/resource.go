package html

import (
	"bytes"
	"errors"
	"io"
	"strings"
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

// mergeText charges the complete replacement string, including allocator
// rounding exposed by Grow. Reconcile before copying so repeated merges cannot
// accumulate uncharged spare capacity.
func (g *resourceGuard) mergeText(left, right string) string {
	if right == "" {
		return left
	}
	if g == nil {
		return left + right
	}
	size := len(left) + len(right)
	var out strings.Builder
	g.initStringBuilder(&out, size)
	out.WriteString(left)
	out.WriteString(right)
	return out.String()
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

// initStringBuilder admits a fresh builder and reconciles allocator rounding
// before callers write into it. It must only be used with an empty builder.
func (g *resourceGuard) initStringBuilder(out *strings.Builder, size int) {
	g.reserve(int64(size))
	out.Grow(size)
	g.reserve(int64(out.Cap() - size))
}

// ownedString keeps empty and single-byte conversions allocation-free while
// accounting for the backing capacity of larger retained token strings.
func (g *resourceGuard) ownedString(data []byte) string {
	if g == nil {
		return string(data)
	}
	if len(data) <= 1 {
		g.reserve(int64(len(data)))
		return string(data)
	}
	var out strings.Builder
	g.initStringBuilder(&out, len(data))
	out.Write(data)
	return out.String()
}

// makeBytes exposes allocated capacity through Buffer, avoiding assumptions
// about Go's size classes. Reconciliation can abort before the buffer is used.
func (g *resourceGuard) makeBytes(size int) []byte {
	if g == nil {
		return make([]byte, size)
	}
	g.reserve(int64(size))
	var out bytes.Buffer
	out.Grow(size)
	g.reserve(int64(out.Cap() - size))
	return out.Bytes()[:size]
}

func (g *resourceGuard) copyBytes(data []byte) []byte {
	g.reserve(int64(len(data)))
	out := bytes.Clone(data)
	g.reserve(int64(cap(out) - len(data)))
	return out
}
