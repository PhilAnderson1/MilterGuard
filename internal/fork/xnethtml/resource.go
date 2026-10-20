package html

import (
	"io"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// ResourceLimits stops parsing when the shared allocation budget or external
// CPU guard is exhausted.
type ResourceLimits struct {
	ShouldStop func()
	Memory     *resourceguard.Memory
}

// NewTokenizerWithLimits applies shared allocation accounting and cooperative
// cancellation to a standalone tokenizer. Resource refusal unwinds immediately,
// including during construction. Err reports ordinary tokenizer/I/O outcomes.
func NewTokenizerWithLimits(r io.Reader, limits ResourceLimits) *Tokenizer {
	g := resourceguard.New(limits.Memory, resourceGuard{limits: limits, sampler: resourceguard.NewStopSampler(256, limits.ShouldStop)})

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

// resourceAbort carries structural parser limits only, never CPU or memory refusal.
type resourceAbort struct{ err error }

type resourceGuard struct {
	sampler resourceguard.StopSampler
	limits  ResourceLimits
	bytes   uint64
}

func (g *resourceGuard) memory() *resourceguard.Memory {
	if g == nil {
		return nil
	}
	return g.limits.Memory
}

func (g *resourceGuard) checkpoint() { g.check() }

// These helpers supply the parser's ledger to shared storage owners.
func newResourceNode(g *resourceGuard, value Node) *Node {
	n := resourceguard.New(g.memory(), value)

	return n
}
func makeResourceSlice[T any](length, capacity int, g *resourceGuard) []T {
	s := resourceguard.MakeSlice[T](g.memory(), length, capacity)

	return s
}

func (g *resourceGuard) stop() {
	if g != nil {
		g.sampler.Check()
	}
}

func (g *resourceGuard) readByte() {
	if g != nil {
		g.bytes++
		if g.bytes&1023 == 0 {
			g.check()
		}
	}
}

// growResourceSlice supplies the parser ledger and checkpoint; storage policy lives
// in resourceguard.
func growResourceSlice[T any](s []T, extra int, g *resourceGuard) []T {
	out := resourceguard.GrowSlice(g.memory(), s, extra, g.checkpoint)

	return out
}

// ParseOptionResourceLimits installs direct tokenizer and tree-builder limits.
func ParseOptionResourceLimits(limits ResourceLimits) ParseOption {
	return func(c *parseConfig) { c.limits = limits }
}

// check samples immediately inside a long byte scan. Operation-level callers
// use stop instead, so short tokens do not each incur a clock syscall.
func (g *resourceGuard) check() {
	if g != nil && g.limits.ShouldStop != nil {
		g.limits.ShouldStop()
	}
}

// initStringBuilder admits a fresh builder and reconciles allocator rounding
// before callers write into it. It must only be used with an empty builder.
func (g *resourceGuard) initStringBuilder(out *strings.Builder, size int) {
	resourceguard.GrowText(g.memory(), out, size, g.checkpoint)
}
func (g *resourceGuard) ownedString(data []byte) string {
	s := resourceguard.CopyString(g.memory(), data, g.checkpoint)

	return s
}
func (g *resourceGuard) makeBytes(size int) []byte {
	b := resourceguard.MakeBytes(g.memory(), size)

	return b
}
func (g *resourceGuard) copyBytes(data []byte) []byte {
	b := resourceguard.CloneBytes(g.memory(), data, g.checkpoint)

	return b
}
