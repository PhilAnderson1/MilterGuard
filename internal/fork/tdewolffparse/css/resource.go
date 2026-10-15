package css

import (
	"errors"
	"fmt"
)

// ErrResourceStopped is returned when ResourceLimits.ShouldStop asks the CSS
// tokenizer or parser to stop processing the current input.
var ErrResourceStopped = errors.New("css: resource processing stopped")

// ErrUnsafeDelimiter reports an unmatched closing parenthesis or bracket that
// would otherwise corrupt the parser's recovery depth.
var ErrUnsafeDelimiter = errors.New("css: unsafe unmatched delimiter")

// ResourceLimits bounds one construct accumulated by the parser and its
// parser-controlled stacks. Zero values leave that resource unlimited.
type ResourceLimits struct {
	ConstructBytes  int
	ConstructTokens int
	Depth           int
	ShouldStop      func() bool
}

// ResourceUsage reports the largest construct and stack depth encountered.
type ResourceUsage struct {
	ConstructBytes  int
	ConstructTokens int
	Depth           int
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
	limits ResourceLimits
	usage  *ResourceUsage
	bytes  int
	tokens int
}

func newResourceGuard(limits ResourceLimits, usage *ResourceUsage) *resourceGuard {
	if usage != nil {
		*usage = ResourceUsage{}
	}
	return &resourceGuard{limits: limits, usage: usage}
}

func (g *resourceGuard) resetConstruct() {
	if g == nil {
		return
	}
	g.bytes = 0
	g.tokens = 0
}

func (g *resourceGuard) token(data []byte) error {
	if g == nil {
		return nil
	}
	g.bytes += len(data)
	g.tokens++
	if g.usage != nil {
		if g.bytes > g.usage.ConstructBytes {
			g.usage.ConstructBytes = g.bytes
		}
		if g.tokens > g.usage.ConstructTokens {
			g.usage.ConstructTokens = g.tokens
		}
	}
	if g.limits.ConstructBytes > 0 && g.bytes > g.limits.ConstructBytes {
		return &ResourceLimitError{"construct bytes", g.limits.ConstructBytes}
	}
	if g.limits.ConstructTokens > 0 && g.tokens > g.limits.ConstructTokens {
		return &ResourceLimitError{"construct tokens", g.limits.ConstructTokens}
	}
	return nil
}

func (g *resourceGuard) depth(depth int) error {
	if g == nil {
		return nil
	}
	if g.usage != nil && depth > g.usage.Depth {
		g.usage.Depth = depth
	}
	if g.limits.Depth > 0 && depth > g.limits.Depth {
		return &ResourceLimitError{"depth", g.limits.Depth}
	}
	return nil
}
