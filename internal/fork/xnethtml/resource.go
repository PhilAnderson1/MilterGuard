package html

import (
	"errors"
	"fmt"
)

// ErrResourceStopped is returned when ResourceLimits.ShouldStop asks the
// tokenizer or tree builder to stop processing the current document.
var ErrResourceStopped = errors.New("html: resource processing stopped")

// ResourceLimits bounds allocations and recovery work performed inside the
// tokenizer and tree builder. Zero values leave the corresponding resource
// unlimited.
type ResourceLimits struct {
	Nodes              int
	TextNodes          int
	Attributes         int
	Depth              int
	TextMergeCopyBytes int64
	ShouldStop         func() bool
}

// ResourceUsage reports parser allocations and the deepest open-element
// stack reached while parsing.
type ResourceUsage struct {
	Nodes              int
	TextNodes          int
	Attributes         int
	Depth              int
	TextMergeCopyBytes int64
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
	limits ResourceLimits
	usage  *ResourceUsage
	bytes  uint64
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
	g.bytes++
	if g.bytes&1023 == 0 && g.limits.ShouldStop != nil && g.limits.ShouldStop() {
		return ErrResourceStopped
	}
	return nil
}

func (g *resourceGuard) node(nodeType NodeType) {
	if g == nil {
		return
	}
	g.usage.Nodes++
	if g.limits.Nodes > 0 && g.usage.Nodes > g.limits.Nodes {
		panic(resourceAbort{&ResourceLimitError{"nodes", int64(g.limits.Nodes)}})
	}
	if nodeType == TextNode {
		g.usage.TextNodes++
		if g.limits.TextNodes > 0 && g.usage.TextNodes > g.limits.TextNodes {
			panic(resourceAbort{&ResourceLimitError{"text nodes", int64(g.limits.TextNodes)}})
		}
	}
}

func (g *resourceGuard) attributes(n int) (err error) {
	if g == nil || n == 0 {
		return nil
	}
	g.usage.Attributes += n
	if g.limits.Attributes > 0 && g.usage.Attributes > g.limits.Attributes {
		return &ResourceLimitError{"attributes", int64(g.limits.Attributes)}
	}
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
	depth := len(p.oe)
	if depth > g.usage.Depth {
		g.usage.Depth = depth
	}
	if g.limits.Depth > 0 && (len(p.afe) > g.limits.Depth || len(p.templateStack) > g.limits.Depth) {
		panic(resourceAbort{&ResourceLimitError{"parser stack depth", int64(g.limits.Depth)}})
	}
}

func (g *resourceGuard) openElement(p *parser, next *Node) {
	if g == nil || g.limits.Depth <= 0 || next.parserImplied {
		return
	}
	sourceDepth := 1
	for _, n := range p.oe {
		if n.Type == ElementNode && !n.parserImplied {
			sourceDepth++
		}
	}
	if sourceDepth > g.limits.Depth {
		panic(resourceAbort{&ResourceLimitError{"source depth", int64(g.limits.Depth)}})
	}
}

func (g *resourceGuard) textMerge(oldBytes int) {
	if g == nil || oldBytes == 0 {
		return
	}
	g.usage.TextMergeCopyBytes += int64(oldBytes)
	if g.limits.TextMergeCopyBytes > 0 && g.usage.TextMergeCopyBytes > g.limits.TextMergeCopyBytes {
		panic(resourceAbort{&ResourceLimitError{"text merge copy bytes", g.limits.TextMergeCopyBytes}})
	}
}

// ParseOptionResourceLimits installs direct tokenizer and tree-builder limits.
// If usage is non-nil it is updated as parsing proceeds, including on error.
func ParseOptionResourceLimits(limits ResourceLimits, usage *ResourceUsage) ParseOption {
	return func(p *parser) {
		if usage == nil {
			usage = &ResourceUsage{}
		} else {
			*usage = ResourceUsage{}
		}
		p.guard = &resourceGuard{limits: limits, usage: usage}
		p.tokenizer.guard = p.guard
	}
}
