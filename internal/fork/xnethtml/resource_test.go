package html

import (
	"errors"
	"strings"
	"testing"
)

func parseWithResources(source string, limits ResourceLimits) (ResourceUsage, error) {
	var usage ResourceUsage
	_, err := ParseWithOptions(strings.NewReader(source), ParseOptionResourceLimits(limits, &usage))
	return usage, err
}

func requireResource(t *testing.T, err error, resource string) {
	t.Helper()
	var limitErr *ResourceLimitError
	if !errors.As(err, &limitErr) || limitErr.Resource != resource {
		t.Fatalf("error = %v, want %q resource limit", err, resource)
	}
}

func TestResourceLimitsBoundTokenizerAttributes(t *testing.T) {
	usage, err := parseWithResources(`<p a b c d e f>text`, ResourceLimits{Attributes: 5})
	requireResource(t, err, "attributes")
	if usage.Attributes != 6 {
		t.Fatalf("attributes = %d, want 6 at rejection", usage.Attributes)
	}
}

func TestResourceLimitsBoundTreeAllocations(t *testing.T) {
	t.Run("nodes", func(t *testing.T) {
		usage, err := parseWithResources(`<p>one</p><p>two</p>`, ResourceLimits{Nodes: 5})
		requireResource(t, err, "nodes")
		if usage.Nodes != 6 {
			t.Fatalf("nodes = %d, want 6 at rejection", usage.Nodes)
		}
	})
	t.Run("text nodes", func(t *testing.T) {
		usage, err := parseWithResources(`one<p>two</p>three`, ResourceLimits{TextNodes: 2})
		requireResource(t, err, "text nodes")
		if usage.TextNodes != 3 {
			t.Fatalf("text nodes = %d, want 3 at rejection", usage.TextNodes)
		}
	})
	t.Run("nodes synthesized from end tags", func(t *testing.T) {
		_, err := parseWithResources(strings.Repeat(`</br>`, 10), ResourceLimits{Nodes: 5})
		requireResource(t, err, "nodes")
	})
	t.Run("attributes copied by formatting recovery", func(t *testing.T) {
		// The source contains one attribute. Reconstructing the active <b>
		// element for the second paragraph copies it onto a parser clone.
		_, err := parseWithResources(`<p><b class=x>one</p><p>two`, ResourceLimits{Attributes: 1})
		requireResource(t, err, "attributes")
	})
}

func TestResourceLimitsBoundDepthInsideTreeBuilder(t *testing.T) {
	const depth = 8
	if _, err := parseWithResources(strings.Repeat(`<div>`, depth), ResourceLimits{Depth: depth}); err != nil {
		t.Fatalf("boundary nesting rejected: %v", err)
	}
	_, err := parseWithResources(strings.Repeat(`<div>`, depth+1), ResourceLimits{Depth: depth})
	requireResource(t, err, "source depth")

	// Implied tbody/tr nodes are admitted only in proportion to actual tables
	// on the parser stack.
	if _, err := parseWithResources(strings.Repeat(`<table><td>`, depth/2), ResourceLimits{Depth: depth}); err != nil {
		t.Fatalf("bounded table recovery rejected: %v", err)
	}
}

func TestResourceLimitsBoundRepeatedTextCopies(t *testing.T) {
	_, err := parseWithResources(`abcdefghij`+strings.Repeat(`</div>abcdefghij`, 20), ResourceLimits{TextMergeCopyBytes: 100})
	requireResource(t, err, "text merge copy bytes")
}

func TestResourceLimitsStopDuringLargeToken(t *testing.T) {
	checks := 0
	_, err := parseWithResources(`<!--`+strings.Repeat("x", 5000)+`-->`, ResourceLimits{
		ShouldStop: func() bool {
			checks++
			return checks >= 2
		},
	})
	if !errors.Is(err, ErrResourceStopped) {
		t.Fatalf("error = %v, want cooperative stop", err)
	}
	if checks < 2 {
		t.Fatalf("stop checks = %d, want at least 2", checks)
	}
}

func TestResourceLimitsApplyToFragments(t *testing.T) {
	var usage ResourceUsage
	_, err := ParseFragmentWithOptions(strings.NewReader(`<b a b c>`), nil,
		ParseOptionResourceLimits(ResourceLimits{Attributes: 2}, &usage),
	)
	requireResource(t, err, "attributes")
}
