package htmlextract

import "fmt"

type Limits struct {
	InputBytes  int
	CSSBytes    int
	MemoryBytes int64
}

func DefaultLimits() Limits {
	return Limits{InputBytes: 8 << 20, CSSBytes: 512 << 10, MemoryBytes: 64 << 20}
}

func (l Limits) validate() error {
	for _, limit := range []struct {
		name  string
		value int
	}{
		{"InputBytes", l.InputBytes},
		{"CSSBytes", l.CSSBytes},
	} {
		if limit.value <= 0 {
			return fmt.Errorf("invalid limit: %s must be positive", limit.name)
		}
	}
	if l.MemoryBytes <= 0 {
		return fmt.Errorf("invalid limit: MemoryBytes must be positive")
	}
	return nil
}

// ResourceUsage records bounded resources consumed by a returned HTML
// document. CSSLimitExceeded means the shared stylesheet cascade was abandoned
// after a CSS resource limit or parser-recovery failure. A malformed inline
// style can instead remain locally unresolved without setting that flag.
type ResourceUsage struct {
	InputBytes                 int
	CSSBytes                   int
	MemoryBytes                int64
	CSSLimitExceeded           bool
	UnsupportedColourFunctions int
}

// AnalysisUsage is published by controlled analysis even when resource
// termination means there is no Document to return. MemoryLimitExceeded records
// a failed allocation reservation, not merely using exactly the allowance.
type AnalysisUsage struct {
	ResourceUsage
	MemoryLimitExceeded bool
}
