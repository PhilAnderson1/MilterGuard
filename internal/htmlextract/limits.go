package htmlextract

import "fmt"

type Limits struct {
	InputBytes         int
	Nodes              int
	TextNodes          int
	Attributes         int
	Depth              int
	Rules              int
	Selectors          int
	SelectorBytes      int
	CSSBytes           int
	CSSConstructBytes  int
	CSSConstructTokens int
	MatchWork          int64
	MediaCases         int
	ExpressionWork     int64
}

// MaxViewingCases is the hard ceiling for conditional evaluations per document.
const MaxViewingCases = 16

// Selector cost functions use MatchWork+1 as a saturated over-budget value.
// Keep that sentinel representable for every accepted caller-supplied limit.
const maxMatchWork = int64(1<<63 - 2)

func DefaultLimits() Limits {
	return Limits{InputBytes: 8 << 20, Nodes: 100000, TextNodes: 50000, Attributes: 50000, Depth: 128, Rules: 10000, Selectors: 20000, SelectorBytes: 2048, CSSBytes: 512 << 10, CSSConstructBytes: maxValueBytes, CSSConstructTokens: maxValueTokens, MatchWork: 10000000, MediaCases: MaxViewingCases, ExpressionWork: 1000000}
}

func (l Limits) validate() error {
	for _, limit := range []struct {
		name  string
		value int
	}{
		{"InputBytes", l.InputBytes},
		{"Nodes", l.Nodes},
		{"TextNodes", l.TextNodes},
		{"Attributes", l.Attributes},
		{"Depth", l.Depth},
		{"SelectorBytes", l.SelectorBytes},
		{"CSSBytes", l.CSSBytes},
		{"CSSConstructBytes", l.CSSConstructBytes},
		{"CSSConstructTokens", l.CSSConstructTokens},
		{"MediaCases", l.MediaCases},
	} {
		if limit.value <= 0 {
			return fmt.Errorf("invalid limit: %s must be positive", limit.name)
		}
	}
	for _, limit := range []struct {
		name  string
		value int
	}{
		{"Rules", l.Rules},
		{"Selectors", l.Selectors},
	} {
		if limit.value < 0 {
			return fmt.Errorf("invalid limit: %s must be non-negative", limit.name)
		}
	}
	for _, limit := range []struct {
		name  string
		value int64
	}{
		{"MatchWork", l.MatchWork},
		{"ExpressionWork", l.ExpressionWork},
	} {
		if limit.value <= 0 {
			return fmt.Errorf("invalid limit: %s must be positive", limit.name)
		}
	}
	if l.MatchWork > maxMatchWork {
		return fmt.Errorf("invalid limit: MatchWork must be at most %d", maxMatchWork)
	}
	return nil
}

// ResourceUsage records deterministic input-derived work performed while
// analysing one HTML document. Callers use it to carry remaining work across
// the HTML parts of one message; limits are still enforced inside Analyze.
type ResourceUsage struct {
	InputBytes                   int
	Nodes                        int
	TextNodes                    int
	Attributes                   int
	Depth                        int
	CSSDepth                     int
	Rules                        int
	Selectors                    int
	CSSBytes                     int
	MediaCases                   int
	MatchWork                    int64
	ExpressionWork               int64
	CSSLimitExceeded             bool
	MatchWorkExhausted           bool
	ExpressionWorkExhausted      bool
	ExpressionDepthLimitExceeded bool
	UnsupportedColourFunctions   int
}
