package htmlextract

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func TestInheritedColourDependencyThroughUnrelatedScopes(t *testing.T) {
	for _, middle := range []string{`--unrelated:1`, `--unrelated:var(--missing,1)`} {
		for _, alias := range []string{`--alias:var(--show)`, `--show:inherit;--alias:var(--show)`} {
			src := `<style>:root{--show:none}@media(prefers-color-scheme:dark){:root{--show:block}}</style><div style="` + middle + `"><p style="` + alias + `;display:var(--alias)">T</p></div>`
			if got := findText(t, inspectHTML(t, src), "T").Label; got != "unknown" {
				t.Fatalf("%s / %s: %s", middle, alias, got)
			}
		}
	}
	src := `<style>:root{--show:none}@media(prefers-color-scheme:dark){:root{--show:block}}</style><div style="--show:none"><p style="--alias:var(--show);display:var(--alias)">T</p></div>`
	if got := findText(t, inspectHTML(t, src), "T").Label; got != "concealed" {
		t.Fatal(got)
	}
}

func TestNestedMSOUniversalWrapperKeepsOuterUncertainty(t *testing.T) {
	src := `<!--[if !mso]><!--><div><!--[if mso]><!--><p>Inner</p><!--<![endif]--><p>T</p><style>#target{display:none}</style></div><!--<![endif]--><p id="target">Styled</p><p>After</p>`
	d := inspectHTML(t, src)
	for _, name := range []string{"Inner", "T", "Styled"} {
		if got := findText(t, d, name).Label; got != "unknown" {
			t.Fatalf("%s: %s", name, got)
		}
	}
	if got := findText(t, d, "After").Label; got != "visible" {
		t.Fatal(got)
	}
}

func TestASCIIFoldComparesEveryByte(t *testing.T) {
	for _, pair := range [][2]string{{"é", "ê"}, {"é", "é"}, {"\xc3\xff", "\xc3\xfe"}, {"Aé", "aé"}, {"Aé", "aê"}} {
		if equalASCIIFold(pair[0], pair[1]) != equalASCIIFoldBytes([]byte(pair[0]), pair[1]) {
			t.Fatalf("comparison differs for %q", pair)
		}
	}
}

func BenchmarkAuditMedia(b *testing.B) {
	for _, groups := range []int{4, 128} {
		b.Run(fmt.Sprint(groups), func(b *testing.B) {
			var source strings.Builder
			for g := 0; g < groups; g++ {
				fmt.Fprintf(&source, "@media(min-width:%dpx){", g+1)
				for i := 0; i < 2048/groups; i++ {
					source.WriteString("p{display:none}")
				}
				source.WriteByte('}')
			}
			b.ReportAllocs()
			for b.Loop() {
				s := sheet{limits: DefaultLimits()}
				s.parseStylesheetCSS(source.String())
				s.buildSelectorIndex()
				s.viewingCases()
				if s.cascadeIncomplete {
					b.Fatal("cascade abandoned")
				}
			}
		})
	}
}
func BenchmarkAuditFallback(b *testing.B) {
	for _, depth := range []int{16, 64, 192} {
		b.Run(fmt.Sprint(depth), func(b *testing.B) {
			ts, status := lexValue(strings.Repeat("var(--missing,", depth)+"none"+strings.Repeat(")", depth), nil)
			if status != valueResolved {
				b.Fatal(status)
			}
			lookup := func(string) variableValue { return variableValue{status: valueInvalid} }
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				v := substituteTokens(ts, lookup, nil, 0)
				if v.status != valueResolved {
					b.Fatal(v)
				}
			}
		})
	}
}
func BenchmarkAuditAttributes(b *testing.B) {
	for _, selector := range []string{".x", "#x"} {
		b.Run(selector, func(b *testing.B) {
			s := sheet{limits: DefaultLimits()}
			s.parseStylesheetCSS(selector + "{display:none}")
			s.buildSelectorIndex()
			n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "class", Val: strings.Repeat("x ", 4096)}}}
			b.ReportAllocs()
			for b.Loop() {
				s.runtime.attributeCandidates = nil
				if _, ok := s.attributeCandidateBuckets(n, nil); !ok {
					b.Fatal("stopped")
				}
			}
		})
	}
}
func BenchmarkAuditMath(b *testing.B) {
	ts, status := lexValue("min("+strings.Repeat("1px,", 1023)+"2px)", nil)
	if status != valueResolved {
		b.Fatal(status)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, status := evalMathTokens(fontSize, "", ts, &initialStyle, &initialStyle, nil)
		if status != valueResolved {
			b.Fatal(status)
		}
	}
}

func TestAuditAllocationBoundaries(t *testing.T) {
	t.Run("cumulative slice growth", func(t *testing.T) {
		memory := resourceguard.NewMemory(1 << 20)
		s, ok := growSlice([]uint64(nil), 1, memory)
		if !ok {
			t.Fatal("initial growth")
		}
		first := cap(s)
		s = s[:cap(s)]
		s, ok = growSlice(s, 1, memory)
		if !ok {
			t.Fatal("second growth")
		}
		if want := int64(first+cap(s)) * 8; memory.Used() != want {
			t.Fatalf("used=%d want=%d", memory.Used(), want)
		}
	})
	t.Run("plain container preparation", func(t *testing.T) {
		memory := resourceguard.NewMemory(64*int64(unsafe.Sizeof(documentFrame{})) + elementPreparationEntryBytes - 1)
		root := &html.Node{Type: html.ElementNode, Data: "div"}
		root.AppendChild(&html.Node{Type: html.ElementNode, Data: "span"})
		document := parsedDocument{memory: memory, elements: make(map[*html.Node]elementPreparation)}
		walker := documentWalker{document: &document, processor: processor{memory: memory, cpu: &cpuGuard{memory: memory}}}
		if err := walker.run(root); err == nil || !memory.Exhausted() {
			t.Fatalf("err=%v exhausted=%v", err, memory.Exhausted())
		}
	})
	t.Run("legacy hints", func(t *testing.T) {
		memory := resourceguard.NewMemory(int64(unsafe.Sizeof(declaration{})) - 1)
		n := &html.Node{Type: html.ElementNode, Data: "img", Attr: []html.Attribute{{Key: "width", Val: "1"}}}
		if ds := legacyDeclarationsWithBudget(n, &cpuGuard{memory: memory}); len(ds) != 0 || !memory.Exhausted() {
			t.Fatal("unbudgeted hints")
		}
	})
	t.Run("prepared value", func(t *testing.T) {
		memory := resourceguard.NewMemory(int64(unsafe.Sizeof(preparedDeclaration{})) - 1)
		d := prepareDeclaration(declaration{prop: display, value: "none"}, &cpuGuard{memory: memory})
		if d.prepared != nil || !memory.Exhausted() {
			t.Fatal("unbudgeted prepared value")
		}
	})
	t.Run("selector scratch", func(t *testing.T) {
		memory := resourceguard.NewMemory(4 + 1)
		s := sheet{memory: memory, index: selectorIndex{count: 1, universal: []selectorRef{{sequence: 0}}}}
		if _, ok := s.collectCandidates(&html.Node{Type: html.ElementNode, Data: "p"}, &cpuGuard{memory: memory}); ok || !memory.Exhausted() {
			t.Fatal("unbudgeted candidates")
		}
	})
	t.Run("ancestor activation", func(t *testing.T) {
		var active activeAncestorBuckets
		memory := resourceguard.NewMemory(1)
		if active.reset(100, memory) || !memory.Exhausted() {
			t.Fatal("unbudgeted activation")
		}
	})
	t.Run("result reasons", func(t *testing.T) {
		memory := resourceguard.NewMemory(int64(unsafe.Sizeof(string(""))) - 1)
		if got := concealmentReasonStringsWithBudget(reasonDisplayNone, &cpuGuard{memory: memory}); got != nil || !memory.Exhausted() {
			t.Fatal("unbudgeted reasons")
		}
	})
}

func stopOnSecondSample() *cpuGuard {
	calls := 0
	return &cpuGuard{shouldStop: func() bool { calls++; return calls >= 2 }}
}
func TestAuditLongLoopsSampleCancellation(t *testing.T) {
	t.Run("prepared cascade", func(t *testing.T) {
		d := prepareDeclaration(declaration{prop: display, value: "none"}, nil)
		ds := make([]declaration, 1024)
		for i := range ds {
			ds[i] = d
		}
		work := stopOnSecondSample()
		s := sheet{}
		if _, ok := s.collectCascade(nil, nil, ds, nil, &mediaEvaluation{}, selectorMatchContext{}, work, evaluationContext{}); ok || !work.stopped {
			t.Fatal("cascade did not stop within list")
		}
	})
	t.Run("colour layers", func(t *testing.T) {
		layers := make([]paintLayer, 1024)
		for i := range layers {
			layers[i] = layer(&initialStyle)
		}
		work := stopOnSecondSample()
		if result := evaluateColour(initialStyle[color], layers, work); result.known || !work.stopped {
			t.Fatal("colour loop did not stop")
		}
	})
	t.Run("variable boundaries", func(t *testing.T) {
		ts, status := lexValue(strings.Repeat("var(--missing,", 192)+"none"+strings.Repeat(")", 192), nil)
		if status != valueResolved {
			t.Fatal(status)
		}
		work := stopOnSecondSample()
		if v := substituteTokens(ts, func(string) variableValue { return variableValue{status: valueInvalid} }, work, 0); v.status != valueUnsupported || !work.stopped {
			t.Fatal("variable scan did not stop")
		}
	})
	t.Run("latched public stop", func(t *testing.T) {
		calls := 0
		_, err := AnalyzeWithStop([]byte(strings.Repeat("<p>T</p>", 2000)), DefaultLimits(), func() bool { calls++; return calls == 3 })
		if !IsStopped(err) {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
}

func TestMediaGroupsMatchIndependentRuleEvaluation(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`p{display:none}@media(min-width:1px){p{color:red}b{color:red}@media(max-width:1px){i{color:blue}}}@media(max-width:2px){p{display:block}}@media(prefers-color-scheme:dark){b{display:none}}`)
	s.buildSelectorIndex()
	widths, fallback := s.viewingCases()
	if fallback {
		t.Fatal("unexpected fallback")
	}
	candidates := []float64{0, .5, 1, 1.5, 2, math.Nextafter(2, math.Inf(1))}
	seen := map[string]bool{}
	var expected []float64
	for _, width := range candidates {
		var vector []byte
		for _, rule := range s.rules {
			vector = append(vector, byte(independentMediaState(rule.conditions, width, false)))
		}
		if !seen[string(vector)] {
			seen[string(vector)] = true
			expected = append(expected, width)
		}
	}
	if !reflect.DeepEqual(widths, expected) {
		t.Fatalf("widths=%v want=%v", widths, expected)
	}
	for _, width := range append(widths, 1024) {
		for _, fallback := range []bool{false, true} {
			states, ok := s.mediaStates(width, fallback, nil)
			if !ok {
				t.Fatal("incomplete media")
			}
			for _, rule := range s.rules {
				if got, want := int(states[rule.mediaGroup]), independentMediaState(rule.conditions, width, fallback); got != want {
					t.Fatalf("width=%v fallback=%v state=%d want=%d", width, fallback, got, want)
				}
			}
		}
	}
}

func TestAttributeBucketsDeduplicateAndPreserveFirstAttributes(t *testing.T) {
	s := sheet{limits: DefaultLimits()}
	s.parseStylesheetCSS(`.x{display:none}.x *{opacity:0}#first{visibility:hidden}#second{font-size:0}`)
	s.buildSelectorIndex()
	n := &html.Node{Type: html.ElementNode, Data: "p", Attr: []html.Attribute{{Key: "id", Val: "first"}, {Key: "id", Val: "second"}, {Key: "class", Val: strings.Repeat("x\t\n\f", 1000)}}}
	result, ok := s.attributeCandidateBuckets(n, nil)
	if !ok || len(result.direct) != 2 || len(result.ancestor) != 1 {
		t.Fatalf("buckets=%+v complete=%v", result, ok)
	}
	for _, bucket := range result.direct {
		for _, ref := range bucket {
			if s.rules[ref.rule].plans[ref.branch].source == "#second" {
				t.Fatal("duplicate attribute overrode first")
			}
		}
	}
	s.runtime.activeAncestors.reset(s.index.count, nil)
	s.runtime.activeAncestors.enabled = true
	first, ok := s.activateAncestorBuckets(n, nil)
	if !ok {
		t.Fatal("activation")
	}
	second, ok := s.activateAncestorBuckets(n, nil)
	if !ok {
		t.Fatal("activation")
	}
	s.deactivateAncestorBuckets(second)
	if len(s.runtime.activeAncestors.buckets) != 1 {
		t.Fatal("inner exit removed outer bucket")
	}
	s.deactivateAncestorBuckets(first)
	if len(s.runtime.activeAncestors.buckets) != 0 {
		t.Fatal("activation leaked")
	}
}

func TestMathPreservesPreparedTokens(t *testing.T) {
	source := "clamp(1px, calc(2px + 3px), max(4px, 8px))"
	tokens, status := lexValue(source, nil)
	if status != valueResolved {
		t.Fatal(status)
	}
	saved := append([]valueToken(nil), tokens...)
	for range 2 {
		value, status := evalMathTokens(fontSize, source, tokens, &initialStyle, &initialStyle, nil)
		if status != valueResolved || value.Number != 5 {
			t.Fatalf("value=%+v status=%v", value, status)
		}
		if !reflect.DeepEqual(tokens, saved) {
			t.Fatal("evaluation mutated prepared tokens")
		}
	}
}
