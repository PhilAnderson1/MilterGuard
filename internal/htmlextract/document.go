// Package document retains one HTML tree and traverses with bounded inherited
// state. It has no resource loader, renderer, global stylesheet or font cache.
package htmlextract

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract/harness"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract/repair"
	"golang.org/x/net/html"
)

type Limits struct {
	InputBytes, Depth, Rules, Selectors, Diagnostics, SelectorBytes int
	MatchWork                                                       int64
	MediaCases                                                      int
	ExpressionWork                                                  int64
}

// MaxViewingCases is the hard ceiling for conditional evaluations per document.
const MaxViewingCases = 16

func DefaultLimits() Limits {
	return Limits{InputBytes: 8 << 20, Depth: 128, Rules: 10000, Selectors: 20000, Diagnostics: 256, SelectorBytes: 2048, MatchWork: 100000000, MediaCases: MaxViewingCases, ExpressionWork: 10000000}
}

type Processor struct {
	Repair bool
	Limits Limits
}
type Text struct {
	CaseLabels          []string         `json:"case_labels,omitempty"`
	Element             string           `json:"element"`
	Text                string           `json:"text"`
	Label               string           `json:"label"`
	Style               map[string]Value `json:"style"`
	AncestorDisplayNone bool             `json:"effective_display_none"`
	EffectiveOpacity    float64          `json:"effective_opacity"`
	OpacityKnown        bool             `json:"effective_opacity_known"`
	Colour              ColourInspection `json:"colour"`
	ConcealmentReasons  []string         `json:"concealment_reasons"`
	Node                *html.Node       `json:"-"`
}
type Source struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}
type Element struct {
	Node               *html.Node `json:"-"`
	Label              string     `json:"label"`
	CaseLabels         []string   `json:"case_labels,omitempty"`
	ConcealmentReasons []string   `json:"concealment_reasons,omitempty"`
	EffectiveOpacity   float64    `json:"effective_opacity"`
	OpacityKnown       bool       `json:"effective_opacity_known"`
}
type Inspection struct {
	Root                *html.Node      `json:"-"`
	Widths              []float64       `json:"viewing_widths_css_px"`
	ConditionalFallback bool            `json:"conditional_fallback"`
	Canvas              string          `json:"default_canvas"`
	Repairs             []repair.Change `json:"repairs"`
	Diagnostics         []string        `json:"uncertainty_reasons"`
	Text                []Text          `json:"body_text"`
	Elements            []Element       `json:"elements"`
	Sources             []Source        `json:"excluded_source"`
}

// Analyze parses and resolves a document once and retains the tree alongside
// the per-text-node presentation decisions used by message extraction.
func Analyze(input []byte, limits Limits) (Inspection, error) {
	processor := Processor{Limits: limits}
	result, err := processor.Process(input, "styles", true)
	if err != nil {
		return Inspection{}, err
	}
	inspection, ok := result.Inspection.(Inspection)
	if !ok {
		return Inspection{}, fmt.Errorf("HTML inspection unavailable")
	}
	return inspection, nil
}

type digest uint64

func (h *digest) add(s string) {
	for i := 0; i < len(s); i++ {
		*h ^= digest(s[i])
		*h *= 1099511628211
	}
	*h ^= 255
	*h *= 1099511628211
}
func (h *digest) number(v float64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], math.Float64bits(v))
	h.add(string(b[:]))
}
func (h *digest) style(s Style) {
	var b [8]byte
	for _, v := range s {
		h.add(v.Text)
		binary.LittleEndian.PutUint64(b[:], math.Float64bits(v.Number))
		h.add(string(b[:]))
		if v.Known {
			h.add("known")
		} else {
			h.add("unknown")
		}
	}
}
func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}
func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}
func identify(n *html.Node) string {
	if n == nil {
		return "document"
	}
	s := n.Data
	if id := attr(n, "id"); id != "" {
		s += "#" + id
	}
	if cl := attr(n, "class"); cl != "" {
		s += "." + strings.Join(strings.Fields(cl), ".")
	}
	return s
}
func excluded(n *html.Node, parent string) string {
	if parent != "" {
		return parent
	}
	if n.Type != html.ElementNode {
		return ""
	}
	switch n.Data {
	case "head", "style", "script", "title":
		return n.Data
	case "template", "iframe", "noembed", "noframes", "object":
		return "outside-coverage:" + n.Data
	}
	return ""
}
func void(n string) bool {
	return strings.Contains(" area base br col embed hr img input link meta param source track wbr ", " "+n+" ")
}

// Preflight bounds nesting before the HTML5 tree builder (which itself can do
// expensive recovery). This conservative lexical stack can reject malformed
// optional-tag sequences that would produce a shallower tree; that is explicit.
func preflight(b []byte, l Limits) error {
	z := html.NewTokenizer(bytes.NewReader(b))
	stack := make([]string, 0, l.Depth)
	for {
		t := z.Next()
		if t == html.ErrorToken {
			return nil
		}
		if t != html.StartTagToken && t != html.EndTagToken {
			continue
		}
		raw, _ := z.TagName()
		n := string(raw)
		if t == html.EndTagToken {
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i] == n {
					stack = stack[:i]
					break
				}
			}
		} else if !void(n) {
			stack = append(stack, n)
			if len(stack) > l.Depth {
				return fmt.Errorf("limit: lexical depth > %d", l.Depth)
			}
		}
	}
}
func (p Processor) Process(input []byte, mode string, inspect bool) (harness.Result, error) {
	var res harness.Result
	if len(input) > p.Limits.InputBytes {
		return res, fmt.Errorf("limit: input bytes > %d", p.Limits.InputBytes)
	}
	b := input
	var log []repair.Change
	if p.Repair {
		var err error
		b, log, err = repair.Apply(b)
		if err != nil {
			return res, err
		}
	}
	res.Repairs = len(log)
	if len(log) > p.Limits.Diagnostics {
		return res, fmt.Errorf("limit: repair log volume")
	}
	h := digest(14695981039346656037)
	if mode == "repair" {
		h.add(string(b))
		res.Checksum = fmt.Sprintf("%016x", h)
		if inspect {
			res.Inspection = Inspection{Repairs: log}
		}
		return res, nil
	}
	if err := preflight(b, p.Limits); err != nil {
		return res, err
	}
	// Email extraction does not execute scripts; parse noscript fallback content
	// in the corresponding HTML5 tree-construction mode.
	root, err := html.ParseWithOptions(bytes.NewReader(b), html.ParseOptionEnableScripting(false))
	if err != nil {
		return res, err
	}
	s := sheet{limits: p.Limits}
	inlineDecls := make(map[*html.Node][]declaration)
	type entry struct {
		n     *html.Node
		depth int
		scope string
	}
	todo := []entry{{root, 0, ""}}
	treeDepth := 0
	for len(todo) > 0 {
		e := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		n := e.n
		if e.depth > p.Limits.Depth {
			return res, fmt.Errorf("limit: tree depth > %d", p.Limits.Depth)
		}
		if e.depth > treeDepth {
			treeDepth = e.depth
		}
		res.Nodes++
		if n.Type == html.ElementNode {
			res.Elements++
		}
		if n.Type == html.TextNode {
			res.TextNodes++
			res.TextBytes += len(n.Data)
		}
		if mode == "parse" {
			h.add(n.Data)
		}
		if mode == "styles" && n.Type == html.ElementNode {
			if n.Data == "style" && (e.scope == "" || e.scope == "head") {
				var css strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						css.WriteString(c.Data)
					}
				}
				s.parseCSS(css.String(), false)
			}
			if value := attr(n, "style"); value != "" {
				inlineDecls[n] = s.parseCSS(value, true)
			}
			if n.Data == "link" && strings.Contains(strings.ToLower(attr(n, "rel")), "stylesheet") {
				s.warn("external stylesheet not fetched")
			}
		}
		scope := excluded(n, e.scope)
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			todo = append(todo, entry{c, e.depth + 1, scope})
		}
	}
	res.Rules = len(s.rules)
	res.Selectors = s.selectors
	if s.err != nil {
		return res, s.err
	}
	in := Inspection{Root: root, Repairs: log, Canvas: "opaque white (light-mode assumption)"}
	if mode == "styles" {
		for i := range s.rules {
			r := &s.rules[i]
			for _, sel := range r.selectors {
				r.costs = append(r.costs, selectorCost(sel.String(), treeDepth, res.Nodes, p.Limits.MatchWork))
				r.fallbackScopes = append(r.fallbackScopes, uncertainSelectorScope(sel.String()))
				r.scopeCosts = append(r.scopeCosts, int64(len(sel.String())+1))
			}
		}
		cap := p.Limits.MediaCases
		if cap < 1 || cap > MaxViewingCases {
			cap = MaxViewingCases
		}
		widths, fallback := s.viewingCases(cap)
		res.ViewingCases = len(widths)
		res.ConditionalFallback = fallback
		in.Widths = widths
		in.ConditionalFallback = fallback
		if fallback {
			s.warn("conditional case cap/planning budget: unresolved width conditions")
		}
		exprLimit := p.Limits.ExpressionWork
		if exprLimit < 1 {
			exprLimit = 10000000
		}
		budget := expressionBudget{remaining: exprLimit}
		work := s.planningWork
		var labels, elementLabels []uint8
		var firstText []Text
		var firstElements []Element
		for caseIndex, width := range widths {
			textIndex := 0
			elementIndex := 0
			type frame struct {
				n, next            *html.Node
				entered            bool
				style              Style
				scope              string
				none               bool
				alpha              float64
				alphaKnown         bool
				displayKnown       bool
				vars               *variableScope
				clipped, clipKnown bool
			}
			frames := make([]frame, 1, p.Limits.Depth+2)
			frames[0] = frame{n: root, style: initial(), alpha: 1, alphaKnown: true, displayKnown: true, clipKnown: true}
			rootStyle := initial()
			layers := make([]paintLayer, 0, p.Limits.Depth)
			for len(frames) > 0 {
				f := &frames[len(frames)-1]
				n := f.n
				if !f.entered {
					f.entered = true
					f.next = n.FirstChild
					if n.Type == html.ElementNode {
						parent := f.style
						var err error
						f.style, f.vars, err = s.elementStyle(n, parent, rootStyle, f.vars, inlineDecls[n], width, fallback, &work, &budget)
						if err != nil {
							return res, err
						}
						empty, known := emptyClip(f.style, n.Namespace)
						f.clipped = f.clipped || empty
						f.clipKnown = f.clipKnown && known
						layers = append(layers, layer(f.style))
						if n.Data == "html" {
							rootStyle = f.style
						}
						f.displayKnown = f.displayKnown && f.style[display].Known
						if f.style[display].Known && f.style[display].Text == "none" {
							f.none = true
						}
						a := f.style[opacity]
						if a.Known && a.Number == 0 {
							f.alpha = 0
							f.alphaKnown = true
						} else if f.alphaKnown && f.alpha == 0 {
						} else {
							f.alpha *= a.Number
							f.alphaKnown = f.alphaKnown && a.Known
						}
						label := "visible"
						var reasonMask uint8
						if f.none {
							reasonMask |= 1
						}
						if f.style[visibility].Known && f.style[visibility].Text == "hidden" {
							reasonMask |= 2
						}
						if f.alphaKnown && f.alpha <= .01+1e-14 {
							reasonMask |= 4
						}
						if f.clipped {
							reasonMask |= 8
						}
						if reasonMask != 0 {
							label = "concealed"
						} else if !f.displayKnown || !f.style[visibility].Known || !f.alphaKnown || !f.clipKnown {
							label = "unknown"
						}
						bit := uint8(1)
						if label == "concealed" {
							bit = 2
						} else if label == "unknown" {
							bit = 4
						}
						if caseIndex == 0 {
							elementLabels = append(elementLabels, bit)
						} else {
							elementLabels[elementIndex] |= bit
						}
						if inspect && caseIndex == 0 {
							var reasons []string
							for i, reason := range []string{"display-none", "visibility-hidden", "opacity", "empty-clip"} {
								if reasonMask&(1<<i) != 0 {
									reasons = append(reasons, reason)
								}
							}
							in.Elements = append(in.Elements, Element{Node: n, Label: label, CaseLabels: []string{label}, ConcealmentReasons: reasons, EffectiveOpacity: f.alpha, OpacityKnown: f.alphaKnown})
						} else if inspect {
							firstElements[elementIndex].CaseLabels = append(firstElements[elementIndex].CaseLabels, label)
						}
						elementIndex++
						if strings.HasPrefix(excluded(n, ""), "outside-coverage:") {
							s.warn("inert/client-dependent content: " + n.Data)
						}
					}
					f.scope = excluded(n, f.scope)
					if n.Type == html.TextNode {
						if f.scope != "" {
							if inspect && caseIndex == 0 {
								in.Sources = append(in.Sources, Source{f.scope, n.Data})
							}
						} else {
							if caseIndex == 0 {
								res.BodyTextNodes++
							}
							label := "visible"
							st := f.style
							colour := evaluateColour(st[color], layers)
							var reasonMask uint8
							if f.none {
								reasonMask |= 1
							}
							if st[visibility].Known && st[visibility].Text == "hidden" {
								reasonMask |= 2
							}
							if f.alphaKnown && f.alpha <= .01+1e-14 {
								reasonMask |= 4
							}
							if st[fontSize].Known && st[fontSize].Number <= 2 {
								reasonMask |= 8
							}
							if colour.known {
								if caseIndex == 0 {
									res.ColourKnownTextNodes++
								}
								if colourConcealed(colour.distance) {
									reasonMask |= 16
									if caseIndex == 0 {
										res.ColourConcealedTextNodes++
									}
								}
							} else {
								if caseIndex == 0 {
									res.ColourUnknownTextNodes++
								}
							}
							if f.clipped {
								reasonMask |= 32
							}
							if reasonMask != 0 {
								label = "concealed"
							} else if !f.displayKnown || !st[visibility].Known || !st[fontSize].Known || !f.alphaKnown || !colour.known || !f.clipKnown {
								label = "unknown"
							}
							h.colour(colour)
							h.add(n.Data)
							h.style(st)
							h.add(label)
							h.add(fmt.Sprintf("%t/%g/%t", f.none, f.alpha, f.alphaKnown))
							bit := uint8(1)
							if label == "concealed" {
								bit = 2
							}
							if label == "unknown" {
								bit = 4
							}
							if caseIndex == 0 {
								labels = append(labels, bit)
							} else {
								labels[textIndex] |= bit
							}
							if inspect && caseIndex == 0 {
								m := make(map[string]Value, properties)
								for i, name := range names {
									m[name] = st[i]
								}
								var reasons []string
								for i, name := range []string{"display-none", "visibility-hidden", "opacity", "font-size", "colour-distance", "empty-clip"} {
									if reasonMask&(1<<i) != 0 {
										reasons = append(reasons, name)
									}
								}
								in.Text = append(in.Text, Text{CaseLabels: []string{label}, Element: identify(n.Parent), Text: n.Data, Label: label, Style: m, AncestorDisplayNone: f.none, EffectiveOpacity: f.alpha, OpacityKnown: f.alphaKnown, Colour: colour.inspection(), ConcealmentReasons: reasons, Node: n})
							}
							if inspect && caseIndex > 0 {
								firstText[textIndex].CaseLabels = append(firstText[textIndex].CaseLabels, label)
							}
							textIndex++
						}
					} else if n.Type == html.CommentNode && inspect && caseIndex == 0 {
						in.Sources = append(in.Sources, Source{"comment", n.Data})
					}
				}
				if f.next == nil {
					if f.n.Type == html.ElementNode {
						layers = layers[:len(layers)-1]
					}
					frames = frames[:len(frames)-1]
					continue
				}
				c := f.next
				f.next = c.NextSibling
				frames = append(frames, frame{n: c, style: f.style, scope: f.scope, none: f.none, alpha: f.alpha, alphaKnown: f.alphaKnown, displayKnown: f.displayKnown, vars: f.vars, clipped: f.clipped, clipKnown: f.clipKnown})
			}
			if caseIndex == 0 {
				firstText = in.Text
				firstElements = in.Elements
			}
		}
		for i, bits := range labels {
			label := aggregateLabel(bits)
			h.add(label)
			if label == "client-dependent" {
				res.ClientDependentTextNodes++
			}
			if label == "concealed" {
				res.ConcealedTextNodes++
			}
			if label == "unknown" {
				res.UnknownTextNodes++
			}
			if inspect {
				firstText[i].Label = label
				if label != "concealed" {
					firstText[i].ConcealmentReasons = nil
				}
			}
		}
		in.Text = firstText
		if inspect {
			for i, bits := range elementLabels {
				firstElements[i].Label = aggregateLabel(bits)
				if firstElements[i].Label != "concealed" {
					firstElements[i].ConcealmentReasons = nil
				}
			}
		}
		in.Elements = firstElements
		res.ExpressionWork = exprLimit - budget.remaining
		if budget.exhausted {
			s.warn("expression work budget exhausted; affected values unresolved")
		}
		res.MatchWork = work
	}
	if s.err != nil {
		return res, s.err
	}
	res.Warnings = s.diagnostics
	res.Uncertainties = len(s.diagnostics)
	res.Checksum = fmt.Sprintf("%016x", h)
	if inspect {
		in.Diagnostics = s.diagnostics
		res.Inspection = in
	}
	return res, nil
}
