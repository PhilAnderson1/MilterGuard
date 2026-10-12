package htmlextract

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

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
	return nil
}

type processor struct {
	Limits           Limits
	retainInspection bool // tests only; production results retain compact decisions
}

func concealedVisibilityReason(value Value) string {
	if !value.Known {
		return ""
	}
	switch value.Text {
	case "hidden":
		return "visibility-hidden"
	case "collapse":
		return "visibility-collapse"
	default:
		return ""
	}
}

const (
	reasonDisplayNone uint8 = 1 << iota
	reasonVisibility
	reasonOpacity
	reasonFontSize
	reasonColour
	reasonEmptyClip
	reasonContentVisibility
)

type visibilityDecision struct {
	label   string
	reasons []string
}

func decideVisibility(style Style, none bool, displayKnown bool, alpha float64, alphaKnown bool, clipped, clipKnown, contentHidden, contentKnown, msoHidden, msoKnown, layoutUncertain bool, colour *colourResult) visibilityDecision {
	var mask uint8
	visibilityReason := concealedVisibilityReason(style[visibility])
	if none {
		mask |= reasonDisplayNone
	}
	if visibilityReason != "" {
		mask |= reasonVisibility
	}
	if alphaKnown && alpha <= .01+1e-14 {
		mask |= reasonOpacity
	}
	if clipped {
		mask |= reasonEmptyClip
	}
	if contentHidden {
		mask |= reasonContentVisibility
	}

	known := displayKnown && style[visibility].Known && alphaKnown && clipKnown && contentKnown && msoKnown && !layoutUncertain
	if colour != nil {
		if style[fontSize].Known && style[fontSize].Number <= 2 {
			mask |= reasonFontSize
		}
		if colour.known && colourConcealed(colour.distance) {
			mask |= reasonColour
		}
		known = known && style[fontSize].Known && colour.known
	}

	decision := visibilityDecision{label: "visible"}
	if mask != 0 {
		decision.label = "concealed"
	} else if !known {
		decision.label = "unknown"
	} else if msoHidden {
		// mso-hide is honored only by Word-based Outlook clients. This is
		// client-dependent, but not viewport-dependent, so use the generic
		// uncertainty annotation rather than the viewport-specific one.
		decision.label = "unknown"
	}
	for _, reason := range []struct {
		bit  uint8
		name string
	}{
		{reasonDisplayNone, "display-none"},
		{reasonVisibility, visibilityReason},
		{reasonOpacity, "opacity"},
		{reasonFontSize, "font-size"},
		{reasonColour, "colour-distance"},
		{reasonEmptyClip, "empty-clip"},
		{reasonContentVisibility, "content-visibility-hidden"},
	} {
		if mask&reason.bit != 0 {
			decision.reasons = append(decision.reasons, reason.name)
		}
	}
	return decision
}

func labelBit(label string) uint8 {
	switch label {
	case "concealed":
		return 2
	case "unknown":
		return 4
	default:
		return 1
	}
}

type Text struct {
	Label              string
	FontSize           string
	EffectiveOpacity   float64
	ConcealmentReasons []string
	Node               *html.Node
	inspection         *textInspection
}

// textInspection keeps detailed resolver evidence available to package tests
// without copying it into every production Text result.
type textInspection struct {
	style  Style
	colour colourInspection
}
type Element struct {
	Node               *html.Node
	Label              string
	ConcealmentReasons []string
	EffectiveOpacity   float64
}
type Document struct {
	Root                 *html.Node
	Text                 []Text
	Elements             []Element
	Usage                ResourceUsage
	UnresolvedStylesheet bool
}

// ResourceUsage records deterministic input-derived work performed while
// analysing one HTML document. Callers use it to carry remaining work across
// the HTML parts of one message; limits are still enforced inside Analyze.
type ResourceUsage struct {
	InputBytes              int
	Nodes                   int
	TextNodes               int
	Attributes              int
	Depth                   int
	CSSDepth                int
	Rules                   int
	Selectors               int
	MediaCases              int
	MatchWork               int64
	ExpressionWork          int64
	MatchWorkExhausted      bool
	ExpressionWorkExhausted bool
}

// Analyze parses and resolves a document once and retains the tree alongside
// the per-text-node presentation decisions used by message extraction.
func Analyze(input []byte, limits Limits) (Document, error) {
	p := processor{Limits: limits}
	return p.process(input)
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
func excluded(n *html.Node, parent string) string {
	if n.Type != html.ElementNode {
		return parent
	}
	// Inert/external-presentation containers override an inherited head scope.
	// Otherwise a style element nested in (for example) a head template would
	// incorrectly be collected as a document stylesheet.
	switch n.Data {
	case "template", "iframe", "noembed", "noframes", "object":
		return "outside-coverage:" + n.Data
	}
	if parent != "" {
		return parent
	}
	switch n.Data {
	case "head", "style", "script", "title":
		return n.Data
	}
	return ""
}
func void(n string) bool {
	switch n {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	default:
		return false
	}
}

func foreignBreakout(n string) bool {
	// HTML start tags that end ordinary SVG/MathML foreign-content parsing.
	// Treat font conservatively as a breakout without inspecting its attributes.
	switch n {
	case "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em", "embed", "font", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var":
		return true
	default:
		return false
	}
}

type lexicalFrame struct {
	name         string
	foreign      bool
	htmlChildren bool
}

// measurePreflight bounds explicit lexical nesting before the HTML5 tree builder
// (which itself can do expensive recovery). The builder can insert implied
// ancestors, so parseDocument separately enforces the limit on final tree
// depth. This conservative lexical stack can also reject malformed optional-tag
// sequences that would produce a shallower tree; that is explicit.
type lexicalUsage struct {
	nodes, textNodes, attributes, depth int
}

func measurePreflight(b []byte, l Limits) (lexicalUsage, error) {
	z := html.NewTokenizer(bytes.NewReader(b))
	var stack []lexicalFrame
	open := make(map[string]int)
	popTo := func(keep int) {
		for i := len(stack) - 1; i >= keep; i-- {
			name := stack[i].name
			if open[name] == 1 {
				delete(open, name)
			} else {
				open[name]--
			}
		}
		stack = stack[:keep]
	}
	var usage lexicalUsage
	for {
		t := z.Next()
		if t == html.ErrorToken {
			return usage, nil
		}
		switch t {
		case html.StartTagToken, html.SelfClosingTagToken, html.TextToken, html.CommentToken, html.DoctypeToken:
			usage.nodes++
			if usage.nodes > l.Nodes {
				return usage, fmt.Errorf("limit: lexical nodes > %d", l.Nodes)
			}
		}
		if t == html.TextToken {
			usage.textNodes++
			if usage.textNodes > l.TextNodes {
				return usage, fmt.Errorf("limit: lexical text nodes > %d", l.TextNodes)
			}
		}
		if t != html.StartTagToken && t != html.SelfClosingTagToken && t != html.EndTagToken {
			continue
		}
		raw, more := z.TagName()
		n := string(raw)
		if t == html.StartTagToken || t == html.SelfClosingTagToken {
			for more {
				_, _, more = z.TagAttr()
				usage.attributes++
				if usage.attributes > l.Attributes {
					return usage, fmt.Errorf("limit: lexical attributes > %d", l.Attributes)
				}
			}
		}
		if t == html.EndTagToken {
			// Unmatched end tags are common in malformed input and cannot
			// affect this stack. Avoid searching the full bounded depth for
			// every such token in an adversarial end-tag flood.
			if open[n] == 0 {
				continue
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == n {
					popTo(i)
					break
				}
			}
			continue
		}

		parentForeign := len(stack) > 0 && stack[len(stack)-1].foreign && !stack[len(stack)-1].htmlChildren
		if parentForeign && foreignBreakout(n) {
			// The HTML tree builder pops ordinary foreign elements and
			// reprocesses this token in HTML mode.
			keep := len(stack)
			for keep > 0 && stack[keep-1].foreign && !stack[keep-1].htmlChildren {
				keep--
			}
			popTo(keep)
			parentForeign = false
		}
		foreign := parentForeign || n == "svg" || n == "math"
		if t == html.SelfClosingTagToken && foreign {
			// The self-closing flag is honored in foreign content.
			continue
		}
		if !foreign && void(n) {
			continue
		}
		stack = append(stack, lexicalFrame{
			name:         n,
			foreign:      foreign,
			htmlChildren: foreign && (n == "foreignobject" || n == "desc" || n == "title"),
		})
		open[n]++
		if len(stack) > usage.depth {
			usage.depth = len(stack)
		}
		if len(stack) > l.Depth {
			return usage, fmt.Errorf("limit: lexical depth > %d", l.Depth)
		}
	}
}

type parsedDocument struct {
	root           *html.Node
	styles         sheet
	inlineDecls    map[*html.Node][]declaration
	treeDepth      int
	nodeCount      int
	textCount      int
	attributeCount int
	attributeWork  selectorAttributeProfile
	lexical        lexicalUsage
}

func (p processor) parseDocument(input []byte) (parsedDocument, error) {
	var document parsedDocument
	if err := p.Limits.validate(); err != nil {
		return document, err
	}
	if len(input) > p.Limits.InputBytes {
		return document, fmt.Errorf("limit: input bytes > %d", p.Limits.InputBytes)
	}
	lexical, err := measurePreflight(input, p.Limits)
	if err != nil {
		return document, err
	}
	document.lexical = lexical
	// Email extraction does not execute scripts; parse noscript fallback content
	// in the corresponding HTML5 tree-construction mode.
	root, err := html.ParseWithOptions(bytes.NewReader(input), html.ParseOptionEnableScripting(false))
	if err != nil {
		return document, err
	}
	document.root = root
	document.styles = sheet{limits: p.Limits}
	document.inlineDecls = make(map[*html.Node][]declaration)
	type entry struct {
		n     *html.Node
		depth int
		scope string
	}
	todo := []entry{{root, 0, ""}}
	for len(todo) > 0 {
		e := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		n := e.n
		if e.depth > p.Limits.Depth {
			return document, fmt.Errorf("limit: tree depth > %d", p.Limits.Depth)
		}
		if e.depth > document.treeDepth {
			document.treeDepth = e.depth
		}
		document.nodeCount++
		if document.nodeCount > p.Limits.Nodes {
			return document, fmt.Errorf("limit: tree nodes > %d", p.Limits.Nodes)
		}
		if n.Type == html.TextNode {
			document.textCount++
			if document.textCount > p.Limits.TextNodes {
				return document, fmt.Errorf("limit: tree text nodes > %d", p.Limits.TextNodes)
			}
		}
		if n.Type == html.ElementNode {
			document.attributeCount += len(n.Attr)
			if document.attributeCount > p.Limits.Attributes {
				return document, fmt.Errorf("limit: tree attributes > %d", p.Limits.Attributes)
			}
			document.attributeWork.observe(n)
			if href, media, applies := stylesheetLink(n); applies && (e.scope == "" || e.scope == "head") {
				document.styles.loadStylesheetReference(href, media)
			}
			if n.Data == "style" && (e.scope == "" || e.scope == "head") {
				var css strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						css.WriteString(c.Data)
					}
				}
				document.styles.parseStylesheet(css.String(), attr(n, "media"))
			}
			if value := attr(n, "style"); value != "" {
				document.inlineDecls[n] = document.styles.parseCSS(value, true)
			}
		}
		scope := excluded(n, e.scope)
		for c := n.LastChild; c != nil; c = c.PrevSibling {
			todo = append(todo, entry{c, e.depth + 1, scope})
		}
	}
	return document, nil
}

func (p processor) process(input []byte) (Document, error) {
	document, err := p.parseDocument(input)
	if err != nil {
		return Document{}, err
	}
	root := document.root
	s := &document.styles
	inlineDecls := document.inlineDecls
	in := Document{Root: root, Usage: ResourceUsage{
		InputBytes: len(input), Nodes: max(document.nodeCount, document.lexical.nodes),
		TextNodes:  max(document.textCount, document.lexical.textNodes),
		Attributes: max(document.attributeCount, document.lexical.attributes),
		Depth:      max(document.treeDepth, document.lexical.depth), CSSDepth: s.conditionDepth,
		Rules: len(s.rules), Selectors: s.selectors,
	}, UnresolvedStylesheet: s.unresolvedStylesheet}
	s.buildSelectorIndex(document.treeDepth, document.nodeCount)
	cap := p.Limits.MediaCases
	if cap < 1 || cap > MaxViewingCases {
		cap = MaxViewingCases
	}
	widths, fallback := s.viewingCases(cap)
	in.Usage.MediaCases = len(widths)
	s.cacheMatches = len(widths) > 1
	exprLimit := p.Limits.ExpressionWork
	if exprLimit < 1 {
		exprLimit = 10000000
	}
	budget := expressionBudget{remaining: exprLimit}
	matches := matchBudget{limit: p.Limits.MatchWork, used: s.planningWork}
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
			contentHidden      bool
			contentKnown       bool
			msoHidden          bool
			msoKnown           bool
			layoutUncertain    bool
			vars               *variableScope
			clipped, clipKnown bool
			selectorPath       selectorAttributeProfile
		}
		frames := make([]frame, 1)
		frames[0] = frame{n: root, style: initial(), alpha: 1, alphaKnown: true, displayKnown: true, contentKnown: true, msoKnown: true, clipKnown: true}
		rootStyle := initial()
		var layers []paintLayer
		for len(frames) > 0 {
			f := &frames[len(frames)-1]
			n := f.n
			if !f.entered {
				f.entered = true
				f.next = n.FirstChild
				if n.Type == html.ElementNode {
					parent := f.style
					var selectorCurrent selectorAttributeProfile
					selectorCurrent.observe(n)
					f.selectorPath.classes = max(f.selectorPath.classes, selectorCurrent.classes)
					f.selectorPath.ids = max(f.selectorPath.ids, selectorCurrent.ids)
					f.selectorPath.attributes = max(f.selectorPath.attributes, selectorCurrent.attributes)
					selectorContext := selectorMatchContext{
						current: selectorCurrent, path: f.selectorPath, document: document.attributeWork,
						depth: len(frames) - 1, nodes: document.nodeCount,
					}
					var err error
					var elementLayoutUncertain bool
					var displayDeclared bool
					f.style, f.vars, elementLayoutUncertain, displayDeclared, err = s.elementStyle(n, parent, rootStyle, f.vars, inlineDecls[n], width, fallback, selectorContext, &matches, &budget)
					if err != nil {
						return in, err
					}
					empty, known, clipPathIgnored := emptyClip(f.style, n, displayDeclared)
					f.clipped = f.clipped || empty
					f.clipKnown = f.clipKnown && known
					paintStyle := f.style
					if clipPathIgnored {
						paintStyle[clipPath] = initialStyle[clipPath]
					}
					layers = append(layers, layer(paintStyle))
					if n.Namespace == "" && n.Data == "body" && n.Parent != nil && n.Parent.Namespace == "" && n.Parent.Data == "html" {
						propagateHTMLBodyBackground(layers)
					}
					if n.Data == "html" {
						rootStyle = f.style
					}
					f.displayKnown = f.displayKnown && f.style[display].Known
					if f.style[display].Known && f.style[display].Text == "none" {
						f.none = true
					}
					cv := f.style[contentVisibility]
					if cv.Known && cv.Text == "hidden" {
						f.contentHidden = true
					}
					f.contentKnown = f.contentKnown && cv.Known
					mh := f.style[msoHide]
					if mh.Known && mh.Text == "all" {
						f.msoHidden = true
					}
					f.msoKnown = f.msoKnown && mh.Known
					f.layoutUncertain = f.layoutUncertain || elementLayoutUncertain
					a := f.style[opacity]
					if a.Known && a.Number == 0 {
						f.alpha = 0
						f.alphaKnown = true
					} else if f.alphaKnown && f.alpha == 0 {
					} else {
						f.alpha *= a.Number
						f.alphaKnown = f.alphaKnown && a.Known
					}
					if n.Data == "img" || n.Data == "input" {
						decision := decideVisibility(f.style, f.none, f.displayKnown, f.alpha, f.alphaKnown, f.clipped, f.clipKnown, f.contentHidden, f.contentKnown, f.msoHidden, f.msoKnown, f.layoutUncertain, nil)
						bit := labelBit(decision.label)
						if caseIndex == 0 {
							elementLabels = append(elementLabels, bit)
						} else {
							elementLabels[elementIndex] |= bit
						}
						if caseIndex == 0 {
							in.Elements = append(in.Elements, Element{Node: n, Label: decision.label, ConcealmentReasons: decision.reasons, EffectiveOpacity: f.alpha})
						}
						elementIndex++
					}
				}
				f.scope = excluded(n, f.scope)
				if n.Type == html.TextNode {
					if f.scope == "" {
						st := f.style
						colour := evaluateColour(st[color], layers, &matches)
						decision := decideVisibility(st, f.none, f.displayKnown, f.alpha, f.alphaKnown, f.clipped, f.clipKnown, f.contentHidden, f.contentKnown, f.msoHidden, f.msoKnown, f.layoutUncertain, &colour)
						bit := labelBit(decision.label)
						if caseIndex == 0 {
							labels = append(labels, bit)
						} else {
							labels[textIndex] |= bit
						}
						if caseIndex == 0 {
							text := Text{Label: decision.label, FontSize: st[fontSize].Text, EffectiveOpacity: f.alpha, ConcealmentReasons: decision.reasons, Node: n}
							if p.retainInspection {
								text.inspection = &textInspection{style: st, colour: colour.inspection()}
							}
							in.Text = append(in.Text, text)
						}
						textIndex++
					}
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
			frames = append(frames, frame{n: c, style: f.style, scope: f.scope, none: f.none, alpha: f.alpha, alphaKnown: f.alphaKnown, displayKnown: f.displayKnown, contentHidden: f.contentHidden, contentKnown: f.contentKnown, msoHidden: f.msoHidden, msoKnown: f.msoKnown, layoutUncertain: f.layoutUncertain, vars: f.vars, clipped: f.clipped, clipKnown: f.clipKnown, selectorPath: f.selectorPath})
		}
		if caseIndex == 0 {
			firstText = in.Text
			firstElements = in.Elements
		}
		if matches.exhausted && caseIndex+1 < len(widths) {
			// All later cases would receive unresolved styles. Mark their
			// contribution directly instead of repeatedly traversing the DOM.
			unknown := labelBit("unknown")
			for i := range labels {
				labels[i] |= unknown
			}
			for i := range elementLabels {
				elementLabels[i] |= unknown
			}
			break
		}
	}
	for i, bits := range labels {
		label := aggregateLabel(bits)
		firstText[i].Label = label
		if label != "concealed" {
			firstText[i].ConcealmentReasons = nil
		}
	}
	in.Text = firstText
	for i, bits := range elementLabels {
		firstElements[i].Label = aggregateLabel(bits)
		if firstElements[i].Label != "concealed" {
			firstElements[i].ConcealmentReasons = nil
		}
	}
	in.Elements = firstElements
	in.Usage.MatchWork = matches.used
	in.Usage.MatchWorkExhausted = matches.exhausted || s.workIncomplete
	in.Usage.ExpressionWork = exprLimit - budget.remaining
	if in.Usage.ExpressionWork > exprLimit {
		in.Usage.ExpressionWork = exprLimit
	}
	in.Usage.ExpressionWorkExhausted = budget.exhausted
	return in, nil
}
