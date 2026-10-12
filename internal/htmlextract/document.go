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

type visibilityLabel uint8

const (
	labelVisible visibilityLabel = 1 << iota
	labelConcealed
	labelUnknown
)

type concealmentReason uint8

func concealedVisibilityReason(value Value) concealmentReason {
	if !value.Known {
		return 0
	}
	switch value.Text {
	case "hidden":
		return reasonVisibilityHidden
	case "collapse":
		return reasonVisibilityCollapse
	default:
		return 0
	}
}

const (
	reasonDisplayNone concealmentReason = 1 << iota
	reasonVisibilityHidden
	reasonVisibilityCollapse
	reasonOpacity
	reasonFontSize
	reasonColour
	reasonEmptyClip
	reasonContentVisibility
)

type visibilityDecision struct {
	label   visibilityLabel
	reasons concealmentReason
}

type presentationState struct {
	none, displayKnown          bool
	alpha                       float64
	alphaKnown                  bool
	clipped, clipKnown          bool
	contentHidden, contentKnown bool
	msoHidden, msoKnown         bool
	layoutUncertain             bool
}

func initialPresentationState() presentationState {
	return presentationState{alpha: 1, alphaKnown: true, displayKnown: true, contentKnown: true, msoKnown: true, clipKnown: true}
}

func decideVisibility(style *Style, state presentationState, colour *colourResult) visibilityDecision {
	var mask concealmentReason
	visibilityReason := concealedVisibilityReason(style[visibility])
	if state.none {
		mask |= reasonDisplayNone
	}
	if visibilityReason != 0 {
		mask |= visibilityReason
	}
	if state.alphaKnown && state.alpha <= .01+1e-14 {
		mask |= reasonOpacity
	}
	if state.clipped {
		mask |= reasonEmptyClip
	}
	if state.contentHidden {
		mask |= reasonContentVisibility
	}

	known := state.displayKnown && style[visibility].Known && state.alphaKnown && state.clipKnown && state.contentKnown && state.msoKnown && !state.layoutUncertain
	if colour != nil {
		if style[fontSize].Known && style[fontSize].Number <= 2 {
			mask |= reasonFontSize
		}
		if colour.known && colourConcealed(colour.distance) {
			mask |= reasonColour
		}
		known = known && style[fontSize].Known && colour.known
	}

	decision := visibilityDecision{label: labelVisible, reasons: mask}
	if mask != 0 {
		decision.label = labelConcealed
	} else if !known {
		decision.label = labelUnknown
	} else if state.msoHidden {
		// mso-hide is honored only by Word-based Outlook clients. This is
		// client-dependent, but not viewport-dependent, so use the generic
		// uncertainty annotation rather than the viewport-specific one.
		decision.label = labelUnknown
	}
	return decision
}

func concealmentReasonStrings(mask concealmentReason) []string {
	var reasons [8]string
	count := 0
	for _, reason := range []struct {
		bit  concealmentReason
		name string
	}{
		{reasonDisplayNone, "display-none"},
		{reasonVisibilityHidden, "visibility-hidden"},
		{reasonVisibilityCollapse, "visibility-collapse"},
		{reasonOpacity, "opacity"},
		{reasonFontSize, "font-size"},
		{reasonColour, "colour-distance"},
		{reasonEmptyClip, "empty-clip"},
		{reasonContentVisibility, "content-visibility-hidden"},
	} {
		if mask&reason.bit != 0 {
			reasons[count] = reason.name
			count++
		}
	}
	return append([]string(nil), reasons[:count]...)
}

func labelBit(label string) visibilityLabel {
	switch label {
	case "concealed":
		return labelConcealed
	case "unknown":
		return labelUnknown
	default:
		return labelVisible
	}
}

// Text describes one extractable text node. Label is aggregated across every
// evaluated viewing case. FontSize, EffectiveOpacity and ConcealmentReasons
// describe the first evaluated case and provide representative rendering
// evidence rather than a second cross-case aggregate.
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

// Element describes an image-like element. Label is aggregated across viewing
// cases; EffectiveOpacity and ConcealmentReasons come from the first case.
type Element struct {
	Node               *html.Node
	Label              string
	ConcealmentReasons []string
	EffectiveOpacity   float64
}
type Document struct {
	Root     *html.Node
	Text     []Text
	Elements []Element
	Usage    ResourceUsage
	// UnresolvedStylesheet reports that an applicable external or unsupported
	// stylesheet could not be evaluated. It does not force every node label to
	// unknown; consumers must account for the missing global CSS separately.
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
	CSSLimitExceeded        bool
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
	root                    *html.Node
	styles                  sheet
	elements                map[*html.Node]elementPreparation
	treeDepth               int
	nodeCount               int
	textCount               int
	attributeCount          int
	extractableTextCount    int
	extractableElementCount int
	attributeWork           selectorAttributeProfile
	lexical                 lexicalUsage
}

type elementPreparation struct {
	inline, legacy []declaration
	selector       selectorAttributeProfile
}

func (p selectorAttributeProfile) empty() bool {
	return p.classes == 0 && p.ids == 0 && p.attributes == 0
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
	document.elements = make(map[*html.Node]elementPreparation)
	type entry struct {
		n, next *html.Node
		depth   int
		scope   string
		entered bool
	}
	stack := make([]entry, 1, max(1, document.lexical.depth+1))
	stack[0] = entry{n: root}
	for len(stack) > 0 {
		e := &stack[len(stack)-1]
		if e.entered {
			if e.next == nil {
				stack = stack[:len(stack)-1]
				continue
			}
			child := e.next
			e.next = child.NextSibling
			stack = append(stack, entry{n: child, depth: e.depth + 1, scope: e.scope})
			continue
		}
		e.entered = true
		e.next = e.n.FirstChild
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
			var prepared elementPreparation
			prepared.selector.observe(n)
			document.attributeWork.classes = max(document.attributeWork.classes, prepared.selector.classes)
			document.attributeWork.ids = max(document.attributeWork.ids, prepared.selector.ids)
			document.attributeWork.attributes = max(document.attributeWork.attributes, prepared.selector.attributes)
			if href, media, applies := stylesheetLink(n); applies && (e.scope == "" || e.scope == "head") {
				document.styles.loadStylesheetReference(href, media)
			}
			if n.Data == "style" && (e.scope == "" || e.scope == "head") {
				styles := &document.styles
				if !styles.cascadeIncomplete && !styles.workIncomplete {
					remaining := styles.limits.CSSBytes - styles.cssBytes
					css, complete := boundedStyleText(n, remaining)
					if !complete {
						styles.abandonCascade()
					} else {
						styles.parseStylesheet(css, attr(n, "media"))
					}
				}
			}
			if value := attr(n, "style"); value != "" {
				prepared.inline = document.styles.parseCSS(value, true)
			}
			if !document.styles.cascadeIncomplete && !document.styles.workIncomplete {
				prepared.legacy = prepareDeclarations(legacyDeclarations(n))
			}
			if len(prepared.inline) != 0 || len(prepared.legacy) != 0 || !prepared.selector.empty() {
				document.elements[n] = prepared
			}
			if n.Data == "img" || n.Data == "input" {
				document.extractableElementCount++
			}
		}
		e.scope = excluded(n, e.scope)
		if n.Type == html.TextNode && e.scope == "" {
			document.extractableTextCount++
		}
	}
	if document.styles.cascadeIncomplete || document.styles.workIncomplete {
		// No prepared per-element CSS can be used once global style analysis is
		// incomplete. Release declarations and selector profiles collected before
		// the failure rather than retaining them through result traversal.
		document.elements = nil
	}
	return document, nil
}

func boundedStyleText(style *html.Node, maximum int) (string, bool) {
	if maximum < 0 {
		return "", false
	}
	var css strings.Builder
	for child := style.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != html.TextNode {
			continue
		}
		if len(child.Data) > maximum-css.Len() {
			return "", false
		}
		css.WriteString(child.Data)
	}
	return css.String(), true
}

type viewingCaseResults struct {
	text           []Text
	elements       []Element
	textLabels     []visibilityLabel
	elementLabels  []visibilityLabel
	textReasons    []concealmentReason
	elementReasons []concealmentReason
}

type viewingCaseFrame struct {
	n, next *html.Node
	entered bool
	style   Style
	scope   string
	presentationState
	vars         *variableScope
	selectorPath selectorAttributeProfile
}

type viewingCaseRunner struct {
	document         *parsedDocument
	styles           *sheet
	retainInspection bool
	matches          *matchBudget
	expressions      *expressionBudget
	results          *viewingCaseResults
	frames           []viewingCaseFrame
	layers           []paintLayer
}

func (r *viewingCaseRunner) run(width float64, fallback, first bool) error {
	textIndex, elementIndex := 0, 0
	media := mediaEvaluation{width: width, fallback: fallback}
	r.frames = r.frames[:0]
	r.frames = append(r.frames, viewingCaseFrame{n: r.document.root, style: initial(), presentationState: initialPresentationState()})
	rootStyle := initial()
	r.layers = r.layers[:0]
	for len(r.frames) > 0 {
		f := &r.frames[len(r.frames)-1]
		n := f.n
		if !f.entered {
			f.entered = true
			f.next = n.FirstChild
			if n.Type == html.ElementNode {
				prepared := r.document.elements[n]
				selectorCurrent := prepared.selector
				f.selectorPath.classes = max(f.selectorPath.classes, selectorCurrent.classes)
				f.selectorPath.ids = max(f.selectorPath.ids, selectorCurrent.ids)
				f.selectorPath.attributes = max(f.selectorPath.attributes, selectorCurrent.attributes)
				selectorContext := selectorMatchContext{
					current: selectorCurrent, path: f.selectorPath, document: r.document.attributeWork,
					depth: len(r.frames) - 1, nodes: r.document.nodeCount,
				}
				resolved := r.styles.elementStyle(n, &f.style, &rootStyle, f.vars, prepared.legacy, prepared.inline, &media, selectorContext, r.matches, r.expressions)
				f.style = resolved.style
				f.vars = resolved.variables
				empty, known, inlineClipPathUncertain := emptyClip(&f.style, n, resolved.displayDeclared)
				f.clipped = f.clipped || empty
				f.clipKnown = f.clipKnown && known
				paintStyle := f.style
				if inlineClipPathUncertain {
					paintStyle[clipPath] = initialStyle[clipPath]
				}
				r.layers = append(r.layers, layer(&paintStyle))
				if n.Namespace == "" && n.Data == "body" && n.Parent != nil && n.Parent.Namespace == "" && n.Parent.Data == "html" {
					propagateHTMLBodyBackground(r.layers)
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
				f.layoutUncertain = f.layoutUncertain || resolved.layoutUncertain
				a := f.style[opacity]
				if a.Known && a.Number == 0 {
					f.alpha = 0
					f.alphaKnown = true
				} else if !(f.alphaKnown && f.alpha == 0) {
					f.alpha *= a.Number
					f.alphaKnown = f.alphaKnown && a.Known
				}
				if n.Data == "img" || n.Data == "input" {
					decision := decideVisibility(&f.style, f.presentationState, nil)
					if first {
						r.results.elementLabels = append(r.results.elementLabels, decision.label)
						r.results.elementReasons = append(r.results.elementReasons, decision.reasons)
						r.results.elements = append(r.results.elements, Element{Node: n, EffectiveOpacity: f.alpha})
					} else if !mergeViewingCaseLabel(r.results.elementLabels, elementIndex, decision.label) {
						return fmt.Errorf("internal: viewing-case element count exceeded first case")
					}
					elementIndex++
				}
			}
			f.scope = excluded(n, f.scope)
			if n.Type == html.TextNode && f.scope == "" {
				st := f.style
				colour := evaluateColour(st[color], r.layers, r.matches)
				decision := decideVisibility(&st, f.presentationState, &colour)
				if first {
					r.results.textLabels = append(r.results.textLabels, decision.label)
					r.results.textReasons = append(r.results.textReasons, decision.reasons)
					text := Text{FontSize: st[fontSize].Text, EffectiveOpacity: f.alpha, Node: n}
					if r.retainInspection {
						text.inspection = &textInspection{style: st, colour: colour.inspection()}
					}
					r.results.text = append(r.results.text, text)
				} else if !mergeViewingCaseLabel(r.results.textLabels, textIndex, decision.label) {
					return fmt.Errorf("internal: viewing-case text count exceeded first case")
				}
				textIndex++
			}
		}
		if f.next == nil {
			if f.n.Type == html.ElementNode {
				r.layers = r.layers[:len(r.layers)-1]
			}
			r.frames = r.frames[:len(r.frames)-1]
			continue
		}
		child := f.next
		f.next = child.NextSibling
		r.frames = append(r.frames, viewingCaseFrame{
			n: child, style: f.style, scope: f.scope, presentationState: f.presentationState,
			vars: f.vars, selectorPath: f.selectorPath,
		})
	}
	if !first && (textIndex != len(r.results.textLabels) || elementIndex != len(r.results.elementLabels)) {
		return fmt.Errorf("internal: viewing-case traversal shape changed: text %d/%d, elements %d/%d", textIndex, len(r.results.textLabels), elementIndex, len(r.results.elementLabels))
	}
	return nil
}

func (p processor) process(input []byte) (Document, error) {
	document, err := p.parseDocument(input)
	if err != nil {
		return Document{}, err
	}
	root := document.root
	s := &document.styles
	in := Document{
		Root:     root,
		Text:     make([]Text, 0, document.extractableTextCount),
		Elements: make([]Element, 0, document.extractableElementCount),
		Usage: ResourceUsage{
			InputBytes: len(input), Nodes: max(document.nodeCount, document.lexical.nodes),
			TextNodes:  max(document.textCount, document.lexical.textNodes),
			Attributes: max(document.attributeCount, document.lexical.attributes),
			Depth:      max(document.treeDepth, document.lexical.depth), CSSDepth: s.conditionDepth,
			Rules: s.rulesSeen, Selectors: s.selectors, CSSLimitExceeded: s.cascadeIncomplete,
		},
		UnresolvedStylesheet: s.unresolvedStylesheet,
	}
	s.buildSelectorIndex(document.treeDepth, document.nodeCount)
	cap := p.Limits.MediaCases
	if cap < 1 || cap > MaxViewingCases {
		cap = MaxViewingCases
	}
	widths, fallback := s.viewingCases(cap)
	in.Usage.MediaCases = len(widths)
	s.runtime.cacheMatches = len(widths) > 1
	exprLimit := p.Limits.ExpressionWork
	if exprLimit < 1 {
		exprLimit = 10000000
	}
	budget := expressionBudget{remaining: exprLimit}
	matches := matchBudget{limit: p.Limits.MatchWork, used: s.planningWork}
	results := viewingCaseResults{
		text:           in.Text,
		elements:       in.Elements,
		textLabels:     make([]visibilityLabel, 0, document.extractableTextCount),
		elementLabels:  make([]visibilityLabel, 0, document.extractableElementCount),
		textReasons:    make([]concealmentReason, 0, document.extractableTextCount),
		elementReasons: make([]concealmentReason, 0, document.extractableElementCount),
	}
	runner := viewingCaseRunner{
		document: &document, styles: s, retainInspection: p.retainInspection,
		matches: &matches, expressions: &budget, results: &results,
		frames: make([]viewingCaseFrame, 0, document.treeDepth+1),
		layers: make([]paintLayer, 0, document.treeDepth),
	}
	for caseIndex, width := range widths {
		if err := runner.run(width, fallback, caseIndex == 0); err != nil {
			return in, err
		}
		if matches.exhausted && caseIndex+1 < len(widths) {
			// All later cases would receive unresolved styles. Mark their
			// contribution directly instead of repeatedly traversing the DOM.
			unknown := labelUnknown
			for i := range results.textLabels {
				results.textLabels[i] |= unknown
			}
			for i := range results.elementLabels {
				results.elementLabels[i] |= unknown
			}
			break
		}
	}
	for i, bits := range results.textLabels {
		label := aggregateLabel(bits)
		results.text[i].Label = label
		if label == "concealed" {
			results.text[i].ConcealmentReasons = concealmentReasonStrings(results.textReasons[i])
		}
	}
	in.Text = results.text
	for i, bits := range results.elementLabels {
		results.elements[i].Label = aggregateLabel(bits)
		if results.elements[i].Label == "concealed" {
			results.elements[i].ConcealmentReasons = concealmentReasonStrings(results.elementReasons[i])
		}
	}
	in.Elements = results.elements
	in.Usage.MatchWork = matches.used
	in.Usage.MatchWorkExhausted = matches.exhausted || s.workIncomplete
	in.Usage.ExpressionWork = exprLimit - budget.remaining
	if in.Usage.ExpressionWork > exprLimit {
		in.Usage.ExpressionWork = exprLimit
	}
	in.Usage.ExpressionWorkExhausted = budget.exhausted
	return in, nil
}

func mergeViewingCaseLabel(labels []visibilityLabel, index int, bit visibilityLabel) bool {
	if index < 0 || index >= len(labels) {
		return false
	}
	labels[index] |= bit
	return true
}
