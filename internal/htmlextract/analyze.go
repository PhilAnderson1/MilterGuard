package htmlextract

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type processor struct {
	Limits           Limits
	retainInspection bool // tests only; production results retain compact decisions
	shouldStop       func() bool
	cpu              *cpuGuard
	memory           *resourceguard.Memory
}

var errStopped = errors.New("HTML processing stopped")

// IsStopped reports whether analysis ended because the caller's external
// resource guard requested the bounded fallback.
func IsStopped(err error) bool { return errors.Is(err, errStopped) }

// Analyze parses and resolves a document once and retains the tree alongside
// the per-text-node presentation decisions used by message extraction.
func Analyze(input []byte, limits Limits) (Document, error) {
	p := processor{Limits: limits}
	return p.process(input)
}

// AnalyzeWithStop is Analyze with a cooperative stop check. The callback is
// sampled inside the forked parsers as well as between bounded analysis phases
// and during long traversals.
func AnalyzeWithStop(input []byte, limits Limits, shouldStop func() bool) (Document, error) {
	p := processor{Limits: limits, shouldStop: shouldStop}
	return p.process(input)
}

func (p processor) stopped() bool { return p.shouldStop != nil && p.shouldStop() }

type viewingCaseResults struct {
	text           []Text
	elements       []Element
	textLabels     []visibilityLabel
	elementLabels  []visibilityLabel
	textReasons    []concealmentReason
	elementReasons []concealmentReason
}

type viewingCaseFrame struct {
	n, next    *html.Node
	entered    bool
	styleIndex int
	// colourContextChanged records whether this element's paint layer changed
	// colour composition, so leaving it invalidates the one-entry memo too.
	colourContextChanged bool
	scope                nodeScope
	presentationState
	vars         *variableScope
	ancestorKeys selectorAncestorActivation
}

type colourMemo struct {
	foreground Value
	result     colourResult
	generation uint64
	valid      bool
}

type viewingCase struct {
	width      float64
	fallback   bool
	initialize bool
}

type viewingCaseRunner struct {
	document         *parsedDocument
	styles           *sheet
	retainInspection bool
	work             *cpuGuard
	results          *viewingCaseResults
	frames           []viewingCaseFrame
	styleStack       []Style
	layers           []paintLayer
	layerGeneration  uint64
	colourMemo       colourMemo
	shouldStop       func() bool
	visited          int
}

func (r *viewingCaseRunner) evaluateColour(foreground Value) colourResult {
	if !chargeColourEvaluation(foreground, r.layers, r.work) {
		return colourResult{uncertainty: "style-analysis CPU limit"}
	}
	if r.colourMemo.valid && r.colourMemo.generation == r.layerGeneration && r.colourMemo.foreground == foreground {
		return r.colourMemo.result
	}
	result := evaluateColourUncharged(foreground, r.layers)
	r.colourMemo = colourMemo{foreground: foreground, result: result, generation: r.layerGeneration, valid: true}
	return result
}

func (r *viewingCaseRunner) enterPaintLayer(n *html.Node, paint paintLayer) bool {
	r.layers = append(r.layers, paint)
	changed := !paint.colourNeutral()
	if n.Namespace == "" && n.Data == "body" && n.Parent != nil && n.Parent.Namespace == "" && n.Parent.Data == "html" {
		// Canvas propagation can mutate both the root and body layers. Treat the
		// body boundary conservatively even when its original layer was neutral.
		propagateHTMLBodyBackground(r.layers)
		changed = true
	}
	if changed {
		r.layerGeneration++
	}
	return changed
}

func (r *viewingCaseRunner) leavePaintLayer(changed bool) {
	r.layers = r.layers[:len(r.layers)-1]
	if changed {
		r.layerGeneration++
	}
}

func (r *viewingCaseRunner) run(c viewingCase) error {
	textIndex, elementIndex := 0, 0
	media := mediaEvaluation{width: c.width, fallback: c.fallback}
	r.frames = r.frames[:0]
	r.styleStack = r.styleStack[:0]
	r.styleStack = append(r.styleStack, initial())
	r.frames = append(r.frames, viewingCaseFrame{n: r.document.root, presentationState: initialPresentationState()})
	rootStyle := initial()
	r.layers = r.layers[:0]
	r.layerGeneration = 0
	r.colourMemo.valid = false
	r.styles.runtime.activeAncestors.enabled = r.styles.hasAncestorSelectorIndex()
	if r.styles.runtime.activeAncestors.enabled {
		r.styles.runtime.activeAncestors.reset(r.styles.index.count)
	}
	defer func() { r.styles.runtime.activeAncestors.enabled = false }()
	msoRevealedDepth := 0
	for len(r.frames) > 0 {
		r.visited++
		if r.visited&255 == 0 && r.shouldStop != nil && r.shouldStop() {
			return errStopped
		}
		f := &r.frames[len(r.frames)-1]
		n := f.n
		if !f.entered {
			f.entered = true
			f.next = n.FirstChild
			if n.Type == html.CommentNode && (f.scope == scopeActive || f.scope == scopeHead) {
				switch msoDownlevelRevealedMarker(n.Data) {
				case msoRevealedStart:
					msoRevealedDepth++
				case msoRevealedEnd:
					if msoRevealedDepth > 0 {
						msoRevealedDepth--
					}
				}
			}
			if n.Type == html.ElementNode {
				var prepared elementPreparation
				if len(r.document.elements) != 0 {
					prepared = r.document.elements[n]
				}
				selectorContext := selectorMatchContext{elements: r.document.elements}
				parentStyle := &r.styleStack[f.styleIndex]
				var resolved elementStyleResult
				if prepared.inlineIncomplete {
					// A malformed style attribute can affect this element and its
					// descendants, but cannot alter the cascade elsewhere in the
					// document. Keep that uncertainty local instead of abandoning all
					// stylesheet analysis.
					resolved = elementStyleResult{style: unresolvedStyle(), variables: f.vars}
				} else {
					resolved = r.styles.elementStyle(n, parentStyle, &rootStyle, f.vars, prepared.legacy, prepared.inline, &media, selectorContext, r.work)
				}
				if r.styles.stopped {
					return errStopped
				}
				r.styleStack = append(r.styleStack, resolved.style)
				f.styleIndex = len(r.styleStack) - 1
				style := &r.styleStack[f.styleIndex]
				f.vars = resolved.variables
				clip := emptyClip(style, n, resolved.displayDeclared)
				wasClipped := f.clipped
				f.clipped = f.clipped || clip.empty
				if clip.empty {
					if clip.clientDependent && !wasClipped {
						f.clientDependentReasons |= reasonEmptyClip
					} else if !clip.clientDependent {
						f.clientDependentReasons &^= reasonEmptyClip
					}
				}
				f.clipKnown = f.clipKnown && clip.known
				f.colourContextChanged = r.enterPaintLayer(n, layerWithClipOverride(style, clip.inlineUncertain))
				if n.Data == "html" {
					rootStyle = *style
				}
				f.displayKnown = f.displayKnown && style[display].Known
				if style[display].Known && style[display].Text == "none" {
					f.none = true
				}
				cv := style[contentVisibility]
				if cv.Known && cv.Text == "hidden" {
					f.contentHidden = true
					f.clientDependentReasons |= reasonContentVisibility
				}
				f.contentKnown = f.contentKnown && cv.Known
				mh := style[msoHide]
				if mh.Known && mh.Text == "all" {
					f.msoHidden = true
				}
				f.msoKnown = f.msoKnown && mh.Known
				if f.clipsDescendantsX && resolved.offsetWithinClippedAncestorX ||
					f.clipsDescendantsY && resolved.offsetWithinClippedAncestorY {
					// Relative and positioned descendants can be shifted wholly outside
					// an ancestor's clipping box even when the standalone offset is below
					// the coarse off-screen threshold.
					f.layoutUncertain = true
				}
				f.layoutUncertain = f.layoutUncertain || resolved.layoutUncertain
				f.clipsDescendantsX = f.clipsDescendantsX || resolved.clipsDescendantsX
				f.clipsDescendantsY = f.clipsDescendantsY || resolved.clipsDescendantsY
				f.animationUncertain = f.animationUncertain || resolved.animationActive
				f.alternateColourSchemeReasons |= resolved.alternateColourSchemeReasons
				a := style[opacity]
				if a.Known && a.Number == 0 {
					f.alpha = 0
					f.alphaKnown = true
				} else if !(f.alphaKnown && f.alpha == 0) {
					f.alpha *= a.Number
					f.alphaKnown = f.alphaKnown && a.Known
				}
				if f.alphaKnown && f.alpha <= .01+1e-14 {
					// The colour evaluator applies group opacity before measuring
					// contrast, so opacity can also manufacture a colour-distance
					// concealment reason. Word-based Outlook ignores opacity; mark
					// both conclusions as client-dependent so the derived colour
					// result cannot accidentally make the decision authoritative.
					f.clientDependentReasons |= reasonOpacity | reasonColour
				}
				if f.scope == scopeActive && (n.Data == "img" || n.Data == "input") {
					elementState := f.presentationState
					if msoRevealedDepth > 0 {
						// Word-based Outlook excludes downlevel-revealed regions.
						elementState.layoutUncertain = true
					}
					if resolved.elementGeometryConcealed {
						elementState.clipped = true
					}
					if !elementPaintKnown(style) {
						elementState.layoutUncertain = true
					}
					if hiddenInput(n) {
						elementState.none = true
					}
					decision := decideVisibility(style, elementState, nil)
					if c.initialize {
						r.results.elementLabels = append(r.results.elementLabels, decision.label)
						r.results.elementReasons = append(r.results.elementReasons, decision.reasons)
						r.results.elements = append(r.results.elements, Element{Node: n, EffectiveOpacity: f.alpha})
					} else if !mergeViewingCaseLabel(r.results.elementLabels, elementIndex, decision.label) {
						return fmt.Errorf("internal: viewing-case element count exceeded first case")
					} else {
						r.results.elementReasons[elementIndex] |= decision.reasons
						if decision.reasons&reasonOpacity != 0 && f.alpha < r.results.elements[elementIndex].EffectiveOpacity {
							r.results.elements[elementIndex].EffectiveOpacity = f.alpha
						}
					}
					elementIndex++
				}
				if n.Namespace == "" && n.Data == "noscript" {
					// Email clients disagree on whether noscript fallback content is
					// rendered or removed during sanitization. Retain the subtree for
					// analysis, but do not claim that otherwise readable content is
					// definitely visible to the recipient.
					f.layoutUncertain = true
				}
				if !r.work.stopped && prepared.hasElementChild {
					activation, complete := r.styles.activateAncestorBuckets(n, r.work)
					if complete {
						f.ancestorKeys = activation
					}
				}
			}
			f.scope = nodeContentScope(n, f.scope)
			if n.Type == html.TextNode && f.scope == scopeActive {
				style := &r.styleStack[f.styleIndex]
				colour := r.evaluateColour(style[color])
				textState := f.presentationState
				if msoRevealedDepth > 0 {
					// Content readable in ordinary clients but excluded by Outlook
					// cannot be called definitely visible. Independently concealed
					// content remains concealed in every client.
					textState.layoutUncertain = true
				}
				decision := decideVisibility(style, textState, &colour)
				if c.initialize {
					r.results.textLabels = append(r.results.textLabels, decision.label)
					r.results.textReasons = append(r.results.textReasons, decision.reasons)
					text := Text{FontSize: style[fontSize].Text, EffectiveOpacity: f.alpha, Node: n}
					if r.retainInspection {
						text.inspection = &textInspection{style: *style, colour: colour.inspection()}
					}
					r.results.text = append(r.results.text, text)
				} else if !mergeViewingCaseLabel(r.results.textLabels, textIndex, decision.label) {
					return fmt.Errorf("internal: viewing-case text count exceeded first case")
				} else {
					r.results.textReasons[textIndex] |= decision.reasons
					if decision.reasons&reasonOpacity != 0 && f.alpha < r.results.text[textIndex].EffectiveOpacity {
						r.results.text[textIndex].EffectiveOpacity = f.alpha
					}
					if decision.reasons&reasonFontSize != 0 {
						r.results.text[textIndex].FontSize = style[fontSize].Text
					}
				}
				textIndex++
			}
		}
		if f.next == nil {
			if f.n.Type == html.ElementNode {
				r.styles.deactivateAncestorBuckets(f.ancestorKeys)
				r.leavePaintLayer(f.colourContextChanged)
				r.styleStack = r.styleStack[:len(r.styleStack)-1]
			}
			r.frames = r.frames[:len(r.frames)-1]
			continue
		}
		child := f.next
		f.next = child.NextSibling
		r.frames = append(r.frames, viewingCaseFrame{
			n: child, styleIndex: f.styleIndex, scope: f.scope, presentationState: f.presentationState,
			vars: f.vars,
		})
	}
	if !c.initialize && (textIndex != len(r.results.textLabels) || elementIndex != len(r.results.elementLabels)) {
		return fmt.Errorf("internal: viewing-case traversal shape changed: text %d/%d, elements %d/%d", textIndex, len(r.results.textLabels), elementIndex, len(r.results.elementLabels))
	}
	return nil
}

func (p processor) process(input []byte) (result Document, resultErr error) {
	if p.cpu == nil {
		p.cpu = &cpuGuard{shouldStop: p.shouldStop}
	}
	if p.memory == nil {
		p.memory = resourceguard.NewMemory(p.Limits.MemoryBytes)
	}
	p.cpu.memory = p.memory
	if p.stopped() {
		return Document{}, errStopped
	}
	document, err := p.parseDocument(input)
	if err != nil {
		if p.memory.Exhausted() {
			err = fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
		}
		return Document{
			Usage:                parsedResourceUsage(len(input), &document),
			UnresolvedStylesheet: document.styles.unresolvedStylesheet,
		}, err
	}
	root := document.root
	s := &document.styles
	in := Document{
		Root:                 root,
		Usage:                parsedResourceUsage(len(input), &document),
		UnresolvedStylesheet: s.unresolvedStylesheet,
	}
	// Parsing establishes the document and its shared memory counter, but later
	// selector indexing and viewing-case analysis also reserve from that counter.
	// Refresh usage after the return values have been assigned so every exit path
	// reports the complete per-part charge to the message-wide budget.
	defer func() {
		result.Usage = parsedResourceUsage(len(input), &document)
	}()
	if p.stopped() {
		return in, errStopped
	}
	s.buildSelectorIndex()
	if p.memory.Exhausted() {
		return in, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
	}
	if p.stopped() {
		return in, errStopped
	}
	widths, fallback := s.viewingCases()
	s.runtime.cacheMatches = len(widths) > 1
	guard := p.cpu
	resultBytes := int64(document.extractableTextCount)*(int64(unsafe.Sizeof(Text{}))+int64(unsafe.Sizeof(visibilityLabel(0)))+int64(unsafe.Sizeof(concealmentReason(0)))) +
		int64(document.extractableElementCount)*(int64(unsafe.Sizeof(Element{}))+int64(unsafe.Sizeof(visibilityLabel(0)))+int64(unsafe.Sizeof(concealmentReason(0))))
	frameBytes := int64(document.treeDepth+1) * (int64(unsafe.Sizeof(viewingCaseFrame{})) + int64(unsafe.Sizeof(Style{})) + int64(unsafe.Sizeof(paintLayer{})))
	if !p.memory.Reserve(resultBytes + frameBytes) {
		return in, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
	}
	results := viewingCaseResults{
		text:           make([]Text, 0, document.extractableTextCount),
		elements:       make([]Element, 0, document.extractableElementCount),
		textLabels:     make([]visibilityLabel, 0, document.extractableTextCount),
		elementLabels:  make([]visibilityLabel, 0, document.extractableElementCount),
		textReasons:    make([]concealmentReason, 0, document.extractableTextCount),
		elementReasons: make([]concealmentReason, 0, document.extractableElementCount),
	}
	runner := viewingCaseRunner{
		document: &document, styles: s, retainInspection: p.retainInspection,
		work: guard, results: &results,
		frames:     make([]viewingCaseFrame, 0, document.treeDepth+1),
		styleStack: make([]Style, 0, document.treeDepth+1),
		layers:     make([]paintLayer, 0, document.treeDepth),
		shouldStop: p.shouldStop,
	}
	for caseIndex, width := range widths {
		if p.stopped() {
			return in, errStopped
		}
		if err := runner.run(viewingCase{width: width, fallback: fallback, initialize: caseIndex == 0}); err != nil {
			if p.memory.Exhausted() {
				err = fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
			}
			return in, err
		}
	}
	if s.unsupportedNesting || document.msoOrderUncertain {
		// Nested selectors can target descendants, siblings, or ancestors of
		// their parent match. Foster parenting can likewise move source text
		// outside MSO conditional markers retained below a table. In either case,
		// no element in the document is provably outside the uncertain region.
		for i := range results.textLabels {
			results.textLabels[i] |= labelUnknown
		}
		for i := range results.elementLabels {
			results.elementLabels[i] |= labelUnknown
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
	if p.memory.Exhausted() {
		return in, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
	}
	return in, nil
}

func parsedResourceUsage(inputBytes int, document *parsedDocument) ResourceUsage {
	s := &document.styles
	return ResourceUsage{
		InputBytes:                 inputBytes,
		CSSBytes:                   s.cssBytes,
		MemoryBytes:                memoryUsed(document.memory),
		UnsupportedColourFunctions: s.unsupportedColours,

		CSSLimitExceeded: s.cascadeIncomplete,
	}
}

func memoryUsed(memory *resourceguard.Memory) int64 {
	if memory == nil {
		return 0
	}
	return memory.Used()
}

func mergeViewingCaseLabel(labels []visibilityLabel, index int, bit visibilityLabel) bool {
	if index < 0 || index >= len(labels) {
		return false
	}
	labels[index] |= bit
	return true
}
