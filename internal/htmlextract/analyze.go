package htmlextract

import (
	"fmt"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type processor struct {
	usage            *AnalysisUsage
	Limits           Limits
	retainInspection bool // tests only; production results retain compact decisions
	shouldStop       func()
	cpu              *cpuGuard
	memory           *resourceguard.Memory
}

// Analyze parses and resolves a document once and retains the tree alongside
// the per-text-node presentation decisions used by message extraction.
// The caller must establish an extraction-stage termination.Recover boundary:
// required memory failures unwind even without a supplied checkpoint. Returned
// errors describe ordinary parse/structural failures, not resource exhaustion.
func Analyze(input []byte, limits Limits) (Document, error) {
	p := processor{Limits: limits}
	return p.process(input)
}

// AnalyzeWithStop is Analyze with a cooperative stop check. The callback is
// sampled inside the forked parsers as well as between bounded analysis phases
// and during long traversals. Like Analyze, this requires a caller-managed
// termination.Recover boundary for memory, CPU and cancellation signals.
func AnalyzeWithStop(input []byte, limits Limits, shouldStop func()) (Document, error) {
	p := processor{Limits: limits, shouldStop: shouldStop}
	return p.process(input)
}

// AnalyzeControlled participates in the caller's extraction-stage boundary.
// Required allocation failures and the supplied checkpoint unwind to that
// boundary. Usage is published even when analysis does not return.
func AnalyzeControlled(input []byte, limits Limits, check func(), usage *AnalysisUsage) (Document, error) {
	p := processor{Limits: limits, shouldStop: check, memory: resourceguard.NewMemory(limits.MemoryBytes), usage: usage}
	return p.process(input)
}

// AnalyzeControlledString is AnalyzeControlled for a string whose byte view
// must be owned by the analyser. The conversion is charged to the same child
// ledger as parsing, including when conversion itself exhausts that ledger.
func AnalyzeControlledString(input string, limits Limits, check func(), usage *AnalysisUsage) (Document, error) {
	if err := limits.validate(); err != nil {
		return Document{}, err
	}
	if len(input) > limits.InputBytes {
		return Document{}, fmt.Errorf("limit: input bytes > %d", limits.InputBytes)
	}
	memory := resourceguard.NewMemory(limits.MemoryBytes)
	converted := false
	if usage != nil {
		defer func() {
			if !converted {
				*usage = AnalysisUsage{
					ResourceUsage: ResourceUsage{
						InputBytes:  len(input),
						MemoryBytes: memory.Charged(),
					},
					MemoryLimitExceeded: memory.Exhausted(),
				}
			}
		}()
	}
	owned := resourceguard.StringBytes(memory, input, false, check)
	converted = true
	p := processor{Limits: limits, shouldStop: check, memory: memory, usage: usage}
	return p.process(owned)
}

func (p processor) checkpoint() {
	if p.shouldStop != nil {
		p.shouldStop()
	}
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
	n, next     *html.Node
	entered     bool
	summarySeen bool
	styleIndex  int
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
	rootStyle        Style
	shouldStop       func()
	visited          int
}

func (r *viewingCaseRunner) evaluateColour(foreground Value) colourResult {
	r.work.check()

	if r.colourMemo.valid && r.colourMemo.generation == r.layerGeneration && r.colourMemo.foreground == foreground {
		return r.colourMemo.result
	}

	result := evaluateColour(foreground, r.layers, r.work)

	if foreground.Text == "link-default" && result.known {
		visited := foreground
		visited.RGBA = RGBA{R: 85.0 / 255, G: 26.0 / 255, B: 139.0 / 255, A: 1}
		alternate := evaluateColour(visited, r.layers, r.work)

		if !alternate.known || colourConcealed(result.distance) != colourConcealed(alternate.distance) {
			result = colourResult{uncertainty: "visited link colour"}
		}
	}

	r.colourMemo = colourMemo{foreground: foreground, result: result, generation: r.layerGeneration, valid: true}
	return result
}

func (r *viewingCaseRunner) enterPaintLayer(n *html.Node, paint paintLayer) bool {
	r.layers = append(r.layers, paint)
	changed := !paint.colourNeutral()
	if len(r.layers) > 1 {
		parent := r.layers[len(r.layers)-2]
		changed = changed || parent.glyphKnown != paint.glyphKnown || parent.shadowKnown != paint.shadowKnown
	}
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

func (r *viewingCaseRunner) recordElement(n *html.Node, f *viewingCaseFrame, style *Style, resolved elementStyleResult, msoRevealedDepth int, elementIndex *int, initialize bool) error {
	if f.scope != scopeActive || n.Data != "img" && n.Data != "input" {
		return nil
	}
	elementState := f.presentationState
	if msoRevealedDepth > 0 {
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
	var colour *colourResult
	if n.Data == "input" {
		switch asciiLowerWithBudget(trimCSSWhitespace(attr(n, "type")), r.work) {
		case "button", "submit", "reset":
			result := r.evaluateColour(style[color])
			colour = &result
		}
	}
	decision := decideVisibility(style, elementState, colour)
	if initialize {
		r.results.elementLabels = append(r.results.elementLabels, decision.label)
		r.results.elementReasons = append(r.results.elementReasons, decision.reasons)
		r.results.elements = append(r.results.elements, Element{Node: n, EffectiveOpacity: f.alpha, FontSize: style[fontSize].Text})
	} else if !mergeViewingCaseLabel(r.results.elementLabels, *elementIndex, decision.label) {
		return fmt.Errorf("internal: viewing-case element count exceeded first case")
	} else {
		r.results.elementReasons[*elementIndex] |= decision.reasons
		if decision.reasons&reasonFontSize != 0 {
			r.results.elements[*elementIndex].FontSize = style[fontSize].Text
		}
		if decision.reasons&reasonOpacity != 0 && f.alpha < r.results.elements[*elementIndex].EffectiveOpacity {
			r.results.elements[*elementIndex].EffectiveOpacity = f.alpha
		}
	}
	*elementIndex++
	return nil
}

func (r *viewingCaseRunner) enterElement(n *html.Node, f *viewingCaseFrame, rootStyle *Style, media *mediaEvaluation, msoRevealedDepth int, elementIndex *int, initialize bool) error {
	var prepared elementPreparation

	if len(r.document.elements.View()) != 0 {
		prepared = r.document.elements.View()[n]
	}

	parentStyle := &r.styleStack[f.styleIndex]
	var resolved elementStyleResult

	if prepared.inlineIncomplete {
		resolved = elementStyleResult{style: unresolvedStyle(), variables: f.vars}
	} else {
		resolved = r.styles.elementStyle(n, parentStyle, rootStyle, f.vars, prepared.legacy, prepared.inline, media, selectorMatchContext{elements: r.document.elements.View()}, r.work)
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
		*rootStyle = *style
	}

	f.displayKnown = f.displayKnown && style[display].Known

	if style[display].Known && style[display].Text == "none" {
		f.none = true
	}

	contentVisibilityValue := style[contentVisibility]

	if contentVisibilityValue.Known && contentVisibilityValue.Text == "hidden" {
		f.contentHidden = true
		f.clientDependentReasons |= reasonContentVisibility
	}

	f.contentKnown = f.contentKnown && contentVisibilityValue.Known
	msoHideValue := style[msoHide]

	if msoHideValue.Known && msoHideValue.Text == "all" {
		f.msoHidden = true
	}

	f.msoKnown = f.msoKnown && msoHideValue.Known

	if f.clipsDescendantsX && resolved.offsetWithinClippedAncestorX || f.clipsDescendantsY && resolved.offsetWithinClippedAncestorY {
		f.layoutUncertain = true
	}

	f.layoutUncertain = f.layoutUncertain || resolved.layoutUncertain || !style[translate].Known || !style[rotate].Known || !style[scale].Known || style[display].Text == "table-column" || style[display].Text == "table-column-group"
	f.clipsDescendantsX = f.clipsDescendantsX || resolved.clipsDescendantsX
	f.clipsDescendantsY = f.clipsDescendantsY || resolved.clipsDescendantsY
	for i, set := range resolved.textLayoutSet {
		if set {
			f.textLayout[i] = resolved.textLayout[i]
		}
	}
	f.fontScaleUncertain = f.fontScaleUncertain || resolved.fontScaleUncertain || !style[transform].Known || !style[scale].Known
	f.stableDisplayNone = f.stableDisplayNone || resolved.stableDisplayNone
	f.animationUncertain = f.animationUncertain || resolved.animationActive
	f.alternateColourSchemeReasons |= resolved.alternateColourSchemeReasons
	opacityValue := style[opacity]

	if opacityValue.Known && opacityValue.Number == 0 {
		f.alpha = 0
		f.alphaKnown = true
	} else if !(f.alphaKnown && f.alpha == 0) {
		f.alpha *= opacityValue.Number
		f.alphaKnown = f.alphaKnown && opacityValue.Known
	}

	if f.alphaKnown && f.alpha <= .01+1e-14 {
		f.clientDependentReasons |= reasonOpacity | reasonColour
	}

	if err := r.recordElement(n, f, style, resolved, msoRevealedDepth, elementIndex, initialize); err != nil {
		return err
	}

	if n.Namespace == "" && (n.Data == "noscript" || n.Data == "canvas" || n.Data == "object") {
		f.layoutUncertain = true
	}

	if prepared.hasElementChild {
		activation := r.styles.activateAncestorBuckets(n, r.work)

		f.ancestorKeys = activation
	}

	return nil
}

func (r *viewingCaseRunner) recordText(n *html.Node, f *viewingCaseFrame, msoRevealedDepth int, textIndex *int, initialize bool) error {
	style := &r.styleStack[f.styleIndex]
	var colour colourResult

	// Stable display:none already determines the annotation. Only diagnostic
	// inspection needs additional contrast evidence for this text.
	if !f.stableDisplayNone || r.retainInspection {
		colour = r.evaluateColour(style[color])
	}

	textState := f.presentationState

	if msoRevealedDepth > 0 {
		textState.layoutUncertain = true
	}

	decision := decideVisibility(style, textState, &colour)

	if initialize {
		r.results.textLabels = append(r.results.textLabels, decision.label)
		r.results.textReasons = append(r.results.textReasons, decision.reasons)
		text := Text{FontSize: style[fontSize].Text, EffectiveOpacity: f.alpha, Node: n}

		if r.retainInspection {
			text.inspection = &textInspection{style: *style, colour: colour.inspection()}
		}

		r.results.text = append(r.results.text, text)
	} else if !mergeViewingCaseLabel(r.results.textLabels, *textIndex, decision.label) {
		return fmt.Errorf("internal: viewing-case text count exceeded first case")
	} else {
		r.results.textReasons[*textIndex] |= decision.reasons

		if decision.reasons&reasonOpacity != 0 && f.alpha < r.results.text[*textIndex].EffectiveOpacity {
			r.results.text[*textIndex].EffectiveOpacity = f.alpha
		}

		if decision.reasons&reasonFontSize != 0 {
			r.results.text[*textIndex].FontSize = style[fontSize].Text
		}
	}

	*textIndex++
	return nil
}

func (r *viewingCaseRunner) leaveElement(f *viewingCaseFrame) {
	r.styles.deactivateAncestorBuckets(f.ancestorKeys)
	r.leavePaintLayer(f.colourContextChanged)
	r.styleStack = r.styleStack[:len(r.styleStack)-1]
}

func (r *viewingCaseRunner) run(c viewingCase) error {
	textIndex, elementIndex := 0, 0
	media := mediaEvaluation{width: c.width, fallback: c.fallback}
	r.frames = r.frames[:0]
	r.styleStack = append(r.styleStack[:0], initial())
	r.frames = append(r.frames, viewingCaseFrame{n: r.document.root, presentationState: initialPresentationState()})
	r.rootStyle = initial()
	r.layers = r.layers[:0]
	r.layerGeneration = 0
	r.colourMemo.valid = false
	r.styles.runtime.activeAncestors.enabled = r.styles.hasAncestorSelectorIndex()

	if r.styles.runtime.activeAncestors.enabled {
		r.styles.runtime.activeAncestors.reset(r.styles.index.count, r.styles.memory)
	}

	defer func() { r.styles.runtime.activeAncestors.enabled = false }()
	mso := msoRevealedState{}
	for len(r.frames) > 0 {
		r.visited++

		if r.visited&255 == 0 && r.shouldStop != nil {
			r.shouldStop()
		}

		frame := &r.frames[len(r.frames)-1]
		node := frame.n

		// Preserve the parsed DOM for selectors, but presentation inside inert
		// containers cannot contribute extraction results. No stack was entered.
		if !frame.entered && nodeContentScope(node, frame.scope) == scopeInert {
			r.frames = r.frames[:len(r.frames)-1]
			continue
		}

		if !frame.entered {
			frame.entered = true
			frame.next = node.FirstChild

			if node.Type == html.CommentNode && (frame.scope == scopeActive || frame.scope == scopeHead) {
				mso.update(msoDownlevelRevealedMarker(node.Data), r.work)
			}

			if node.Type == html.ElementNode {

				if err := r.enterElement(node, frame, &r.rootStyle, &media, mso.uncertain, &elementIndex, c.initialize); err != nil {
					return err
				}

			}

			frame.scope = nodeContentScope(node, frame.scope)

			if node.Type == html.TextNode && frame.scope == scopeActive {

				if err := r.recordText(node, frame, mso.uncertain, &textIndex, c.initialize); err != nil {
					return err
				}

			}
		}

		if frame.next == nil {
			if frame.n.Type == html.ElementNode {
				r.leaveElement(frame)
			}

			r.frames = r.frames[:len(r.frames)-1]
			continue
		}

		child := frame.next
		frame.next = child.NextSibling
		childState := frame.presentationState

		if node.Namespace == "" && node.Data == "details" && !hasAttr(node, "open") {
			// Only the first summary escapes closed disclosure content. Track it
			// during the existing walk instead of rescanning siblings per child.
			firstSummary := child.Type == html.ElementNode && child.Namespace == "" && child.Data == "summary" && !frame.summarySeen
			frame.summarySeen = frame.summarySeen || firstSummary
			childState.layoutUncertain = childState.layoutUncertain || !firstSummary
		}

		r.frames = append(r.frames, viewingCaseFrame{
			n: child, styleIndex: frame.styleIndex, scope: frame.scope, presentationState: childState,
			vars: frame.vars,
		})
	}

	if !c.initialize && (textIndex != len(r.results.textLabels) || elementIndex != len(r.results.elementLabels)) {
		return fmt.Errorf("internal: viewing-case traversal shape changed: text %d/%d, elements %d/%d", textIndex, len(r.results.textLabels), elementIndex, len(r.results.elementLabels))
	}

	return nil
}

func (p processor) process(input []byte) (result Document, resultErr error) {

	if err := p.Limits.validate(); err != nil {
		return Document{}, err
	}

	if p.memory == nil {
		p.memory = resourceguard.NewMemory(p.Limits.MemoryBytes)
	}

	parseReturned := false
	if p.usage != nil {
		*p.usage = AnalysisUsage{}
		defer func() {
			// parseDocument publishes its CSS state directly if it unwinds.
			// Once it returns, result.Usage is authoritative and is refreshed
			// by the later analysis-phase defer.
			if parseReturned {
				p.usage.ResourceUsage = result.Usage
			}
			p.usage.InputBytes = len(input)
			p.usage.MemoryBytes = p.memory.Charged()
			p.usage.MemoryLimitExceeded = p.memory.Exhausted()
		}()
	}

	if p.cpu == nil {
		p.cpu = resourceguard.New(p.memory, cpuGuard{shouldStop: p.shouldStop, memory: p.memory, sampler: resourceguard.NewStopSampler(256, p.shouldStop)})
	}

	p.cpu.memory = p.memory
	// Parsers and traversals share one checkpoint callback.
	p.shouldStop = resourceguard.BindCheckpoint(p.memory, p.cpu, stopCPU)

	p.checkpoint()

	document, err := p.parseDocument(input)
	parseReturned = true

	if err != nil {
		return Document{
			Usage:                parsedResourceUsage(len(input), document),
			UnresolvedStylesheet: document.styles.unresolvedStylesheet,
		}, err
	}

	root := document.root
	s := &document.styles
	in := Document{
		Root:                 root,
		Usage:                parsedResourceUsage(len(input), document),
		UnresolvedStylesheet: s.unresolvedStylesheet,
	}
	// Parsing establishes the document and its shared memory counter, but later
	// selector indexing and viewing-case analysis also reserve from that counter.
	// Refresh usage after the return values have been assigned so every exit path
	// reports the complete per-part charge to the message-wide budget.
	defer func() {
		result.Usage = parsedResourceUsage(len(input), document)
	}()

	p.checkpoint()

	s.buildSelectorIndex()

	p.checkpoint()

	widths, fallback := s.viewingCases()
	s.runtime.cacheMatches = len(widths) > 1
	guard := p.cpu
	results := resourceguard.New(p.memory, viewingCaseResults{
		text:           allocatedSlice[Text](p.memory, 0, document.extractableTextCount),
		elements:       allocatedSlice[Element](p.memory, 0, document.extractableElementCount),
		textLabels:     allocatedSlice[visibilityLabel](p.memory, 0, document.extractableTextCount),
		elementLabels:  allocatedSlice[visibilityLabel](p.memory, 0, document.extractableElementCount),
		textReasons:    allocatedSlice[concealmentReason](p.memory, 0, document.extractableTextCount),
		elementReasons: allocatedSlice[concealmentReason](p.memory, 0, document.extractableElementCount),
	})

	runner := resourceguard.New(p.memory, viewingCaseRunner{
		document: document, styles: s, retainInspection: p.retainInspection,
		work: guard, results: results,
		frames:     allocatedSlice[viewingCaseFrame](p.memory, 0, document.treeDepth+1),
		styleStack: allocatedSlice[Style](p.memory, 0, document.treeDepth+1),
		layers:     allocatedSlice[paintLayer](p.memory, 0, document.treeDepth),
		shouldStop: p.shouldStop,
	})

	for caseIndex, width := range widths {
		p.checkpoint()

		if err := runner.run(viewingCase{width: width, fallback: fallback, initialize: caseIndex == 0}); err != nil {
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
		guard.check()

		label := aggregateLabel(bits)
		results.text[i].Label = label

		if label == "concealed" {
			results.text[i].ConcealmentReasons = results.textReasons[i]
		}
	}
	in.Text = results.text
	for i, bits := range results.elementLabels {
		guard.check()

		results.elements[i].Label = aggregateLabel(bits)

		if results.elements[i].Label == "concealed" {
			results.elements[i].ConcealmentReasons = results.elementReasons[i]
		}
	}
	in.Elements = results.elements

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
	return memory.Charged()
}

func mergeViewingCaseLabel(labels []visibilityLabel, index int, bit visibilityLabel) bool {
	if index < 0 || index >= len(labels) {
		return false
	}
	labels[index] |= bit
	return true
}
