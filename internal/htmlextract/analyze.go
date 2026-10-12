package htmlextract

import (
	"fmt"

	"golang.org/x/net/html"
)

type processor struct {
	Limits           Limits
	retainInspection bool // tests only; production results retain compact decisions
}

// Analyze parses and resolves a document once and retains the tree alongside
// the per-text-node presentation decisions used by message extraction.
func Analyze(input []byte, limits Limits) (Document, error) {
	p := processor{Limits: limits}
	return p.process(input)
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
	n, next    *html.Node
	entered    bool
	styleIndex int
	scope      nodeScope
	presentationState
	vars         *variableScope
	selectorPath selectorAttributeProfile
}

type colourMemo struct {
	foreground Value
	result     colourResult
	generation uint64
	valid      bool
}

type viewingCaseRunner struct {
	document         *parsedDocument
	styles           *sheet
	retainInspection bool
	matches          *matchBudget
	expressions      *expressionBudget
	results          *viewingCaseResults
	frames           []viewingCaseFrame
	styleStack       []Style
	layers           []paintLayer
	layerGeneration  uint64
	colourMemo       colourMemo
}

func (r *viewingCaseRunner) evaluateColour(foreground Value) colourResult {
	if !chargeColourEvaluation(foreground, r.layers, r.matches) {
		return colourResult{uncertainty: "style-analysis work limit"}
	}
	if r.colourMemo.valid && r.colourMemo.generation == r.layerGeneration && r.colourMemo.foreground == foreground {
		return r.colourMemo.result
	}
	result := evaluateColourUncharged(foreground, r.layers)
	r.colourMemo = colourMemo{foreground: foreground, result: result, generation: r.layerGeneration, valid: true}
	return result
}

func (r *viewingCaseRunner) run(width float64, fallback, first bool) error {
	textIndex, elementIndex := 0, 0
	media := mediaEvaluation{width: width, fallback: fallback}
	r.frames = r.frames[:0]
	r.styleStack = r.styleStack[:0]
	r.styleStack = append(r.styleStack, initial())
	r.frames = append(r.frames, viewingCaseFrame{n: r.document.root, presentationState: initialPresentationState()})
	rootStyle := initial()
	r.layers = r.layers[:0]
	r.layerGeneration = 0
	r.colourMemo.valid = false
	for len(r.frames) > 0 {
		f := &r.frames[len(r.frames)-1]
		n := f.n
		if !f.entered {
			f.entered = true
			f.next = n.FirstChild
			if n.Type == html.ElementNode {
				var prepared elementPreparation
				if len(r.document.elements) != 0 {
					prepared = r.document.elements[n]
				}
				selectorCurrent := prepared.selector
				f.selectorPath.classes = max(f.selectorPath.classes, selectorCurrent.classes)
				f.selectorPath.ids = max(f.selectorPath.ids, selectorCurrent.ids)
				f.selectorPath.attributes = max(f.selectorPath.attributes, selectorCurrent.attributes)
				selectorContext := selectorMatchContext{
					current: selectorCurrent, path: f.selectorPath, document: r.document.attributeWork,
					depth: len(r.frames) - 1, nodes: r.document.nodeCount,
				}
				parentStyle := &r.styleStack[f.styleIndex]
				resolved := r.styles.elementStyle(n, parentStyle, &rootStyle, f.vars, prepared.legacy, prepared.inline, &media, selectorContext, r.matches, r.expressions)
				r.styleStack = append(r.styleStack, resolved.style)
				f.styleIndex = len(r.styleStack) - 1
				style := &r.styleStack[f.styleIndex]
				f.vars = resolved.variables
				empty, known, inlineClipPathUncertain := emptyClip(style, n, resolved.displayDeclared)
				f.clipped = f.clipped || empty
				f.clipKnown = f.clipKnown && known
				r.layers = append(r.layers, layerWithClipOverride(style, inlineClipPathUncertain))
				r.layerGeneration++
				if n.Namespace == "" && n.Data == "body" && n.Parent != nil && n.Parent.Namespace == "" && n.Parent.Data == "html" {
					propagateHTMLBodyBackground(r.layers)
				}
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
				}
				f.contentKnown = f.contentKnown && cv.Known
				mh := style[msoHide]
				if mh.Known && mh.Text == "all" {
					f.msoHidden = true
				}
				f.msoKnown = f.msoKnown && mh.Known
				f.layoutUncertain = f.layoutUncertain || resolved.layoutUncertain
				a := style[opacity]
				if a.Known && a.Number == 0 {
					f.alpha = 0
					f.alphaKnown = true
				} else if !(f.alphaKnown && f.alpha == 0) {
					f.alpha *= a.Number
					f.alphaKnown = f.alphaKnown && a.Known
				}
				if n.Data == "img" || n.Data == "input" {
					decision := decideVisibility(style, f.presentationState, nil)
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
			f.scope = nodeContentScope(n, f.scope)
			if n.Type == html.TextNode && f.scope == scopeActive {
				style := &r.styleStack[f.styleIndex]
				colour := r.evaluateColour(style[color])
				decision := decideVisibility(style, f.presentationState, &colour)
				if first {
					r.results.textLabels = append(r.results.textLabels, decision.label)
					r.results.textReasons = append(r.results.textReasons, decision.reasons)
					text := Text{FontSize: style[fontSize].Text, EffectiveOpacity: f.alpha, Node: n}
					if r.retainInspection {
						text.inspection = &textInspection{style: *style, colour: colour.inspection()}
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
				r.layerGeneration++
				r.styleStack = r.styleStack[:len(r.styleStack)-1]
			}
			r.frames = r.frames[:len(r.frames)-1]
			continue
		}
		child := f.next
		f.next = child.NextSibling
		r.frames = append(r.frames, viewingCaseFrame{
			n: child, styleIndex: f.styleIndex, scope: f.scope, presentationState: f.presentationState,
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
		Root: root,
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
	budget := expressionBudget{remaining: exprLimit}
	matches := matchBudget{limit: p.Limits.MatchWork, used: s.planningWork}
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
		matches: &matches, expressions: &budget, results: &results,
		frames:     make([]viewingCaseFrame, 0, document.treeDepth+1),
		styleStack: make([]Style, 0, document.treeDepth+1),
		layers:     make([]paintLayer, 0, document.treeDepth),
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
