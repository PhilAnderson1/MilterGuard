package htmlextract

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/cascadia"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Text describes one extractable text node. Label and ConcealmentReasons are
// aggregated across every evaluated viewing case. FontSize and
// EffectiveOpacity begin with the narrowest-case values; when either explains
// concealment in another case, its evidence is retained from a concealing case.
type Text struct {
	Label              string
	FontSize           string
	EffectiveOpacity   float64
	ConcealmentReasons ConcealmentReason
	Node               *html.Node
	inspection         *textInspection
}

// textInspection keeps detailed resolver evidence available to package tests
// without copying it into every production Text result.
type textInspection struct {
	style  Style
	colour colourInspection
}

// Element describes an image or input control. FontSize is used for input labels. Label and ConcealmentReasons are
// aggregated across viewing cases. EffectiveOpacity begins with the
// narrowest-case value and retains the lowest concealing opacity encountered.
type Element struct {
	FontSize           string
	Node               *html.Node
	Label              string
	ConcealmentReasons ConcealmentReason
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

// x/net/html normalizes attribute keys parsed in HTML content to lowercase;
// callers therefore pass lowercase keys to these lookup helpers.
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

func hiddenInput(n *html.Node) bool {
	return n.Namespace == "" && n.Data == "input" && equalASCIIFold(strings.TrimSpace(attr(n, "type")), "hidden")
}

type nodeScope uint8

const (
	scopeActive nodeScope = iota
	scopeHead
	scopeInert
)

func nodeContentScope(n *html.Node, parent nodeScope) nodeScope {
	if n.Type != html.ElementNode {
		return parent
	}
	// Inert/external-presentation containers override an inherited head scope.
	// Otherwise a style element nested in (for example) a head template would
	// incorrectly be collected as a document stylesheet.
	switch n.Data {
	case "template", "iframe", "noembed", "noframes":
		return scopeInert
	}
	if parent != scopeActive {
		return parent
	}
	switch n.Data {
	case "head":
		return scopeHead
	case "style", "script", "title":
		return scopeInert
	}
	return scopeActive
}

type parsedDocument struct {
	root                    *html.Node
	styles                  sheet
	elements                resourceguard.Table[*html.Node, elementPreparation]
	treeDepth               int
	extractableTextCount    int
	extractableElementCount int
	msoOrderUncertain       bool
	memory                  *resourceguard.Memory
}

type elementPreparation struct {
	inline, legacy   []declaration
	inlineIncomplete bool
	hasElementChild  bool
}

type documentFrame struct {
	n, next *html.Node
	depth   int
	scope   nodeScope
	// Styles declared below noscript are client-dependent: some email
	// sanitizers discard the container while others retain its fallback
	// content. Keep parsing the rules, but do not let them establish a certain
	// presentation result.
	uncertainStylesheetOrigin bool
	entered                   bool
}

type documentWalker struct {
	processor processor
	document  *parsedDocument
	stack     []documentFrame
	nodeCount int
	mso       msoRevealedState
	body      *html.Node
}

func (w *documentWalker) run(root *html.Node) error {
	const initialStackCapacity = 64
	var ok bool
	w.stack, ok = resourceguard.MakeSlice[documentFrame](w.processor.memory, 1, initialStackCapacity)
	if !ok {
		return fmt.Errorf("limit: memory bytes > %d", w.processor.memory.Limit())
	}
	w.stack[0] = documentFrame{n: root}
	for len(w.stack) > 0 {
		frame := &w.stack[len(w.stack)-1]
		if frame.entered {
			if frame.next == nil {
				w.stack = w.stack[:len(w.stack)-1]
				continue
			}
			child := frame.next
			frame.next = child.NextSibling
			if frame.n.Type == html.ElementNode && child.Type == html.ElementNode {
				prepared := w.document.elements.View()[frame.n]
				if !prepared.hasElementChild {
					prepared.hasElementChild = true
					if !w.document.storePreparation(frame.n, prepared) {
						return fmt.Errorf("limit: memory bytes > %d", w.processor.memory.Limit())
					}
				}
			}
			w.stack, ok = resourceguard.GrowSlice(w.processor.memory, w.stack, 1, w.processor.shouldStop)
			if !ok {
				return fmt.Errorf("limit: memory bytes > %d", w.processor.memory.Limit())
			}
			w.stack = append(w.stack, documentFrame{
				n: child, depth: frame.depth + 1, scope: frame.scope,
				uncertainStylesheetOrigin: frame.uncertainStylesheetOrigin,
			})
			continue
		}
		frame.entered = true
		frame.next = frame.n.FirstChild
		if err := w.visit(frame); err != nil {
			return err
		}
	}
	return nil
}

func (w *documentWalker) visit(frame *documentFrame) error {
	node := frame.n
	if frame.depth > w.document.treeDepth {
		w.document.treeDepth = frame.depth
	}
	w.nodeCount++
	if w.nodeCount&255 == 0 && w.processor.stopped() {
		return errStopped
	}
	if node.Type == html.CommentNode && (frame.scope == scopeActive || frame.scope == scopeHead) {
		if !w.visitComment(node) {
			return errStopped
		}
	}
	if node.Type == html.ElementNode {
		if err := w.prepareElement(node, frame); err != nil {
			return err
		}
	}
	frame.scope = nodeContentScope(node, frame.scope)
	if node.Type == html.TextNode && frame.scope == scopeActive {
		w.document.extractableTextCount++
	}
	return nil
}

func (w *documentWalker) visitComment(node *html.Node) bool {
	marker := msoDownlevelRevealedMarker(node.Data)
	if marker != msoRevealedNone {
		// Foster parenting can move text out of table insertion modes while
		// leaving these source-order markers below the table. Once that has
		// happened the final tree cannot identify the displaced region.
	msoAncestors:
		for i := len(w.stack) - 2; i >= 0; i-- {
			ancestor := w.stack[i].n
			if ancestor.Type != html.ElementNode {
				continue
			}
			switch ancestor.Data {
			case "td", "th", "caption":
				break msoAncestors
			case "table", "tbody", "thead", "tfoot", "tr", "colgroup":
				w.document.msoOrderUncertain = true
				break msoAncestors
			}
		}
	}
	if !w.mso.update(marker, w.processor.cpu) {
		return false
	}
	w.document.styles.parseMSOConditionalStyles(node.Data)
	return !w.processor.cpu.stopNow(false)
}

func (w *documentWalker) prepareElement(node *html.Node, frame *documentFrame) error {
	// The container itself is prepared in its parent scope; its contents cannot
	// contribute presentation or stylesheet state. Structural traversal remains.
	if frame.scope == scopeInert {
		return nil
	}
	styles := &w.document.styles
	if node.Namespace == "" && node.Data == "body" && w.body == nil {
		w.body = node
	}
	var prepared elementPreparation
	if href, media, applies := styles.stylesheetLink(node); applies && (frame.scope == scopeActive || frame.scope == scopeHead) {
		styles.loadStylesheetReference(href, media)
	}
	if node.Data == "style" && cssTypeAttributeAppliesWithBudget(node, w.processor.cpu) && (frame.scope == scopeActive || frame.scope == scopeHead) && !styles.cascadeIncomplete && !styles.stopped {
		remaining := styles.limits.CSSBytes - styles.cssBytes
		cssText, complete := boundedStyleTextWithBudget(node, remaining, w.processor.cpu)
		if !complete {
			styles.abandonCascade()
		} else {
			origin := trustedStylesheetOrigin
			if node.Namespace != "" || frame.uncertainStylesheetOrigin || w.mso.uncertain > 0 {
				origin = uncertainStylesheetOrigin
			}
			styles.parseStylesheet(cssText, attr(node, "media"), origin)
		}
	}
	if value := attr(node, "style"); value != "" {
		result := styles.parseInlineCSS(value)
		prepared.inline = result.declarations
		prepared.inlineIncomplete = result.incomplete
	}
	if !styles.cascadeIncomplete && !styles.stopped {
		prepared.legacy = prepareDeclarations(legacyDeclarationsWithBody(node, w.body, w.processor.cpu), w.processor.cpu)
	}
	if len(prepared.inline) != 0 || len(prepared.legacy) != 0 || prepared.inlineIncomplete {
		if !w.document.storePreparation(node, prepared) {
			return fmt.Errorf("limit: memory bytes > %d", w.processor.memory.Limit())
		}
	}
	if frame.scope == scopeActive && (node.Data == "img" || node.Data == "input") {
		w.document.extractableElementCount++
	}
	if node.Namespace == "" && (node.Data == "noscript" || node.Data == "object" || node.Data == "canvas") {
		frame.uncertainStylesheetOrigin = true
	}
	return nil
}

func (p processor) parseDocument(input []byte) (*parsedDocument, error) {
	document, ok := resourceguard.New(p.memory, parsedDocument{memory: p.memory})
	if !ok {
		return nil, resourceguard.ErrMemory
	}
	if err := p.Limits.validate(); err != nil {
		return document, err
	}
	if len(input) > p.Limits.InputBytes {
		return document, fmt.Errorf("limit: input bytes > %d", p.Limits.InputBytes)
	}
	// Email extraction does not execute scripts; parse noscript fallback content
	// in the corresponding HTML5 tree-construction mode.
	root, err := html.ParseWithOptions(bytes.NewReader(input),
		html.ParseOptionEnableScripting(false),
		html.ParseOptionResourceLimits(html.ResourceLimits{
			ShouldStop: p.shouldStop,
			Memory:     p.memory,
		}),
	)
	if err != nil {
		if errors.Is(err, html.ErrResourceStopped) {
			return document, errStopped
		}
		var limitErr *html.ResourceLimitError
		if errors.As(err, &limitErr) {
			return document, fmt.Errorf("limit: HTML parser %s > %d", limitErr.Resource, limitErr.Limit)
		}
		return document, err
	}
	document.root = root
	if p.stopped() {
		return document, errStopped
	}
	document.styles = sheet{
		limits: p.Limits, shouldStop: p.shouldStop,

		cpu:    p.cpu,
		memory: p.memory,
	}
	document.styles.selectorControl, ok = cascadia.NewMatchControlWithMemory(p.shouldStop, p.memory)
	if !ok {
		return document, resourceguard.ErrMemory
	}
	walker := documentWalker{processor: p, document: document}
	if err := walker.run(root); err != nil {
		return document, err
	}
	if document.styles.stopped {
		return document, errStopped
	}
	if document.styles.cascadeIncomplete {
		// No prepared per-element CSS can be used once global style analysis is
		// incomplete. Release declarations and selector profiles collected before
		// the failure rather than retaining them through result traversal.
		document.elements.Release()
	}
	return document, nil
}

func (d *parsedDocument) storePreparation(n *html.Node, prepared elementPreparation) bool {
	return d.elements.Set(d.memory, n, prepared)
}

func boundedStyleText(style *html.Node, maximum int) (string, bool) {
	return boundedStyleTextWithBudget(style, maximum, nil)
}
func boundedStyleTextWithBudget(style *html.Node, maximum int, budget *cpuGuard) (string, bool) {
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
		if !budget.check() || !writeBudgetedString(&css, child.Data, budget) {
			return "", false
		}
	}
	return css.String(), true
}
