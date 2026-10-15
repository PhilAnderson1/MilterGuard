package htmlextract

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unsafe"

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

// Element describes an image-like element. Label and ConcealmentReasons are
// aggregated across viewing cases. EffectiveOpacity begins with the
// narrowest-case value and retains the lowest concealing opacity encountered.
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
	case "template", "iframe", "noembed", "noframes", "object":
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
	elements                map[*html.Node]elementPreparation
	treeDepth               int
	nodeCount               int
	textCount               int
	attributeCount          int
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

func (p processor) parseDocument(input []byte) (parsedDocument, error) {
	document := parsedDocument{memory: p.memory}
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
		selectorControl: cascadia.NewMatchControl(p.shouldStop),
		cpu:             p.cpu,
		memory:          p.memory,
	}
	if !p.memory.Reserve(int64(unsafe.Sizeof(map[*html.Node]elementPreparation{}))) {
		return document, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
	}
	document.elements = make(map[*html.Node]elementPreparation)
	type entry struct {
		n, next *html.Node
		depth   int
		scope   nodeScope
		// Styles declared below noscript are client-dependent: some email
		// sanitizers discard the container while others retain its fallback
		// content. Keep parsing the rules, but do not let them establish a
		// certain presentation result.
		uncertainStylesheetOrigin bool
		entered                   bool
	}
	stackCap := 64
	if !p.memory.Reserve(int64(stackCap) * int64(unsafe.Sizeof(entry{}))) {
		return document, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
	}
	stack := make([]entry, 1, stackCap)
	stack[0] = entry{n: root}
	msoRevealedDepth := 0
	for len(stack) > 0 {
		e := &stack[len(stack)-1]
		if e.entered {
			if e.next == nil {
				stack = stack[:len(stack)-1]
				continue
			}
			child := e.next
			e.next = child.NextSibling
			if e.n.Type == html.ElementNode && child.Type == html.ElementNode {
				prepared := document.elements[e.n]
				if !prepared.hasElementChild {
					prepared.hasElementChild = true
					document.elements[e.n] = prepared
				}
			}
			if len(stack) == cap(stack) {
				newCap := max(1, cap(stack)*2)
				if !p.memory.Reserve(int64(newCap-cap(stack)) * int64(unsafe.Sizeof(entry{}))) {
					return document, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
				}
				grown := make([]entry, len(stack), newCap)
				copy(grown, stack)
				stack = grown
			}
			stack = append(stack, entry{
				n: child, depth: e.depth + 1, scope: e.scope,
				uncertainStylesheetOrigin: e.uncertainStylesheetOrigin,
			})
			continue
		}
		e.entered = true
		e.next = e.n.FirstChild
		n := e.n
		if e.depth > document.treeDepth {
			document.treeDepth = e.depth
		}
		document.nodeCount++
		if document.nodeCount&255 == 0 && p.stopped() {
			return document, errStopped
		}
		if n.Type == html.TextNode {
			document.textCount++
		}
		if n.Type == html.CommentNode && (e.scope == scopeActive || e.scope == scopeHead) {
			marker := msoDownlevelRevealedMarker(n.Data)
			if marker != msoRevealedNone {
				// Foster parenting can move text out of table insertion modes while
				// leaving these source-order markers below the table. Once that has
				// happened the final tree cannot identify the displaced region.
			msoAncestors:
				for i := len(stack) - 2; i >= 0; i-- {
					ancestor := stack[i].n
					if ancestor.Type != html.ElementNode {
						continue
					}
					switch ancestor.Data {
					case "td", "th", "caption":
						break msoAncestors // Ordinary content here is not foster parented.
					case "table", "tbody", "thead", "tfoot", "tr", "colgroup":
						document.msoOrderUncertain = true
						break msoAncestors
					}
				}
			}
			switch marker {
			case msoRevealedStart:
				msoRevealedDepth++
			case msoRevealedEnd:
				if msoRevealedDepth > 0 {
					msoRevealedDepth--
				}
			}
			document.styles.parseMSOConditionalStyles(n.Data)
		}
		if n.Type == html.ElementNode {
			document.attributeCount += len(n.Attr)
			var prepared elementPreparation
			if href, media, applies := document.styles.stylesheetLink(n); applies && (e.scope == scopeActive || e.scope == scopeHead) {
				document.styles.loadStylesheetReference(href, media)
			}
			if n.Data == "style" && cssTypeAttributeApplies(n) && (e.scope == scopeActive || e.scope == scopeHead) {
				styles := &document.styles
				if !styles.cascadeIncomplete && !styles.stopped {
					remaining := styles.limits.CSSBytes - styles.cssBytes
					css, complete := boundedStyleText(n, remaining)
					if !complete {
						styles.abandonCascade()
					} else {
						styles.parseStylesheet(css, attr(n, "media"), n.Namespace != "" || e.uncertainStylesheetOrigin || msoRevealedDepth > 0)
					}
				}
			}
			if value := attr(n, "style"); value != "" {
				result := document.styles.parseInlineCSS(value)
				prepared.inline = result.declarations
				prepared.inlineIncomplete = result.incomplete
			}
			if !document.styles.cascadeIncomplete && !document.styles.stopped {
				prepared.legacy = prepareDeclarations(legacyDeclarations(n))
			}
			if len(prepared.inline) != 0 || len(prepared.legacy) != 0 || prepared.inlineIncomplete {
				if _, exists := document.elements[n]; !exists && !p.memory.Reserve(128) {
					return document, fmt.Errorf("limit: memory bytes > %d", p.memory.Limit())
				}
				document.elements[n] = prepared
			}
			if e.scope == scopeActive && (n.Data == "img" || n.Data == "input") {
				document.extractableElementCount++
			}
			if n.Namespace == "" && n.Data == "noscript" {
				e.uncertainStylesheetOrigin = true
			}
		}
		e.scope = nodeContentScope(n, e.scope)
		if n.Type == html.TextNode && e.scope == scopeActive {
			document.extractableTextCount++
		}
	}
	if document.styles.stopped {
		return document, errStopped
	}
	if document.styles.cascadeIncomplete || document.styles.stopped {
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
