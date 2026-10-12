package htmlextract

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

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
		scope   nodeScope
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
			if href, media, applies := stylesheetLink(n); applies && (e.scope == scopeActive || e.scope == scopeHead) {
				document.styles.loadStylesheetReference(href, media)
			}
			if n.Data == "style" && (e.scope == scopeActive || e.scope == scopeHead) {
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
		e.scope = nodeContentScope(n, e.scope)
		if n.Type == html.TextNode && e.scope == scopeActive {
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
