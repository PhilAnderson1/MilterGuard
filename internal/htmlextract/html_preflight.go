package htmlextract

import (
	"bytes"
	"fmt"

	"golang.org/x/net/html"
)

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
	treeBuilderTokens                   int
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
		// HTML5 error recovery can turn an end tag into a node-producing start
		// tag (notably </br>, and potentially other tags as parser behaviour
		// evolves). Bound every token that can affect tree construction before
		// allowing x/net/html to build the DOM. Keep the separate node count for
		// accurate resource telemetry.
		switch t {
		case html.StartTagToken, html.SelfClosingTagToken, html.EndTagToken, html.TextToken, html.CommentToken, html.DoctypeToken:
			usage.treeBuilderTokens++
			if usage.treeBuilderTokens > l.Nodes {
				return usage, fmt.Errorf("limit: lexical nodes > %d", l.Nodes)
			}
		}
		switch t {
		case html.StartTagToken, html.SelfClosingTagToken, html.TextToken, html.CommentToken, html.DoctypeToken:
			usage.nodes++
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
