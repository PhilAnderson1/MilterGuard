package cascadia

import "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"

func matchingNodesForTest(root *html.Node, matcher Matcher) []*html.Node {
	control := NewMatchControl(func() {})
	var matches []*html.Node
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if control.Match(matcher, node) {
			matches = append(matches, node)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return matches
}
