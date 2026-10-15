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
	// HTML start tags that unconditionally end ordinary SVG/MathML
	// foreign-content parsing. Font is conditional and handled after its
	// attributes have been inspected.
	switch n {
	case "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var":
		return true
	default:
		return false
	}
}

type lexicalFrame struct {
	name             string
	foreign          bool
	htmlChildren     bool
	mathNamespace    bool
	mathTextChildren bool
	textRunBytes     int
	// Foreign-content recovery can leave the lexical and allocating stacks
	// different. Such a frame cannot justify a later implicit closure.
	uncertain        bool
	formatting       *preflightFormatting
	formattingMarker *preflightFormattingScope
}

func mathMLTextIntegrationName(name string) bool {
	switch name {
	case "mi", "mo", "mn", "ms", "mtext":
		return true
	}
	return false
}

// measurePreflight bounds explicit lexical nesting before the HTML5 tree builder
// (which itself can do expensive recovery). The builder can insert implied
// ancestors, so parseDocument separately enforces the limit on final tree
// depth. Recognised implicit closures keep ordinary optional-end-tag sequences
// shallow. Ambiguous recovery remains conservative rather than removing the
// depth guard before the allocating parser runs.
type lexicalUsage struct {
	nodes, textNodes, attributes, depth int
	treeBuilderTokens                   int
	nestedTables                        int
	projectedNodes, projectedAttributes int
	projectedTextMergeCopyBytes         int64
}

// implicitCloseIndex identifies a suffix that a new HTML start tag certainly
// closes. This is deliberately narrower than a second HTML tree builder: never
// search through foreign content or an insertion/scope boundary whose recovery
// we do not model. In particular, matching names alone must not flatten nested
// lists, tables, templates, or formatting-element reconstruction.
func implicitCloseIndex(stack []lexicalFrame, name string) int {
	if len(stack) == 0 {
		return -1
	}
	top := stack[len(stack)-1]
	if top.foreign || top.uncertain {
		return -1
	}
	switch name {
	case "option", "optgroup":
		// The tree builder closes a current option even outside a select. An
		// optgroup closes a preceding group only in a select's implied-end-tag
		// sequence; do not flatten genuinely nested optgroups outside selects.
		keep := len(stack)
		if top.name == "option" {
			keep--
		}
		if name == "optgroup" && keep > 0 && !stack[keep-1].uncertain && stack[keep-1].name == "optgroup" &&
			keep > 1 && !stack[keep-2].foreign && !stack[keep-2].uncertain && stack[keep-2].name == "select" {
			keep--
		}
		if keep < len(stack) {
			return keep
		}
	case "a":
		// Adjacent anchors are safe to close. Adoption-agency recovery through
		// intervening elements can retain/reconstruct descendants, so leave
		// those more complicated cases conservatively nested.
		if top.name == "a" {
			return len(stack) - 1
		}
	case "li", "dd", "dt":
		for i := len(stack) - 1; i >= 0; i-- {
			f := stack[i]
			if f.foreign || f.uncertain {
				break
			}
			if f.name == name || (name != "li" && (f.name == "dd" || f.name == "dt")) {
				return i
			}
			// Only cross known non-special phrasing elements and the three
			// special elements explicitly exempted by the tree builder. Unknown
			// tags remain barriers so dependency changes cannot weaken admission.
			if f.name != "address" && f.name != "div" && f.name != "p" && !preflightPhrasing(f.name) {
				break
			}
		}
	case "td", "th", "tr", "tbody", "thead", "tfoot":
		// Locate the nearest explicit table first. Never close a cell or row
		// belonging to an outer table, or cross a template/foreign boundary.
		table := -1
		for i := len(stack) - 1; i >= 0; i-- {
			f := stack[i]
			if f.foreign || f.uncertain || f.name == "template" || f.name == "select" {
				break
			}
			if f.name == "table" {
				table = i
				break
			}
		}
		if table >= 0 {
			keep := -1
			for i := len(stack) - 1; i > table; i-- {
				switch stack[i].name {
				case "td", "th":
					keep = i
				case "tr":
					if name != "td" && name != "th" {
						keep = i
					}
				case "tbody", "thead", "tfoot":
					if name == "tbody" || name == "thead" || name == "tfoot" {
						keep = i
					}
				}
			}
			return keep
		}
	}
	if closesParagraph(name) {
		for i := len(stack) - 1; i >= 0; i-- {
			f := stack[i]
			if f.foreign || f.uncertain {
				break
			}
			if f.name == "p" {
				return i
			}
			// These are button-scope boundaries in the HTML tree builder.
			switch f.name {
			case "applet", "caption", "html", "table", "td", "th", "marquee", "object", "template", "select", "button":
				return -1
			}
		}
	}
	return -1
}

func preflightPhrasing(name string) bool {
	switch name {
	case "a", "abbr", "b", "bdi", "bdo", "big", "cite", "code", "del", "dfn", "em", "font", "i", "ins", "kbd", "mark", "q", "s", "samp", "small", "span", "strike", "strong", "sub", "sup", "time", "tt", "u", "var":
		return true
	}
	return false
}

func closesParagraph(name string) bool {
	// table is intentionally absent: whether it closes p depends on quirks
	// mode. form likewise depends on whether another form is already open.
	switch name {
	case "address", "article", "aside", "blockquote", "center", "details", "dialog", "dir", "div", "dl", "fieldset", "figcaption", "figure", "footer", "header", "hgroup", "main", "menu", "nav", "ol", "p", "search", "section", "summary", "ul", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "listing", "li", "dd", "dt", "plaintext", "hr", "xmp":
		return true
	}
	return false
}

func measurePreflight(b []byte, l Limits) (lexicalUsage, error) {
	return measurePreflightWithStop(b, l, nil)
}

// PreflightWithStop guards a subsequent HTML tree-builder call without building
// a tree or resolving CSS. Callers must still check actual tree limits after
// parsing; recovery projections deliberately overestimate ambiguous input.
func PreflightWithStop(input []byte, limits Limits, shouldStop func() bool) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if len(input) > limits.InputBytes {
		return fmt.Errorf("limit: input bytes > %d", limits.InputBytes)
	}
	if shouldStop != nil && shouldStop() {
		return errStopped
	}
	if _, err := measurePreflightWithStop(input, limits, shouldStop); err != nil {
		return err
	}
	if shouldStop != nil && shouldStop() {
		return errStopped
	}
	return nil
}

func measurePreflightWithStop(b []byte, l Limits, shouldStop func() bool) (lexicalUsage, error) {
	if err := preflightStartTagAttributes(b, max(l.Attributes, sourceAttributeGuardFloor), shouldStop); err != nil {
		return lexicalUsage{}, err
	}
	z := html.NewTokenizer(bytes.NewReader(b))
	var stack []lexicalFrame
	open := make(map[string]int)
	var usage lexicalUsage
	allocations := allocationPreflight{limits: l, usage: &usage}
	openTables := 0
	rootTextRunBytes := 0
	textRun := func() *int {
		if len(stack) == 0 {
			return &rootTextRunBytes
		}
		return &stack[len(stack)-1].textRunBytes
	}
	noteText := func(textBytes int) error {
		if textBytes == 0 {
			return nil
		}
		run := textRun()
		copyBudget := int64(min(l.InputBytes, maxHTMLTextMergeCopyBytes))
		if int64(*run) > copyBudget-usage.projectedTextMergeCopyBytes {
			return fmt.Errorf("limit: projected text merge copies > %d bytes", copyBudget)
		}
		usage.projectedTextMergeCopyBytes += int64(*run)
		if textBytes > l.InputBytes-*run {
			// The decoded text retained below one projected parent cannot exceed
			// the complete admitted input by more than tokenizer replacement of
			// NUL bytes. Saturation keeps malformed input from overflowing this
			// accounting; the copy budget will reject its next merge.
			*run = l.InputBytes
		} else {
			*run += textBytes
		}
		return nil
	}
	breakTextRun := func() {
		*textRun() = 0
	}
	popTo := func(keep int, name string, explicit bool) {
		allocations.notePop(stack, keep, name, explicit)
		clearScope := allocations.canClearScope(stack, keep, name, explicit)
		for i := len(stack) - 1; i >= keep; i-- {
			allocations.orphan(stack[i].formatting)
			if clearScope != nil && stack[i].formattingMarker == clearScope {
				allocations.popScope()
			}
			name := stack[i].name
			if name == "table" && !stack[i].foreign {
				openTables--
			}
			if open[name] == 1 {
				delete(open, name)
			} else {
				open[name]--
			}
		}
		stack = stack[:keep]
	}
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
			if usage.treeBuilderTokens&255 == 0 && shouldStop != nil && shouldStop() {
				return usage, errStopped
			}
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
			// Entity and newline decoding cannot enlarge a token. NUL replacement
			// can turn one source byte into the three-byte UTF-8 replacement rune;
			// account for that expansion without asking Text to allocate it.
			rawText := z.Raw()
			textBytes := len(rawText) + 2*bytes.Count(rawText, []byte{0})
			if err := noteText(textBytes); err != nil {
				return usage, err
			}
		}
		if t != html.StartTagToken && t != html.SelfClosingTagToken && t != html.EndTagToken {
			if t == html.CommentToken {
				// An inserted comment becomes the preceding sibling and prevents
				// the next text token from appending to this text node.
				breakTextRun()
			}
			if err := allocations.add(1, 0); err != nil {
				return usage, err
			}
			if t == html.TextToken {
				if err := allocations.reconstruct(); err != nil {
					return usage, err
				}
			}
			continue
		}
		raw, more := z.TagName()
		n := string(raw)
		allocations.uncertainInsertionMode(n)
		attributes := 0
		fontBreakout := false
		if t == html.StartTagToken || t == html.SelfClosingTagToken {
			for more {
				key, _, next := z.TagAttr()
				more = next
				usage.attributes++
				attributes++
				if n == "font" && (bytes.Equal(key, []byte("color")) || bytes.Equal(key, []byte("face")) || bytes.Equal(key, []byte("size"))) {
					fontBreakout = true
				}
				if usage.attributes&255 == 0 && shouldStop != nil && shouldStop() {
					return usage, errStopped
				}
				if usage.attributes > l.Attributes {
					return usage, fmt.Errorf("limit: lexical attributes > %d", l.Attributes)
				}
			}
			if err := allocations.add(1, attributes); err != nil {
				return usage, err
			}
		}
		if t == html.EndTagToken {
			// Recovery can reprocess an end tag as a start tag (notably br/p),
			// or flush pending table text and reconstruct formatting entries.
			if err := allocations.reconstruct(); err != nil {
				return usage, err
			}
			nodeProducing := n == "br" || (n == "p" && implicitCloseIndex(stack, "p") < 0)
			if nodeProducing {
				if err := allocations.add(1, 0); err != nil {
					return usage, err
				}
				breakTextRun()
			}
			if formattingTag(n) {
				if err := allocations.endFormatting(n, stack); err != nil {
					return usage, err
				}
			}
			if len(stack) > 0 && stack[len(stack)-1].foreign {
				// End tags at a foreign current node stay in the foreign-content
				// algorithm even at HTML integration points. A match may pop a
				// contiguous foreign suffix. If there is no such match, x/net/html
				// can fall back to an HTML insertion mode whose special-element
				// boundaries decide whether an older HTML match is ignored. Reject
				// that malformed boundary case rather than predicting it incorrectly.
				foreignMatch := -1
				for i := len(stack) - 1; i >= 0 && stack[i].foreign; i-- {
					if stack[i].name == n {
						foreignMatch = i
						break
					}
				}
				if foreignMatch >= 0 {
					popTo(foreignMatch, n, true)
					continue
				}
				return usage, fmt.Errorf("limit: ambiguous foreign-content end tag")
			}
			// Unmatched end tags are common in malformed input and cannot
			// affect this stack. Avoid searching the full bounded depth for
			// every such token in an adversarial end-tag flood.
			if open[n] == 0 {
				allocations.uncertain = true
				continue
			}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == n {
					for _, frame := range stack[i:] {
						if frame.foreign {
							return usage, fmt.Errorf("limit: ambiguous foreign-content end tag")
						}
					}
					popTo(i, n, true)
					break
				}
			}
			continue
		}

		// An inserted element becomes its parent's preceding child. Do this
		// before changing the lexical stack so the parent's text run is reset.
		breakTextRun()

		parentForeign := len(stack) > 0 && stack[len(stack)-1].foreign && !stack[len(stack)-1].htmlChildren
		// MathML text integration points process ordinary child start tags in
		// HTML mode. mglyph and malignmark are the two specified exceptions and
		// remain in the MathML namespace.
		if parentForeign && stack[len(stack)-1].mathTextChildren && n != "mglyph" && n != "malignmark" {
			parentForeign = false
		}
		foreignBreakoutToken := false
		if parentForeign && (foreignBreakout(n) || n == "font" && fontBreakout) {
			allocations.uncertain = true
			// The HTML tree builder pops ordinary foreign elements and
			// reprocesses this token in HTML mode.
			keep := len(stack)
			for keep > 0 && stack[keep-1].foreign && !stack[keep-1].htmlChildren && !stack[keep-1].mathTextChildren {
				keep--
			}
			popTo(keep, "", false)
			// Do not let a later optional tag close a lexical ancestor that
			// foreign-content recovery may already have closed or reparented.
			for i := range stack {
				stack[i].uncertain = true
				allocations.orphan(stack[i].formatting)
			}
			parentForeign = false
			foreignBreakoutToken = true
		}
		foreign := parentForeign || n == "svg" || n == "math"
		mathNamespace := false
		if parentForeign {
			mathNamespace = stack[len(stack)-1].mathNamespace
		} else if n == "math" {
			mathNamespace = true
		}
		if n == "a" || n == "nobr" {
			if err := allocations.endFormatting(n, stack); err != nil {
				return usage, err
			}
		}
		// Foreign integration points have additional namespace-sensitive rules.
		// A lexical breakout alone is not sufficient evidence that an earlier
		// HTML paragraph is in scope; retain conservative depth for that token.
		if !foreign && !foreignBreakoutToken {
			if keep := implicitCloseIndex(stack, n); keep >= 0 {
				popTo(keep, n, false)
			}
		}
		// The tokenizer assumes noscript and raw-text-named elements contain
		// uninterpreted text unless its parser supplies insertion-mode context.
		// Our DOM parse disables scripting, so noscript contains markup. The
		// HTML tree builder likewise disables raw-text tokenization for elements
		// it pushes in SVG or MathML namespaces. Mirror both decisions here so
		// markup in those regions is charged before the allocating DOM parse.
		if n == "noscript" || foreign {
			z.NextIsNotRawText()
		}
		if err := allocations.add(impliedTableNodes(n, stack), 0); err != nil {
			return usage, err
		}
		if err := allocations.reconstruct(); err != nil {
			return usage, err
		}
		if t == html.SelfClosingTagToken && foreign {
			if formattingTag(n) {
				// A namespace-model disagreement at an integration point can make
				// this an HTML tag whose self-closing flag the parser ignores.
				entry, err := allocations.startFormatting(n, attributes)
				if err != nil {
					return usage, err
				}
				allocations.orphan(entry)
			}
			// The self-closing flag is honored in foreign content.
			continue
		}
		if !foreign && void(n) {
			continue
		}
		frame := lexicalFrame{
			name:             n,
			foreign:          foreign,
			htmlChildren:     foreign && !mathNamespace && (n == "foreignobject" || n == "desc" || n == "title"),
			mathNamespace:    mathNamespace,
			mathTextChildren: mathNamespace && mathMLTextIntegrationName(n),
		}
		// Track possible HTML formatting in foreign content too. Integration
		// and recovery can disagree with the conservative lexical namespace;
		// a false foreign classification must not omit clone reservations.
		if formattingTag(n) {
			var err error
			frame.formatting, err = allocations.startFormatting(n, attributes)
			if err != nil {
				return usage, err
			}
		}
		if !foreign && formattingScopeMarker(n, stack) {
			var err error
			frame.formattingMarker, err = allocations.pushScope()
			if err != nil {
				return usage, err
			}
		}
		stack = append(stack, frame)
		if n == "table" && !foreign {
			openTables++
			if openTables > usage.nestedTables {
				usage.nestedTables = openTables
			}
		}
		open[n]++
		if len(stack) > usage.depth {
			usage.depth = len(stack)
		}
		if len(stack) > l.Depth {
			return usage, fmt.Errorf("limit: lexical depth > %d", l.Depth)
		}
	}
}
