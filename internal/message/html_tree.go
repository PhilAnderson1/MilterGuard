package message

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	xhtml "golang.org/x/net/html"
)

type HTMLExtractionMode uint8

const (
	TagHidden HTMLExtractionMode = iota
	StripHidden
)

type annotationUsage struct {
	UsedConcealedTag                      bool
	UsedVisibilityVariesByViewportSizeTag bool
	UsedVisibilityUncertainTag            bool
	UsedHiddenContentStrippedTag          bool
}

var reservedAnnotation = regexp.MustCompile(`(?is)</?\s*(?:concealed|visibility-varies-by-viewport-size|visibility-uncertain|hidden-content-stripped)\b[^>]*>`)

type htmlExtraction struct {
	inspection  htmlextract.Inspection
	states      map[*xhtml.Node]htmlextract.Text
	elements    map[*xhtml.Node]htmlextract.Element
	base        *url.URL
	baseSeen    bool
	links       linkCollector
	images      imageRefCollector
	anchorDepth int
}

type outputAnnotation struct {
	kind, reason, value string
}

type outputChunk struct {
	text       string
	annotation outputAnnotation
}

// annotatedOutput delays annotation markup until the rendered content is
// complete. This lets equal effective visibility states flow across element
// boundaries, layout whitespace, and generated Markdown such as links.
type annotatedOutput struct {
	chunks []outputChunk
}

func (o *annotatedOutput) WriteString(value string) { o.write(outputAnnotation{}, value) }
func (o *annotatedOutput) WriteByte(value byte) error {
	o.write(outputAnnotation{}, string([]byte{value}))
	return nil
}

func (o *annotatedOutput) write(annotation outputAnnotation, value string) {
	if value == "" {
		return
	}
	if len(o.chunks) > 0 && o.chunks[len(o.chunks)-1].annotation == annotation {
		o.chunks[len(o.chunks)-1].text += value
		return
	}
	o.chunks = append(o.chunks, outputChunk{text: value, annotation: annotation})
}

func (o *annotatedOutput) plainText() string {
	var out strings.Builder
	for _, chunk := range o.chunks {
		out.WriteString(chunk.text)
	}
	return out.String()
}

func (o *annotatedOutput) uniformAnnotation() (outputAnnotation, bool) {
	var found outputAnnotation
	haveContent := false
	for _, chunk := range o.chunks {
		if annotationWhitespaceOnly(chunk.text) {
			continue
		}
		if !haveContent {
			found = chunk.annotation
			haveContent = true
			continue
		}
		if chunk.annotation != found {
			return outputAnnotation{}, false
		}
	}
	return found, haveContent
}

func (o *annotatedOutput) String() string {
	var out, pending strings.Builder
	var active outputAnnotation
	haveActive := false
	closeActive := func() {
		if !haveActive {
			return
		}
		switch active.kind {
		case "concealed":
			out.WriteString("</concealed>")
		case "client-dependent":
			out.WriteString("</visibility-varies-by-viewport-size>")
		case "unknown":
			out.WriteString("</visibility-uncertain>")
		}
		haveActive = false
	}
	open := func(annotation outputAnnotation) {
		switch annotation.kind {
		case "concealed":
			fmt.Fprintf(&out, `<concealed reason="%s"`, annotation.reason)
			if annotation.value != "" {
				fmt.Fprintf(&out, ` value="%s"`, annotation.value)
			}
			out.WriteByte('>')
		case "client-dependent":
			out.WriteString("<visibility-varies-by-viewport-size>")
		case "unknown":
			out.WriteString("<visibility-uncertain>")
		case "stripped":
			out.WriteString("<hidden-content-stripped/>")
		}
	}
	lastWasStripped := false
	for _, chunk := range o.chunks {
		if annotationWhitespaceOnly(chunk.text) {
			pending.WriteString(chunk.text)
			continue
		}
		if chunk.annotation.kind == "stripped" {
			closeActive()
			out.WriteString(pending.String())
			pending.Reset()
			if !lastWasStripped {
				open(chunk.annotation)
			}
			lastWasStripped = true
			continue
		}
		lastWasStripped = false
		if chunk.annotation.kind == "" {
			closeActive()
			out.WriteString(pending.String())
			pending.Reset()
			out.WriteString(chunk.text)
			continue
		}
		if !haveActive || active != chunk.annotation {
			closeActive()
			out.WriteString(pending.String())
			pending.Reset()
			open(chunk.annotation)
			active = chunk.annotation
			haveActive = true
		} else {
			out.WriteString(pending.String())
			pending.Reset()
		}
		out.WriteString(chunk.text)
	}
	closeActive()
	out.WriteString(pending.String())
	return out.String()
}

func htmlToText(source string) extractedContent { return extractTreeHTML(source) }

func extractTreeHTML(source string) extractedContent {
	limits := htmlextract.DefaultLimits()
	inspection, err := htmlextract.Analyze([]byte(source), limits)
	if err != nil {
		// A bounded lexical fallback retains evidence when tree/style processing
		// cannot complete. It is explicitly reported as incomplete extraction.
		return extractBoundedHTMLFallback(source)
	}
	e := htmlExtraction{inspection: inspection, states: make(map[*xhtml.Node]htmlextract.Text, len(inspection.Text)), elements: make(map[*xhtml.Node]htmlextract.Element, len(inspection.Elements))}
	for _, state := range inspection.Text {
		e.states[state.Node] = state
	}
	for _, state := range inspection.Elements {
		e.elements[state.Node] = state
	}
	e.findBase(inspection.Root)
	tagged := e.render(TagHidden)
	stripped := ""
	if tagged.hasConcealed {
		stripped = e.render(StripHidden).text
	}
	return extractedContent{
		Text: tagged.text, VisibleText: tagged.visible, StrippedText: stripped,
		Links: e.links.links, ImageRefs: e.images.refs, HasConcealedContent: tagged.hasConcealed,
		Annotations: tagged.usage,
	}
}

type renderedHTML struct {
	text, visible string
	usage         annotationUsage
	hasConcealed  bool
}

func (e *htmlExtraction) render(mode HTMLExtractionMode) renderedHTML {
	var body annotatedOutput
	var visible strings.Builder
	usage := annotationUsage{}
	e.walk(e.inspection.Root, mode, &body, &visible, &usage)
	text := normalizeHTMLText(body.String())
	visibleText := normalizeHTMLText(visible.String())
	usage = annotationUsage{
		UsedConcealedTag:                      strings.Contains(text, "<concealed "),
		UsedVisibilityVariesByViewportSizeTag: strings.Contains(text, "<visibility-varies-by-viewport-size>"),
		UsedVisibilityUncertainTag:            strings.Contains(text, "<visibility-uncertain>"),
		UsedHiddenContentStrippedTag:          strings.Contains(text, "<hidden-content-stripped/>"),
	}
	return renderedHTML{text: text, visible: visibleText, usage: usage, hasConcealed: e.hasConcealed()}
}

func (e *htmlExtraction) hasConcealed() bool {
	for _, state := range e.inspection.Text {
		if state.Label == "concealed" && strings.TrimSpace(state.Text) != "" {
			return true
		}
	}
	for _, state := range e.inspection.Elements {
		if state.Label == "concealed" && state.Node != nil {
			name := strings.ToLower(state.Node.Data)
			if name == "img" || name == "input" {
				return true
			}
		}
	}
	return false
}

func (e *htmlExtraction) walk(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *strings.Builder, usage *annotationUsage) {
	if n == nil {
		return
	}
	if n.Type == xhtml.TextNode {
		e.writeText(n, mode, out, visible, usage)
		return
	}
	if n.Type == xhtml.CommentNode {
		e.writeConditionalComment(n.Data, out, visible, usage)
		return
	}
	if n.Type != xhtml.ElementNode && n.Type != xhtml.DocumentNode {
		return
	}
	name := strings.ToLower(n.Data)
	if omittedHTMLElement(name) {
		return
	}
	if name == "img" {
		e.writeImage(n, mode, out, visible, usage)
		return
	}
	if name == "input" {
		typ := strings.ToLower(strings.TrimSpace(firstAttr(n, "type")))
		if typ == "submit" || typ == "button" || typ == "reset" {
			label := sanitizeSenderText(firstAttr(n, "value"))
			e.writeElementContent(n, label, mode, out, visible, usage)
		}
		return
	}
	if isBlockElement(name) || name == "br" || name == "hr" {
		out.WriteByte('\n')
		visible.WriteByte('\n')
	}
	if name == "blockquote" {
		marker := "[quoted content begins]\n"
		if e.anchorDepth > 0 {
			marker = `\[quoted content begins\] `
		}
		out.WriteString(marker)
		visible.WriteString("[quoted content begins]\n")
	}
	if name == "a" {
		var label annotatedOutput
		var visibleLabel strings.Builder
		e.anchorDepth++
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			e.walk(child, mode, &label, &visibleLabel, usage)
		}
		e.anchorDepth--
		destination, ok := e.destination(firstAttr(n, "href"))
		if ok {
			plain := strings.TrimSpace(label.plainText())
			if plain == "" {
				plain = "link"
			}
			rendered := "[" + plain + "](" + markdownURL(destination) + ")"
			if annotation, uniform := label.uniformAnnotation(); uniform {
				out.write(annotation, rendered)
			} else {
				// Preserve distinct child annotations when a label crosses a real
				// visibility boundary.
				out.WriteByte('[')
				out.WriteString(strings.TrimSpace(label.String()))
				out.WriteString("](")
				out.WriteString(markdownURL(destination))
				out.WriteByte(')')
			}
			e.links.AddDestination(destination)
		} else {
			for _, chunk := range label.chunks {
				out.write(chunk.annotation, chunk.text)
			}
		}
		visible.WriteString(visibleLabel.String())
		return
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.walk(child, mode, out, visible, usage)
	}
	if name == "blockquote" {
		marker := "\n[quoted content ends]"
		if e.anchorDepth > 0 {
			marker = ` \[quoted content ends\]`
		}
		out.WriteString(marker)
		visible.WriteString("\n[quoted content ends]")
	}
	if isBlockElement(name) {
		out.WriteByte('\n')
		visible.WriteByte('\n')
	}
}

func (e *htmlExtraction) writeElementContent(n *xhtml.Node, content string, mode HTMLExtractionMode, out *annotatedOutput, visible *strings.Builder, usage *annotationUsage) {
	if content == "" {
		return
	}
	state := e.elements[n]
	switch state.Label {
	case "concealed":
		if mode == StripHidden {
			out.write(outputAnnotation{kind: "stripped"}, content)
			usage.UsedHiddenContentStrippedTag = true
			return
		}
		reason, value := elementConcealmentReason(state)
		out.write(outputAnnotation{kind: "concealed", reason: reason, value: value}, content)
		usage.UsedConcealedTag = true
	case "client-dependent":
		out.write(outputAnnotation{kind: "client-dependent"}, content)
		visible.WriteString(content)
		usage.UsedVisibilityVariesByViewportSizeTag = true
	case "unknown":
		out.write(outputAnnotation{kind: "unknown"}, content)
		visible.WriteString(content)
		usage.UsedVisibilityUncertainTag = true
	default:
		out.WriteString(content)
		visible.WriteString(content)
	}
}

func (e *htmlExtraction) writeConditionalComment(data string, out *annotatedOutput, visible *strings.Builder, usage *annotationUsage) {
	trimmed := strings.TrimSpace(data)
	if !strings.HasPrefix(strings.ToLower(trimmed), "[if ") {
		return
	}
	start := strings.Index(trimmed, "]>")
	end := strings.LastIndex(strings.ToLower(trimmed), "<![endif]")
	if start < 0 || end <= start+2 {
		return
	}
	fragment, err := xhtml.ParseFragment(strings.NewReader(trimmed[start+2:end]), nil)
	if err != nil {
		return
	}
	var content strings.Builder
	for _, node := range fragment {
		e.walkConditionalNode(node, &content)
	}
	value := normalizeHTMLText(content.String())
	if value == "" || annotationWhitespaceOnly(value) {
		return
	}
	out.write(outputAnnotation{kind: "unknown"}, value)
	visible.WriteString(value)
	usage.UsedVisibilityUncertainTag = true
}

func (e *htmlExtraction) walkConditionalNode(n *xhtml.Node, out *strings.Builder) {
	if n.Type == xhtml.TextNode {
		out.WriteString(sanitizeSenderText(n.Data))
		return
	}
	if n.Type != xhtml.ElementNode && n.Type != xhtml.DocumentNode {
		return
	}
	name := strings.ToLower(n.Data)
	// Outlook conditionals can contain Office configuration XML alongside
	// alternate message markup. It is presentation code, not recipient-facing
	// fallback content.
	if omittedHTMLElement(name) || name == "xml" || strings.HasPrefix(name, "o:") {
		return
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "a") {
		var label strings.Builder
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			e.walkConditionalNode(child, &label)
		}
		if destination, ok := e.destination(firstAttr(n, "href")); ok {
			fmt.Fprintf(out, "[%s](%s)", markdownLabelText(strings.TrimSpace(label.String())), markdownURL(destination))
			e.links.AddDestination(destination)
		} else {
			out.WriteString(label.String())
		}
		return
	}
	if isBlockElement(name) || strings.EqualFold(n.Data, "br") {
		out.WriteByte('\n')
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.walkConditionalNode(child, out)
	}
	if isBlockElement(name) {
		out.WriteByte('\n')
	}
}

func (e *htmlExtraction) writeText(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *strings.Builder, usage *annotationUsage) {
	text := compactFormattingPadding(sanitizeSenderText(n.Data))
	if text == "" {
		return
	}
	state, found := e.states[n]
	if !found {
		return // source in head/style/script/title/template or another inert scope
	}
	outText := text
	if e.anchorDepth > 0 {
		outText = markdownLabelText(text)
	}
	// Presentation annotations around whitespace add noise without carrying a
	// visibility claim about message content. This includes decoded HTML space
	// entities such as &nbsp; (U+00A0) and standalone runs of invisible formatting
	// characters. Formatting characters embedded in meaningful text still follow
	// that text's visibility state and remain available as obfuscation evidence.
	if annotationWhitespaceOnly(text) {
		out.WriteString(outText)
		if state.Label != "concealed" {
			visible.WriteString(text)
		}
		return
	}
	switch state.Label {
	case "concealed":
		if mode == StripHidden {
			out.write(outputAnnotation{kind: "stripped"}, outText)
			usage.UsedHiddenContentStrippedTag = true
			return
		}
		reason, value := concealmentReason(state)
		out.write(outputAnnotation{kind: "concealed", reason: reason, value: value}, outText)
		usage.UsedConcealedTag = true
	case "client-dependent":
		out.write(outputAnnotation{kind: "client-dependent"}, outText)
		visible.WriteString(text)
		usage.UsedVisibilityVariesByViewportSizeTag = true
	case "unknown":
		out.write(outputAnnotation{kind: "unknown"}, outText)
		visible.WriteString(text)
		usage.UsedVisibilityUncertainTag = true
	default:
		out.WriteString(outText)
		visible.WriteString(text)
	}
}

// Email preheaders commonly repeat a mixture of spaces and default-ignorable
// Unicode characters hundreds of times to occupy inbox-preview width. Preserve
// a small sample as evidence, but do not let formatting-only padding dominate
// the LLM input. Ordinary whitespace and short obfuscation runs are unchanged.
func compactFormattingPadding(value string) string {
	const threshold, retained = 32, 8
	runes := []rune(value)
	var out strings.Builder
	for start := 0; start < len(runes); {
		end := start
		hasFormat := false
		for end < len(runes) && preheaderPaddingRune(runes[end]) {
			hasFormat = hasFormat || !unicode.IsSpace(runes[end])
			end++
		}
		if end == start {
			out.WriteRune(runes[start])
			start++
			continue
		}
		keep := end - start
		if hasFormat && keep >= threshold {
			keep = retained
		}
		for _, r := range runes[start : start+keep] {
			out.WriteRune(r)
		}
		start = end
	}
	return out.String()
}

func preheaderPaddingRune(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	switch r {
	case '\u00ad', '\u034f', '\u061c', '\u180e', '\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\u2060', '\ufeff':
		return true
	}
	return false
}

func annotationWhitespaceOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !preheaderPaddingRune(r) {
			return false
		}
	}
	return true
}

func concealmentReason(state htmlextract.Text) (string, string) {
	for _, reason := range state.ConcealmentReasons {
		switch reason {
		case "display-none":
			return "display:none", ""
		case "visibility-hidden":
			return "visibility:hidden", ""
		case "visibility-collapse":
			return "visibility:collapse", ""
		case "content-visibility-hidden":
			return "content-visibility:hidden", ""
		case "opacity":
			return "opacity", strconv.FormatFloat(state.EffectiveOpacity, 'g', 6, 64)
		case "font-size":
			if value, ok := state.Style["font-size"]; ok {
				return "font-size", value.Text
			}
		case "colour-distance":
			return "color-match", ""
		case "empty-clip":
			return "empty-clip", ""
		}
	}
	return "display:none", ""
}

func (e *htmlExtraction) writeImage(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *strings.Builder, usage *annotationUsage) {
	if explicitTrackingPixel(n) {
		return
	}
	raw := strings.TrimSpace(firstAttr(n, "src"))
	alt := sanitizeSenderText(firstAttr(n, "alt"))
	var rendered string
	if strings.HasPrefix(strings.ToLower(raw), "cid:") {
		id := normalizeContentID(raw[4:])
		if id == "" {
			return
		}
		if alt == "" {
			alt = "embedded image"
		}
		rendered = fmt.Sprintf(" ![%s](cid:%s) ", markdownLabelText(alt), markdownURL(id))
		e.images.Add(id)
	} else if destination, ok := e.destination(raw); ok && (strings.HasPrefix(destination, "http://") || strings.HasPrefix(destination, "https://")) {
		if alt == "" {
			alt = "image"
		}
		rendered = fmt.Sprintf(" ![%s](%s) ", markdownLabelText(alt), markdownURL(destination))
		e.links.AddDestination(destination)
	}
	if rendered == "" {
		return
	}
	state := e.elements[n]
	switch state.Label {
	case "concealed":
		if mode == StripHidden {
			out.write(outputAnnotation{kind: "stripped"}, rendered)
			usage.UsedHiddenContentStrippedTag = true
			return
		}
		reason, value := elementConcealmentReason(state)
		out.write(outputAnnotation{kind: "concealed", reason: reason, value: value}, rendered)
		usage.UsedConcealedTag = true
	case "client-dependent":
		out.write(outputAnnotation{kind: "client-dependent"}, rendered)
		usage.UsedVisibilityVariesByViewportSizeTag = true
	case "unknown":
		out.write(outputAnnotation{kind: "unknown"}, rendered)
		usage.UsedVisibilityUncertainTag = true
	default:
		out.WriteString(rendered)
	}
}

func explicitTrackingPixel(n *xhtml.Node) bool {
	if strings.TrimSpace(firstAttr(n, "alt")) != "" {
		return false
	}
	unit := func(name string) bool {
		value, present := attrPresent(n, name)
		if !present {
			return false
		}
		value = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(value), "px"))
		n, err := strconv.ParseFloat(value, 64)
		return err == nil && n > 0 && n <= 1
	}
	return unit("width") && unit("height")
}

func elementConcealmentReason(state htmlextract.Element) (string, string) {
	for _, reason := range state.ConcealmentReasons {
		switch reason {
		case "display-none":
			return "display:none", ""
		case "visibility-hidden":
			return "visibility:hidden", ""
		case "visibility-collapse":
			return "visibility:collapse", ""
		case "content-visibility-hidden":
			return "content-visibility:hidden", ""
		case "opacity":
			return "opacity", strconv.FormatFloat(state.EffectiveOpacity, 'g', 6, 64)
		case "empty-clip":
			return "empty-clip", ""
		}
	}
	return "display:none", ""
}

func (e *htmlExtraction) findBase(n *xhtml.Node) {
	if n == nil || e.baseSeen {
		return
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "template") {
		return
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "base") {
		raw, present := attrPresent(n, "href")
		if present {
			e.baseSeen = true
			if parsed, err := url.Parse(strings.TrimSpace(raw)); err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				e.base = parsed
			}
			return // first base href wins even when unusable
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.findBase(child)
	}
}

func (e *htmlExtraction) destination(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r == '\x00' {
			return -1
		}
		return r
	}, raw))
	var encoded strings.Builder
	authorityEnd := 0
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		authorityEnd = len(raw)
		if rest := strings.IndexAny(raw[scheme+3:], "/?#"); rest >= 0 {
			authorityEnd = scheme + 3 + rest
		}
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c < 0x20 || c == 0x7f {
			if authorityEnd > 0 && i < authorityEnd {
				return "", false
			}
			fmt.Fprintf(&encoded, "%%%02X", c)
		} else {
			encoded.WriteByte(c)
		}
	}
	raw = encoded.String()
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.IsAbs() {
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "mailto" && scheme != "tel" {
			return "", false
		}
		if (scheme == "http" || scheme == "https") && parsed.Hostname() == "" {
			return "", false
		}
		return parsed.String(), true
	}
	if e.base != nil {
		return e.base.ResolveReference(parsed).String(), true
	}
	return raw, true
}

func firstAttr(n *xhtml.Node, key string) string { value, _ := attrPresent(n, key); return value }
func attrPresent(n *xhtml.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

func omittedHTMLElement(name string) bool {
	switch name {
	case "head", "style", "script", "title", "template", "iframe", "object":
		return true
	}
	return false
}

func isBlockElement(name string) bool {
	switch name {
	case "address", "article", "aside", "blockquote", "div", "dl", "dt", "dd", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "li", "main", "nav", "ol", "p", "pre", "section", "table", "tbody", "thead", "tfoot", "tr", "td", "th", "ul":
		return true
	}
	return false
}

func sanitizeSenderText(value string) string { return reservedAnnotation.ReplaceAllString(value, "") }

func normalizeHTMLText(value string) string {
	value = strings.ToValidUTF8(value, "�")
	var b strings.Builder
	b.Grow(len(value))
	space, newlines := false, 0
	for _, r := range value {
		switch r {
		case ' ', '\t', '\f':
			space = true
		case '\r', '\n':
			space = false
			if b.Len() > 0 && newlines < 2 {
				b.WriteByte('\n')
				newlines++
			}
		default:
			if space && b.Len() > 0 && newlines == 0 {
				b.WriteByte(' ')
			}
			space, newlines = false, 0
			if r < utf8.RuneSelf {
				b.WriteByte(byte(r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	return strings.Trim(b.String(), " \t\r\n\f")
}

func (collector *linkCollector) AddDestination(candidate string) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return
	}
	if collector.seen == nil {
		collector.seen = make(map[string]struct{})
	}
	if _, exists := collector.seen[candidate]; exists {
		return
	}
	characters := utf8.RuneCountInString(candidate)
	if len(collector.links) >= maxExtractedLinks || characters > maxExtractedLinkLength || collector.chars+characters > maxExtractedLinkChars {
		return
	}
	collector.seen[candidate] = struct{}{}
	collector.links = append(collector.links, candidate)
	collector.chars += characters
}
