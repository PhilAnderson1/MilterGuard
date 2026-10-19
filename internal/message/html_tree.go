package message

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	xhtml "github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
	"github.com/PhilAnderson1/MilterGuard/internal/htmlextract"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

type HTMLExtractionMode uint8

const (
	TagHidden HTMLExtractionMode = iota
	StripHidden
)

const (
	maxConditionalFragmentBytes = 64 << 10
	conditionalOmissionMarker   = "[conditional Outlook content omitted: processing limit]"
)

type annotationUsage struct {
	UsedInvisibleTag                      bool
	UsedVisibilityVariesByViewportSizeTag bool
	UsedVisibilityUncertainTag            bool
	UsedHiddenContentStrippedTag          bool
}

var reservedAnnotation = regexp.MustCompile(`(?is)</?\s*(?:invisible|visibility-varies-by-viewport-size|visibility-uncertain|hidden-content-stripped)\b[^>]*>`)

type htmlExtraction struct {
	inspection           htmlextract.Document
	states               map[*xhtml.Node]*htmlextract.Text
	elements             map[*xhtml.Node]*htmlextract.Element
	base                 *url.URL
	baseSeen             bool
	links                linkCollector
	images               imageRefCollector
	anchorDepth          int
	compactURLs          bool
	shouldStop           func() bool
	memory               *resourceguard.Memory
	extractionIncomplete bool
	workSteps            uint32
	stopped              bool
	memoryExhausted      bool
}

type outputAnnotation struct {
	kind, reason, value string
}

type outputChunk struct {
	start, end int
	annotation outputAnnotation
}

// annotatedOutput delays annotation markup until the rendered content is
// complete. This lets equal effective visibility states flow across element
// boundaries, layout whitespace, and generated Markdown such as links.
type annotatedOutput struct {
	data   guardedBuilder
	chunks []outputChunk
	memory *resourceguard.Memory
	failed bool
}

func newAnnotatedOutput(memory *resourceguard.Memory) annotatedOutput {
	return annotatedOutput{data: newGuardedBuilder(memory), memory: memory}
}

func (o *annotatedOutput) WriteString(value string) { o.write(outputAnnotation{}, value) }
func (o *annotatedOutput) WriteByte(value byte) error {
	start := o.data.Len()
	if !o.data.appendByte(value) {
		o.failed = true
		return errOutputMemoryLimit
	}
	o.extendChunk(outputAnnotation{}, start)
	if o.failed {
		return errOutputMemoryLimit
	}
	return nil
}

func (o *annotatedOutput) write(annotation outputAnnotation, value string) {
	if value == "" {
		return
	}
	start := o.data.Len()
	if !o.data.WriteString(value) {
		o.failed = true
		return
	}
	o.extendChunk(annotation, start)
}

func (o *annotatedOutput) writeBytes(annotation outputAnnotation, value []byte) {
	if len(value) == 0 {
		return
	}
	start := o.data.Len()
	if _, err := o.data.Write(value); err != nil {
		o.failed = true
		return
	}
	o.extendChunk(annotation, start)
}

func (o *annotatedOutput) extendChunk(annotation outputAnnotation, start int) {
	if len(o.chunks) > 0 && o.chunks[len(o.chunks)-1].annotation == annotation {
		o.chunks[len(o.chunks)-1].end = o.data.Len()
		return
	}
	if len(o.chunks) == cap(o.chunks) {
		grown, ok := growGuardedSlice(o.chunks, len(o.chunks)+1, o.memory)
		if !ok {
			o.failed = true
			return
		}
		o.chunks = grown
	}
	o.chunks = append(o.chunks, outputChunk{start: start, end: o.data.Len(), annotation: annotation})
}

func (o *annotatedOutput) chunkBytes(chunk outputChunk) []byte {
	return o.data.Bytes()[chunk.start:chunk.end]
}

func (o *annotatedOutput) plainText() string {
	return o.data.String()
}

func (o *annotatedOutput) uniformAnnotation() (outputAnnotation, bool) {
	var found outputAnnotation
	haveContent := false
	for _, chunk := range o.chunks {
		if annotationWhitespaceOnlyBytes(o.chunkBytes(chunk)) {
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

func (o *annotatedOutput) String() (string, bool) {
	out := newGuardedBuilder(o.memory)
	pending := newGuardedBuilder(o.memory)
	var active outputAnnotation
	haveActive := false
	closeActive := func() {
		if !haveActive {
			return
		}
		switch active.kind {
		case "concealed":
			out.WriteString("</invisible>")
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
			out.WriteString(`<invisible reason="`)
			out.WriteString(annotation.reason)
			out.appendByte('"')
			if annotation.value != "" {
				out.WriteString(` value="`)
				out.WriteString(annotation.value)
				out.appendByte('"')
			}
			out.appendByte('>')
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
		if out.Failed() || pending.Failed() {
			return "", false
		}
		value := o.chunkBytes(chunk)
		if annotationWhitespaceOnlyBytes(value) {
			_, _ = pending.Write(value)
			continue
		}
		if chunk.annotation.kind == "stripped" {
			closeActive()
			_, _ = out.Write(pending.Bytes())
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
			_, _ = out.Write(pending.Bytes())
			pending.Reset()
			_, _ = out.Write(value)
			continue
		}
		if !haveActive || active != chunk.annotation {
			closeActive()
			_, _ = out.Write(pending.Bytes())
			pending.Reset()
			open(chunk.annotation)
			active = chunk.annotation
			haveActive = true
		} else {
			_, _ = out.Write(pending.Bytes())
			pending.Reset()
		}
		_, _ = out.Write(value)
	}
	closeActive()
	_, _ = out.Write(pending.Bytes())
	if o.failed || out.Failed() || pending.Failed() {
		return "", false
	}
	return out.String(), true
}

func htmlToText(source string) extractedContent {
	return htmlToTextWithBudget(source, newExtractionBudget())
}

func htmlToTextWithBudget(source string, budget *extractionBudget) extractedContent {
	budget.htmlParts++
	if budget.useFallback() {
		return budget.extractFallback(source)
	}
	limits, ok := budget.htmlLimits(len(source))
	if !ok {
		content := budget.extractFallback(source)
		content.ExtractionIncomplete = true
		return content
	}
	return extractTreeHTMLWithLimits(source, limits, budget)
}

func extractTreeHTML(source string) extractedContent {
	return htmlToText(source)
}

func extractTreeHTMLWithLimits(source string, limits htmlextract.Limits, budget *extractionBudget) extractedContent {
	inspection, err := htmlextract.AnalyzeWithStop([]byte(source), limits, budget.shouldFallback)
	budget.consumeHTML(inspection.Usage)
	if htmlextract.IsStopped(err) {
		budget.cpuLimitExceeded = true
	}
	if budget.useFallback() {
		return budget.extractFallback(source)
	}
	if err != nil {
		// A bounded lexical fallback retains evidence when tree/style processing
		// cannot complete. It is explicitly reported as incomplete extraction.
		content := budget.extractFallback(source)
		content.ExtractionIncomplete = true
		return content
	}
	memory := resourceguard.NewMemory(budget.memoryBytesRemaining)
	mapBytes := int64(len(inspection.Text)+len(inspection.Elements))*64 + 256
	if !memory.Reserve(mapBytes) {
		budget.consumeMemory(memory)
		content := budget.extractFallback(source)
		content.ExtractionIncomplete = true
		return content
	}
	e := htmlExtraction{
		inspection:  inspection,
		states:      make(map[*xhtml.Node]*htmlextract.Text, len(inspection.Text)),
		elements:    make(map[*xhtml.Node]*htmlextract.Element, len(inspection.Elements)),
		compactURLs: budget.compactURLs,
		links:       linkCollector{compactURLs: budget.compactURLs, memory: memory, shouldStop: budget.useFallback},
		shouldStop:  budget.useFallback,
		memory:      memory,
	}
	for i := range inspection.Text {
		if i&255 == 0 && budget.useFallback() {
			budget.consumeMemory(memory)
			return budget.extractFallback(source)
		}
		state := &inspection.Text[i]
		e.states[state.Node] = state
	}
	for i := range inspection.Elements {
		if i&255 == 0 && budget.useFallback() {
			budget.consumeMemory(memory)
			return budget.extractFallback(source)
		}
		state := &inspection.Elements[i]
		e.elements[state.Node] = state
	}
	e.findBase(inspection.Root)
	comments := e.collectHTMLCommentStats(inspection.Root)
	tagged := e.render(TagHidden)
	stripped := ""
	if tagged.hasConcealed && !e.memoryExhausted {
		stripped = e.render(StripHidden).text
	}
	confidentChars := 0
	if !e.memoryExhausted {
		confidentChars = e.confidentVisibleCharacters(inspection.Text)
	}
	if e.memoryExhausted {
		budget.consumeMemory(memory)
		return extractedContent{
			Text: tagged.text, VisibleText: tagged.visible, StrippedText: stripped,
			Links: e.links.links, ImageRefs: e.images.refs, HasConcealedContent: tagged.hasConcealed,
			HTMLComments: comments, CSSIncomplete: inspection.UnresolvedStylesheet || inspection.Usage.CSSLimitExceeded,
			ExtractionIncomplete: true,
		}
	}
	if e.stopped || budget.useFallback() {
		budget.consumeMemory(memory)
		return budget.extractFallback(source)
	}
	cssIncomplete := inspection.UnresolvedStylesheet || inspection.Usage.CSSLimitExceeded
	if cssIncomplete {
		// Unevaluated or resource-limited CSS can alter any element in this
		// HTML part, so none of its text is sufficiently certain to suppress
		// image analysis.
		confidentChars = 0
	}
	budget.consumeMemory(memory)
	return extractedContent{
		Text: tagged.text, VisibleText: tagged.visible, ConfidentVisibleChars: confidentChars, StrippedText: stripped,
		Links: e.links.links, ImageRefs: e.images.refs, HasConcealedContent: tagged.hasConcealed,
		HTMLComments: comments, CSSIncomplete: cssIncomplete,
		ExtractionIncomplete: e.extractionIncomplete,
		HTMLCPULimitExceeded: budget.cpuLimitExceeded,
	}
}

func (budget *extractionBudget) extractFallback(source string) extractedContent {
	if budget.memoryStopped() {
		return extractedContent{ExtractionIncomplete: true, HTMLMemoryLimitExceeded: true}
	}
	content := extractBoundedHTMLFallback(source, budget.compactURLs, budget.fallbackStop)
	content.HTMLCPULimitExceeded = content.HTMLCPULimitExceeded || budget.cpuLimitExceeded
	return content
}

// confidentVisibleCharacters is deliberately separate from VisibleText.
// VisibleText is a useful human-facing estimate and retains uncertain content;
// only text positively classified as visible may suppress fallback image
// analysis. Generated link destinations and image descriptions are not DOM
// text nodes and therefore cannot inflate this count.
func (e *htmlExtraction) confidentVisibleCharacters(states []htmlextract.Text) int {
	count := 0
	for _, state := range states {
		if e.stopRequested() {
			return count
		}
		if state.Label != "visible" || state.Node == nil {
			continue
		}
		value := compactFormattingPadding(sanitizeSenderText(state.Node.Data))
		if value == "" || annotationWhitespaceOnly(value) {
			continue
		}
		count += confidentTextCharacters(value)
	}
	return count
}

func confidentTextCharacters(value string) int {
	value = normalizeHTMLText(compactFormattingPadding(sanitizeSenderText(value)))
	if value == "" || annotationWhitespaceOnly(value) {
		return 0
	}
	return utf8.RuneCountInString(value)
}

type htmlCommentStats struct {
	Characters  int
	WithinWords int
}

func (s *htmlCommentStats) add(other htmlCommentStats) {
	s.Characters += other.Characters
	s.WithinWords += other.WithinWords
}

func (e *htmlExtraction) collectHTMLCommentStats(root *xhtml.Node) htmlCommentStats {
	var stats htmlCommentStats
	var walk func(*xhtml.Node) bool
	walk = func(node *xhtml.Node) bool {
		if node == nil || e.stopRequested() {
			return !e.stopped
		}
		if node.Type == xhtml.CommentNode && !conditionalHTMLComment(node.Data) {
			stats.Characters += utf8.RuneCountInString(node.Data)
			if commentBetweenWordFragments(node) {
				stats.WithinWords++
			}
			return true
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			if !walk(child) {
				return false
			}
		}
		return true
	}
	walk(root)
	return stats
}

func conditionalHTMLComment(value string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "[if ")
}

func commentBetweenWordFragments(comment *xhtml.Node) bool {
	if comment.PrevSibling == nil || comment.NextSibling == nil || comment.PrevSibling.Type != xhtml.TextNode || comment.NextSibling.Type != xhtml.TextNode {
		return false
	}
	left, _ := utf8.DecodeLastRuneInString(comment.PrevSibling.Data)
	right, _ := utf8.DecodeRuneInString(comment.NextSibling.Data)
	return (unicode.IsLetter(left) || unicode.IsNumber(left)) && (unicode.IsLetter(right) || unicode.IsNumber(right))
}

type renderedHTML struct {
	text, visible string
	hasConcealed  bool
}

func (e *htmlExtraction) render(mode HTMLExtractionMode) renderedHTML {
	body := newAnnotatedOutput(e.memory)
	visible := newGuardedBuilder(e.memory)
	if !e.walk(e.inspection.Root, mode, &body, &visible) {
		return renderedHTML{}
	}
	if body.failed || visible.Failed() {
		e.stopForMemory()
		return renderedHTML{}
	}
	rawText, ok := body.String()
	if !ok {
		e.stopForMemory()
		return renderedHTML{}
	}
	if e.stopNow() {
		return renderedHTML{}
	}
	text, ok := normalizeHTMLTextGuarded(rawText, e.memory)
	if !ok {
		e.stopForMemory()
		return renderedHTML{}
	}
	if e.stopNow() {
		return renderedHTML{}
	}
	visibleText, ok := normalizeHTMLTextGuarded(visible.String(), e.memory)
	if !ok {
		e.stopForMemory()
		return renderedHTML{}
	}
	if e.stopNow() {
		return renderedHTML{}
	}
	return renderedHTML{text: text, visible: visibleText, hasConcealed: e.hasConcealed()}
}

func (e *htmlExtraction) stopRequested() bool {
	if e.stopped {
		return true
	}
	if e.memory.Exhausted() {
		e.stopForMemory()
		return true
	}
	e.workSteps++
	if e.workSteps == 1 || e.workSteps&255 == 0 {
		return e.stopNow()
	}
	return false
}

func (e *htmlExtraction) stopForMemory() {
	e.stopped = true
	e.memoryExhausted = true
	e.extractionIncomplete = true
}

func (e *htmlExtraction) stopNow() bool {
	if e.stopped {
		return true
	}
	if e.shouldStop != nil && e.shouldStop() {
		e.stopped = true
		e.extractionIncomplete = true
	}
	return e.stopped
}

func (e *htmlExtraction) hasConcealed() bool {
	for _, state := range e.inspection.Text {
		if e.stopRequested() {
			return false
		}
		if state.Label == "concealed" && state.Node != nil && strings.TrimSpace(state.Node.Data) != "" {
			return true
		}
	}
	for _, state := range e.inspection.Elements {
		if e.stopRequested() {
			return false
		}
		if state.Label == "concealed" && state.Node != nil {
			name := strings.ToLower(state.Node.Data)
			if name == "img" || name == "input" {
				return true
			}
		}
	}
	return false
}

func (e *htmlExtraction) walk(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) bool {
	if n == nil || e.stopRequested() {
		return !e.stopped
	}
	if n.Type == xhtml.TextNode {
		e.writeText(n, mode, out, visible)
		return true
	}
	if n.Type == xhtml.CommentNode {
		e.writeConditionalComment(n.Data, out, visible)
		return !e.stopped
	}
	if n.Type != xhtml.ElementNode && n.Type != xhtml.DocumentNode {
		return true
	}
	name := strings.ToLower(n.Data)
	if omittedHTMLElement(name) {
		return true
	}
	if name == "img" {
		e.writeImage(n, mode, out, visible)
		return true
	}
	if name == "input" {
		typ := strings.ToLower(strings.TrimSpace(firstAttr(n, "type")))
		if typ == "submit" || typ == "button" || typ == "reset" {
			label := sanitizeSenderText(firstAttr(n, "value"))
			e.writeElementContent(n, label, mode, out, visible)
		}
		return true
	}
	if isBlockElement(name) || name == "br" || name == "hr" {
		out.WriteByte('\n')
		visible.appendByte('\n')
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
		label := newAnnotatedOutput(e.memory)
		visibleLabel := newGuardedBuilder(e.memory)
		e.anchorDepth++
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if !e.walk(child, mode, &label, &visibleLabel) {
				e.anchorDepth--
				return false
			}
		}
		e.anchorDepth--
		if label.failed || visibleLabel.Failed() {
			e.stopForMemory()
			return false
		}
		destination, ok := e.destination(firstAttr(n, "href"))
		if ok {
			destination = e.links.AddDestination(destination)
			plain := strings.TrimSpace(label.plainText())
			if plain == "" {
				plain = "link"
			}
			if annotation, uniform := label.uniformAnnotation(); uniform {
				out.write(annotation, "[")
				out.write(annotation, plain)
				out.write(annotation, "](")
				out.write(annotation, markdownURL(destination))
				out.write(annotation, ")")
			} else {
				// Preserve distinct child annotations when a label crosses a real
				// visibility boundary.
				out.WriteByte('[')
				annotatedLabel, complete := label.String()
				if !complete {
					e.stopForMemory()
					return false
				}
				out.WriteString(strings.TrimSpace(annotatedLabel))
				out.WriteString("](")
				out.WriteString(markdownURL(destination))
				out.WriteByte(')')
			}
		} else {
			for _, chunk := range label.chunks {
				out.writeBytes(chunk.annotation, label.chunkBytes(chunk))
			}
		}
		visible.WriteString(visibleLabel.String())
		return true
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if !e.walk(child, mode, out, visible) {
			return false
		}
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
		visible.appendByte('\n')
	}
	return true
}

func (e *htmlExtraction) writeElementContent(n *xhtml.Node, content string, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	if content == "" {
		return
	}
	promptContent, _ := rewritePlainTextURLs(content, e.compactURLs, &e.links, e.stopNow)
	state := e.elements[n]
	if state == nil {
		out.WriteString(promptContent)
		visible.WriteString(content)
		return
	}
	switch state.Label {
	case "concealed":
		if mode == StripHidden {
			out.write(outputAnnotation{kind: "stripped"}, promptContent)
			return
		}
		reason, value := elementConcealmentReason(state)
		out.write(outputAnnotation{kind: "concealed", reason: reason, value: value}, promptContent)
	case "client-dependent":
		out.write(outputAnnotation{kind: "client-dependent"}, promptContent)
		visible.WriteString(content)
	case "unknown":
		out.write(outputAnnotation{kind: "unknown"}, promptContent)
		visible.WriteString(content)
	default:
		out.WriteString(promptContent)
		visible.WriteString(content)
	}
}

func (e *htmlExtraction) writeConditionalComment(data string, out *annotatedOutput, visible *guardedBuilder) {
	trimmed := strings.TrimSpace(data)
	if !conditionalHTMLComment(trimmed) {
		return
	}
	start := strings.Index(trimmed, "]>")
	end := lastIndexASCIIFold(trimmed, "<![endif]")
	if start < 0 || end <= start+2 {
		return
	}
	raw := trimmed[start+2 : end]
	if len(raw) > maxConditionalFragmentBytes {
		e.omitConditionalComment(out)
		return
	}
	fragment, err := xhtml.ParseFragmentWithOptions(strings.NewReader(raw), nil,
		xhtml.ParseOptionEnableScripting(false),
		xhtml.ParseOptionResourceLimits(xhtml.ResourceLimits{
			ShouldStop: e.shouldStop,
			Memory:     e.memory,
		}),
	)
	if err != nil || (e.shouldStop != nil && e.shouldStop()) {
		e.omitConditionalComment(out)
		return
	}
	content := newGuardedBuilder(e.memory)
	walk := conditionalWalk{links: linkCollector{compactURLs: e.compactURLs, memory: e.memory, shouldStop: e.shouldStop}, memory: e.memory, shouldStop: e.shouldStop}
	for _, node := range fragment {
		if !e.walkConditionalNode(node, &content, &walk, 0) {
			e.omitConditionalComment(out)
			return
		}
	}
	value, ok := normalizeHTMLTextGuarded(content.String(), e.memory)
	if !ok {
		e.stopForMemory()
		return
	}
	if value == "" || annotationWhitespaceOnly(value) {
		return
	}
	for _, destination := range walk.links.links {
		e.links.AddDestination(destination)
	}
	out.write(outputAnnotation{kind: "unknown"}, value)
	visible.WriteString(value)
}

func (e *htmlExtraction) omitConditionalComment(out *annotatedOutput) {
	e.extractionIncomplete = true
	out.WriteString("\n" + conditionalOmissionMarker + "\n")
}

// lastIndexASCIIFold finds an ASCII syntax marker without transforming the
// input. Unicode case conversion can change a string's byte length, making an
// index obtained from the converted copy unsafe for slicing the original.
func lastIndexASCIIFold(value, marker string) int {
	if marker == "" {
		return len(value)
	}
	for start := len(value) - len(marker); start >= 0; start-- {
		matched := true
		for i := range marker {
			left, right := value[start+i], marker[i]
			if left >= 'A' && left <= 'Z' {
				left += 'a' - 'A'
			}
			if right >= 'A' && right <= 'Z' {
				right += 'a' - 'A'
			}
			if left != right {
				matched = false
				break
			}
		}
		if matched {
			return start
		}
	}
	return -1
}

type conditionalWalk struct {
	nodes       int
	links       linkCollector
	anchorDepth int
	memory      *resourceguard.Memory
	shouldStop  func() bool
}

func (w *conditionalWalk) enter(depth int) bool {
	if !w.memory.Reserve(64) {
		return false
	}
	w.nodes++
	if w.nodes&255 == 0 && w.shouldStop != nil && w.shouldStop() {
		return false
	}
	return true
}

func (w *conditionalWalk) writeString(out *guardedBuilder, value string) bool {
	return out.WriteString(value)
}

func (e *htmlExtraction) walkConditionalNode(n *xhtml.Node, out *guardedBuilder, walk *conditionalWalk, depth int) bool {
	if !walk.enter(depth) {
		return false
	}
	if n.Type == xhtml.TextNode {
		value := sanitizeSenderText(n.Data)
		if walk.anchorDepth > 0 {
			value, _ = rewritePlainTextURLs(value, e.compactURLs, nil, walk.shouldStop)
		} else {
			value, _ = rewritePlainTextURLs(value, e.compactURLs, &walk.links, walk.shouldStop)
		}
		return walk.writeString(out, value)
	}
	if n.Type != xhtml.ElementNode && n.Type != xhtml.DocumentNode {
		return true
	}
	name := strings.ToLower(n.Data)
	// Outlook conditionals can contain Office configuration XML alongside
	// alternate message markup. It is presentation code, not recipient-facing
	// fallback content.
	if omittedHTMLElement(name) || name == "xml" || strings.HasPrefix(name, "o:") {
		return true
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "a") {
		label := newGuardedBuilder(walk.memory)
		walk.anchorDepth++
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if !e.walkConditionalNode(child, &label, walk, depth+1) {
				walk.anchorDepth--
				return false
			}
		}
		walk.anchorDepth--
		if destination, ok := e.destination(firstAttr(n, "href")); ok {
			destination = walk.links.AddDestination(destination)
			if !walk.writeString(out, "[") ||
				!walk.writeString(out, markdownLabelText(strings.TrimSpace(label.String()))) ||
				!walk.writeString(out, "](") ||
				!walk.writeString(out, markdownURL(destination)) ||
				!walk.writeString(out, ")") {
				return false
			}
		} else {
			if !walk.writeString(out, label.String()) {
				return false
			}
		}
		return true
	}
	if isBlockElement(name) || strings.EqualFold(n.Data, "br") {
		if !walk.writeString(out, "\n") {
			return false
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if !e.walkConditionalNode(child, out, walk, depth+1) {
			return false
		}
	}
	if isBlockElement(name) {
		if !walk.writeString(out, "\n") {
			return false
		}
	}
	return true
}

func (e *htmlExtraction) writeText(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	text := compactFormattingPadding(sanitizeSenderText(n.Data))
	if text == "" {
		return
	}
	state := e.states[n]
	if state == nil {
		return // source in head/style/script/title/template or another inert scope
	}
	var outText string
	if e.anchorDepth > 0 {
		// Text resembling a URL inside an anchor label is sender-visible text,
		// not an independently validated destination.
		outText, _ = rewritePlainTextURLs(text, e.compactURLs, nil, e.stopNow)
		outText = markdownLabelText(outText)
	} else {
		outText, _ = rewritePlainTextURLs(text, e.compactURLs, &e.links, e.stopNow)
	}
	// Presentation annotations around whitespace add noise without carrying a
	// visibility claim about message content. This includes decoded HTML space
	// entities such as &nbsp; (U+00A0) and standalone runs of invisible formatting
	// characters. Formatting characters embedded in meaningful text still follow
	// that text's visibility state and remain available as obfuscation evidence.
	if annotationWhitespaceOnly(text) {
		// Source indentation between inline elements is ordinary collapsible HTML
		// whitespace, not a rendered line break. Preserve non-collapsible Unicode
		// spacing and formatting evidence, while folding ASCII HTML whitespace to
		// the single space a browser would render.
		spacing := outText
		if inlineFormattingGap(n) {
			spacing = collapseHTMLFormattingWhitespace(outText)
		}
		out.WriteString(spacing)
		if state.Label != "concealed" {
			visible.WriteString(spacing)
		}
		return
	}
	switch state.Label {
	case "concealed":
		if mode == StripHidden {
			out.write(outputAnnotation{kind: "stripped"}, outText)
			return
		}
		reason, value := concealmentReason(state)
		out.write(outputAnnotation{kind: "concealed", reason: reason, value: value}, outText)
	case "client-dependent":
		out.write(outputAnnotation{kind: "client-dependent"}, outText)
		visible.WriteString(text)
	case "unknown":
		out.write(outputAnnotation{kind: "unknown"}, outText)
		visible.WriteString(text)
	default:
		out.WriteString(outText)
		visible.WriteString(text)
	}
}

func inlineFormattingGap(n *xhtml.Node) bool {
	return inlineRenderedNode(n.PrevSibling) && inlineRenderedNode(n.NextSibling)
}

func inlineRenderedNode(n *xhtml.Node) bool {
	if n == nil {
		return false
	}
	if n.Type == xhtml.TextNode {
		return !annotationWhitespaceOnly(n.Data)
	}
	if n.Type != xhtml.ElementNode {
		return false
	}
	name := strings.ToLower(n.Data)
	return !omittedHTMLElement(name) && !isBlockElement(name) && name != "br" && name != "hr" && !inlineStyleUsesBlockLayout(n)
}

func inlineStyleUsesBlockLayout(n *xhtml.Node) bool {
	block := false
	for declaration := range strings.SplitSeq(firstAttr(n, "style"), ";") {
		property, value, found := strings.Cut(declaration, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(property), "display") {
			continue
		}
		value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), "!important")))
		switch value {
		case "block", "flow-root", "flex", "grid", "list-item", "table", "table-row", "table-cell", "table-caption":
			block = true
		case "inline", "inline-block", "inline-flex", "inline-grid", "contents":
			block = false
		}
	}
	return block
}

func collapseHTMLFormattingWhitespace(value string) string {
	var out strings.Builder
	pendingSpace := false
	for _, r := range value {
		switch r {
		case ' ', '\t', '\n', '\f', '\r':
			pendingSpace = true
		default:
			if pendingSpace {
				out.WriteByte(' ')
				pendingSpace = false
			}
			out.WriteRune(r)
		}
	}
	if pendingSpace {
		out.WriteByte(' ')
	}
	return out.String()
}

// Email preheaders commonly repeat a mixture of spaces and default-ignorable
// Unicode characters hundreds of times to occupy inbox-preview width. Preserve
// a small sample as evidence, but do not let formatting-only padding dominate
// the LLM input. Ordinary whitespace and short obfuscation runs are unchanged.
func compactFormattingPadding(value string) string {
	const threshold, retained = 32, 8
	runLength := 0
	hasFormat := false
	needsCompaction := false
	for _, r := range value {
		if !preheaderPaddingRune(r) {
			runLength = 0
			hasFormat = false
			continue
		}
		runLength++
		hasFormat = hasFormat || !unicode.IsSpace(r)
		if runLength >= threshold && hasFormat {
			needsCompaction = true
			break
		}
	}
	if !needsCompaction {
		return value
	}
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

func annotationWhitespaceOnlyBytes(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if !preheaderPaddingRune(r) {
			return false
		}
		value = value[size:]
	}
	return true
}

func concealmentReason(state *htmlextract.Text) (string, string) {
	return formatConcealmentReason(state.ConcealmentReasons, state.EffectiveOpacity, state.FontSize)
}

func formatConcealmentReason(reasons htmlextract.ConcealmentReason, opacity float64, fontSize string) (string, string) {
	switch reasons.Primary() {
	case htmlextract.ReasonDisplayNone:
		return "display:none", ""
	case htmlextract.ReasonVisibilityHidden:
		return "visibility:hidden", ""
	case htmlextract.ReasonVisibilityCollapse:
		return "visibility:collapse", ""
	case htmlextract.ReasonOpacity:
		return "opacity", strconv.FormatFloat(opacity, 'g', 6, 64)
	case htmlextract.ReasonFontSize:
		return "font-size", fontSize
	case htmlextract.ReasonColour:
		return "color-match", ""
	case htmlextract.ReasonEmptyClip:
		return "empty-clip", ""
	case htmlextract.ReasonContentVisibility:
		return "content-visibility:hidden", ""
	}
	return "display:none", ""
}

func (e *htmlExtraction) writeImage(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	if explicitTrackingPixel(n) {
		return
	}
	raw := strings.TrimSpace(firstAttr(n, "src"))
	alt := sanitizeSenderText(firstAttr(n, "alt"))
	alt, _ = rewritePlainTextURLs(alt, e.compactURLs, nil, e.stopNow)
	var destination string
	if strings.HasPrefix(strings.ToLower(raw), "cid:") {
		id := normalizeContentID(raw[4:])
		if id == "" {
			return
		}
		if alt == "" {
			alt = "embedded image"
		}
		destination = "cid:" + markdownURL(id)
		e.images.Add(id)
	} else if resolved, ok := e.destination(raw); ok && (strings.HasPrefix(resolved, "http://") || strings.HasPrefix(resolved, "https://")) {
		if alt == "" {
			alt = "image"
		}
		destination = markdownURL(e.links.AddDestination(resolved))
	}
	if destination == "" {
		return
	}
	annotation := outputAnnotation{}
	state := e.elements[n]
	if state != nil {
		switch state.Label {
		case "concealed":
			if mode == StripHidden {
				annotation = outputAnnotation{kind: "stripped"}
			} else {
				reason, value := elementConcealmentReason(state)
				annotation = outputAnnotation{kind: "concealed", reason: reason, value: value}
			}
		case "client-dependent":
			annotation = outputAnnotation{kind: "client-dependent"}
		case "unknown":
			annotation = outputAnnotation{kind: "unknown"}
		}
	}
	out.write(annotation, " ![")
	out.write(annotation, markdownLabelText(alt))
	out.write(annotation, "](")
	out.write(annotation, destination)
	out.write(annotation, ") ")
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

func elementConcealmentReason(state *htmlextract.Element) (string, string) {
	return formatConcealmentReason(state.ConcealmentReasons, state.EffectiveOpacity, state.FontSize)
}

func (e *htmlExtraction) findBase(n *xhtml.Node) bool {
	if n == nil || e.baseSeen || e.stopRequested() {
		return !e.stopped
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "template") {
		return true
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "base") {
		raw, present := attrPresent(n, "href")
		if present {
			e.baseSeen = true
			if parsed, err := url.Parse(strings.TrimSpace(raw)); err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				e.base = parsed
			}
			return true // first base href wins even when unusable
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if !e.findBase(child) {
			return false
		}
	}
	return true
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
	case "head", "style", "script", "title", "template", "iframe":
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

func sanitizeSenderText(value string) string {
	if !strings.Contains(value, "<") {
		return value
	}
	return reservedAnnotation.ReplaceAllString(value, "")
}

func normalizeHTMLText(value string) string {
	result, _ := normalizeHTMLTextGuarded(value, nil)
	return result
}

func normalizeHTMLTextGuarded(value string, memory *resourceguard.Memory) (string, bool) {
	b := newGuardedBuilder(memory)
	if !b.Grow(len(value)) {
		return "", false
	}
	space, newlines := false, 0
	for offset := 0; offset < len(value); {
		r, size := utf8.DecodeRuneInString(value[offset:])
		offset += size
		if r == utf8.RuneError && size == 1 {
			// Match strings.ToValidUTF8 by replacing each consecutive run of
			// invalid bytes with one replacement rune.
			for offset < len(value) {
				nextRune, nextSize := utf8.DecodeRuneInString(value[offset:])
				if nextRune != utf8.RuneError || nextSize != 1 {
					break
				}
				offset++
			}
		}
		switch r {
		case ' ', '\t', '\f':
			space = true
		case '\r', '\n':
			space = false
			if b.Len() > 0 && newlines < 2 {
				b.appendByte('\n')
				newlines++
			}
		default:
			if space && b.Len() > 0 && newlines == 0 {
				b.appendByte(' ')
			}
			space, newlines = false, 0
			if r < utf8.RuneSelf {
				b.appendByte(byte(r))
			} else {
				b.appendRune(r)
			}
		}
	}
	if b.Failed() {
		return "", false
	}
	return strings.Trim(b.String(), " \t\r\n\f"), true
}

func (collector *linkCollector) AddDestination(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}
	if rendered, exists := collector.rendered[candidate]; exists {
		return rendered
	}
	if collector.Full() {
		return candidate
	}
	raw := candidate
	var ok bool
	candidate, ok = promptURLWithBudget(raw, collector.compactURLs, collector.memory, collector.shouldStop)
	if !ok {
		return ""
	}
	if collector.seen == nil {
		collector.seen = make(map[string]struct{})
	}
	if _, exists := collector.seen[candidate]; exists {
		return candidate
	}
	characters := utf8.RuneCountInString(candidate)
	if len(collector.links) >= maxExtractedLinks || collector.chars+characters > maxExtractedLinkChars {
		collector.full = true
		return candidate
	}
	if collector.rendered == nil {
		collector.rendered = make(map[string]string)
	}
	collector.rendered[raw] = candidate
	collector.seen[candidate] = struct{}{}
	collector.links = append(collector.links, candidate)
	collector.chars += characters
	return candidate
}
