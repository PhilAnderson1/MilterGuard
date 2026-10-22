package message

import (
	"net/url"
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
	UsedQuotedContentTag                  bool
}

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
	shouldStop           func()
	textShouldStop       func()
	textClockCheck       func() // for loops which already sample their work
	textStopSampler      resourceguard.StopSampler
	memory               *resourceguard.Memory
	extractionIncomplete bool
	workSampler          resourceguard.StopSampler
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
}

func newAnnotatedOutput(memory *resourceguard.Memory) annotatedOutput {
	return annotatedOutput{data: newGuardedBuilder(memory), memory: memory}
}

func (o *annotatedOutput) WriteString(value string) { o.write(outputAnnotation{}, value) }
func (o *annotatedOutput) WriteByte(value byte) error {
	start := o.data.Len()

	o.data.appendByte(value)

	o.extendChunk(outputAnnotation{}, start)

	return nil
}

func (o *annotatedOutput) write(annotation outputAnnotation, value string) {
	if value == "" {
		return
	}
	start := o.data.Len()

	o.data.WriteString(value)

	o.extendChunk(annotation, start)
}

func (o *annotatedOutput) writeBytes(annotation outputAnnotation, value []byte) {
	if len(value) == 0 {
		return
	}
	start := o.data.Len()

	o.data.Write(value)

	o.extendChunk(annotation, start)
}

func (o *annotatedOutput) extendChunk(annotation outputAnnotation, start int) {
	if len(o.chunks) > 0 && o.chunks[len(o.chunks)-1].annotation == annotation {
		o.chunks[len(o.chunks)-1].end = o.data.Len()
		return
	}
	if len(o.chunks) == cap(o.chunks) {
		grown := growGuardedSlice(o.chunks, len(o.chunks)+1, o.memory)

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

func (o *annotatedOutput) uniformAnnotation(stop resourceguard.Stop) (outputAnnotation, bool) {
	var found outputAnnotation
	haveContent := false
	for _, chunk := range o.chunks {
		if stop != nil {
			stop()
		}
		if annotationWhitespaceOnlyBytesWithStop(o.chunkBytes(chunk), stop) {
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

func (o *annotatedOutput) renderAnnotations(stop resourceguard.Stop) string {
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
		if stop != nil {
			stop()
		}
		value := o.chunkBytes(chunk)
		if annotationWhitespaceOnlyBytesWithStop(value, stop) {
			pending.writeWithStop(value, stop)
			continue
		}
		if chunk.annotation.kind == "stripped" {
			closeActive()
			out.writeWithStop(pending.Bytes(), stop)
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
			out.writeWithStop(pending.Bytes(), stop)
			pending.Reset()
			out.writeWithStop(value, stop)
			continue
		}
		if !haveActive || active != chunk.annotation {
			closeActive()
			out.writeWithStop(pending.Bytes(), stop)
			pending.Reset()
			open(chunk.annotation)
			active = chunk.annotation
			haveActive = true
		} else {
			out.writeWithStop(pending.Bytes(), stop)
			pending.Reset()
		}
		out.writeWithStop(value, stop)
	}
	closeActive()
	out.writeWithStop(pending.Bytes(), stop)

	return out.String()
}

func htmlToTextWithBudget(source string, budget *extractionBudget) extractedContent {
	budget.htmlParts++
	budget.checkStage()
	if budget.fallback != nil {
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

func extractTreeHTMLWithLimits(source string, limits htmlextract.Limits, budget *extractionBudget) extractedContent {
	if budget.stageStop == nil {
		budget.stageStop = resourceguard.BindCheckpoint(budget.allocationMemory(), budget, (*extractionBudget).checkStage)
	}
	var inspection htmlextract.Document
	var err error

	inspection, err = analyzeControlledHTML(source, limits, budget)
	budget.checkStage()
	if err != nil {
		// A bounded lexical fallback retains evidence when tree/style processing
		// cannot complete. It is explicitly reported as incomplete extraction.
		content := budget.extractFallback(source)
		content.ExtractionIncomplete = true
		return content
	}
	memory := budget.newMemory(budget.remainingMemory())

	defer budget.consumeMemory(memory)

	mapBytes := int64(len(inspection.Text)+len(inspection.Elements))*64 + 256

	memory.Reserve(mapBytes)

	e := htmlExtraction{
		workSampler: resourceguard.NewStopSampler(256, budget.stageStop),
		images:      imageRefCollector{memory: memory},
		inspection:  inspection,
		states:      make(map[*xhtml.Node]*htmlextract.Text, len(inspection.Text)),
		elements:    make(map[*xhtml.Node]*htmlextract.Element, len(inspection.Elements)),
		compactURLs: budget.compactURLs,
		links:       linkCollector{compactURLs: budget.compactURLs, memory: memory, shouldStop: budget.checkStage},
		shouldStop:  budget.checkStage,
		memory:      memory,
	}
	for i := range inspection.Text {
		if i&255 == 0 {
			budget.checkStage()
		}
		state := &inspection.Text[i]
		e.states[state.Node] = state
	}
	for i := range inspection.Elements {
		if i&255 == 0 {
			budget.checkStage()
		}
		state := &inspection.Elements[i]
		e.elements[state.Node] = state
	}
	e.findBase(inspection.Root)
	comments := e.collectHTMLCommentStats(inspection.Root)
	tagged := e.render(TagHidden)
	stripped := ""
	if tagged.hasConcealed {
		stripped = e.render(StripHidden).text
	}
	confidentChars := 0

	confidentChars = e.confidentVisibleCharacters(inspection.Text)

	budget.checkStage()
	cssIncomplete := inspection.UnresolvedStylesheet || inspection.Usage.CSSLimitExceeded
	if cssIncomplete {
		// Unevaluated or resource-limited CSS can alter any element in this
		// HTML part, so none of its text is sufficiently certain to suppress
		// image analysis.
		confidentChars = 0
	}
	return extractedContent{
		Text: tagged.text, VisibleText: tagged.visible, ConfidentVisibleChars: confidentChars, StrippedText: stripped,
		Links: e.links.links, ImageRefs: e.images.refs, HasConcealedContent: tagged.hasConcealed,
		HTMLComments: comments, CSSIncomplete: cssIncomplete,
		ExtractionIncomplete: e.extractionIncomplete,
		HTMLCPULimitExceeded: budget.cpuLimitExceeded,
	}
}

func (budget *extractionBudget) extractFallback(source string) extractedContent {
	if !budget.beginFallback() {
		return extractedContent{ExtractionIncomplete: true, HTMLMemoryLimitExceeded: budget.memoryLimitExceeded, HTMLCPULimitExceeded: budget.cpuLimitExceeded}
	}
	var content extractedContent
	{
		var complete bool
		budget.fallback.prefix = ""
		content, complete = runExtraction(budget, func() extractedContent {
			return extractBoundedHTMLFallback(source, budget.compactURLs, budget.fallback)
		})
		if !complete {
			prefix := budget.fallback.prefix
			if strings.Contains(prefix, "<") || !utf8.ValidString(prefix) {
				prefix = ""
			}
			content = extractedContent{Text: prefix, HTMLFallbackUsed: true, ExtractionIncomplete: true}
		}
	}

	budget.observeFallback()
	content.HTMLCPULimitExceeded = content.HTMLCPULimitExceeded || budget.cpuLimitExceeded
	content.HTMLMemoryLimitExceeded = content.HTMLMemoryLimitExceeded || budget.fallbackMemoryExceeded
	content.HTMLFallbackMemoryLimitExceeded = budget.fallbackMemoryExceeded
	return content
}

// confidentVisibleCharacters is deliberately separate from VisibleText.
// VisibleText is a useful human-facing estimate and retains uncertain content;
// only text positively classified as visible may suppress fallback image
// analysis. Generated link destinations and image descriptions are not DOM
// text nodes and therefore cannot inflate this count.
func (e *htmlExtraction) confidentVisibleCharacters(states []htmlextract.Text) int {
	stop := e.textStopCallback()

	count := 0
	for _, state := range states {
		e.stopRequested()

		if state.Label != "visible" || state.Node == nil {
			continue
		}
		value := prepareVisibleText(state.Node.Data, e.memory, stop)

		if value == "" || annotationWhitespaceOnly(value, stop) {
			continue
		}
		characters := confidentTextCharactersWithResources(value, e.memory, stop)

		count += characters
	}
	return count
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
	var walk func(*xhtml.Node)
	walk = func(node *xhtml.Node) {
		if node == nil {
			return
		}
		e.stopRequested()
		if node.Type == xhtml.CommentNode && !conditionalHTMLComment(node.Data) {
			stats.Characters += utf8.RuneCountInString(node.Data)
			if commentBetweenWordFragments(node) {
				stats.WithinWords++
			}
			return
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
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

	e.walk(e.inspection.Root, mode, &body, &visible)

	stop := e.textStopCallback()
	rawText := body.renderAnnotations(stop)

	e.stopNow()

	text := normalizeHTMLTextWithResources(rawText, e.memory, stop)

	e.stopNow()

	visibleText := normalizeHTMLTextWithResources(visible.String(), e.memory, stop)

	e.stopNow()

	return renderedHTML{text: text, visible: visibleText, hasConcealed: e.hasConcealed()}
}

func (e *htmlExtraction) stopRequested() {
	e.workSampler.Check()
}

func (e *htmlExtraction) stopNow() {
	if e.shouldStop != nil {
		e.shouldStop()
	}
}

func (e *htmlExtraction) hasConcealed() bool {
	for _, state := range e.inspection.Text {
		e.stopRequested()

		if state.Label == "concealed" && state.Node != nil && strings.TrimSpace(state.Node.Data) != "" {
			return true
		}
	}
	for _, state := range e.inspection.Elements {
		e.stopRequested()

		if state.Label == "concealed" && state.Node != nil {
			name := strings.ToLower(state.Node.Data)
			if name == "img" || name == "input" {
				return true
			}
		}
	}
	return false
}

func (e *htmlExtraction) walk(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	if n == nil {
		return
	}
	e.stopRequested()

	if n.Type == xhtml.TextNode {
		e.writeText(n, mode, out, visible)
		return
	}
	if n.Type == xhtml.CommentNode {
		e.writeConditionalComment(n.Data, out, visible)
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
		e.writeImage(n, mode, out, visible)
		return
	}
	if name == "input" {
		typ := strings.ToLower(strings.TrimSpace(firstAttr(n, "type")))
		if typ == "submit" || typ == "button" || typ == "reset" {
			label := sanitizeSenderTextWithResources(firstAttr(n, "value"), e.memory, e.textStopCallback())
			e.writeElementContent(n, label, mode, out, visible)
		}
		return
	}
	if isBlockElement(name) || name == "br" || name == "hr" {
		out.WriteByte('\n')
		visible.appendByte('\n')
	}
	if name == "blockquote" {
		marker := "<quoted-content>\n"
		if e.anchorDepth > 0 {
			marker = "<quoted-content> "
		}
		out.WriteString(marker)
		visible.WriteString("<quoted-content>\n")
	}
	if name == "a" {
		label := newAnnotatedOutput(e.memory)
		visibleLabel := newGuardedBuilder(e.memory)
		e.anchorDepth++
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			e.walk(child, mode, &label, &visibleLabel)
		}
		e.anchorDepth--

		destination, ok := e.destination(firstAttr(n, "href"))
		if ok {
			destination = e.links.AddDestination(destination)
			plain := strings.TrimSpace(label.plainText())
			if plain == "" {
				plain = "link"
			}

			stop := e.textStopCallback()
			if annotation, uniform := label.uniformAnnotation(stop); uniform {
				out.write(annotation, "[")
				out.write(annotation, plain)
				out.write(annotation, "](")
				out.write(annotation, escapeMarkdown(destination, true, e.memory, e.stopNow))
				out.write(annotation, ")")
			} else {
				{
					// Preserve distinct child annotations when a label crosses a real
					// visibility boundary.
					out.WriteByte('[')
					annotatedLabel := label.renderAnnotations(stop)

					out.WriteString(strings.TrimSpace(annotatedLabel))
					out.WriteString("](")
					out.WriteString(escapeMarkdown(destination, true, e.memory, e.stopNow))
					out.WriteByte(')')
				}
			}

		} else {
			for _, chunk := range label.chunks {
				out.writeBytes(chunk.annotation, label.chunkBytes(chunk))
			}
		}
		visible.WriteString(visibleLabel.String())
		return
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.walk(child, mode, out, visible)
	}
	if name == "blockquote" {
		marker := "\n</quoted-content>"
		if e.anchorDepth > 0 {
			marker = " </quoted-content>"
		}
		out.WriteString(marker)
		visible.WriteString("\n</quoted-content>")
	}
	if isBlockElement(name) {
		out.WriteByte('\n')
		visible.appendByte('\n')
	}
	return
}

func (e *htmlExtraction) writeElementContent(n *xhtml.Node, content string, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	if content == "" {
		return
	}

	e.textStopCallback()

	promptContent := rewritePlainTextURLs(content, e.compactURLs, &e.links, e.memory, e.textClockCheck)
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

	if err != nil {
		e.omitConditionalComment(out)
		return
	}
	if e.shouldStop != nil {
		e.shouldStop()
	}

	content := newGuardedBuilder(e.memory)
	walk := conditionalWalk{links: linkCollector{compactURLs: e.compactURLs, memory: e.memory, shouldStop: e.shouldStop}, memory: e.memory, shouldStop: e.shouldStop}
	for _, node := range fragment {
		e.walkConditionalNode(node, &content, &walk, 0)
	}
	stop := e.textStopCallback()
	value := normalizeHTMLTextWithResources(content.String(), e.memory, stop)

	if value == "" || annotationWhitespaceOnly(value, stop) {
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
	shouldStop  func()
}

func (w *conditionalWalk) enter(depth int) {
	w.memory.Reserve(64)

	w.nodes++

	if w.nodes&255 == 0 && w.shouldStop != nil {
		w.shouldStop()
	}

	return
}

func (w *conditionalWalk) writeString(out *guardedBuilder, value string) {
	out.WriteString(value)
	return
}

func (e *htmlExtraction) walkConditionalNode(n *xhtml.Node, out *guardedBuilder, walk *conditionalWalk, depth int) {
	walk.enter(depth)

	if n.Type == xhtml.TextNode {
		value := sanitizeSenderTextWithResources(n.Data, walk.memory, walk.shouldStop)
		if walk.anchorDepth > 0 {
			value = rewritePlainTextURLs(value, e.compactURLs, nil, walk.memory, walk.shouldStop)
		} else {
			value = rewritePlainTextURLs(value, e.compactURLs, &walk.links, walk.memory, walk.shouldStop)
		}
		walk.writeString(out, value)
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
		label := newGuardedBuilder(walk.memory)
		walk.anchorDepth++
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			e.walkConditionalNode(child, &label, walk, depth+1)
		}
		walk.anchorDepth--

		if destination, ok := e.destination(firstAttr(n, "href")); ok {
			destination = walk.links.AddDestination(destination)

			walk.writeString(out, "[")
			walk.writeString(out, escapeMarkdown(strings.TrimSpace(label.String()), false, walk.memory, walk.shouldStop))
			walk.writeString(out, "](")
			walk.writeString(out, escapeMarkdown(destination, true, e.memory, e.stopNow))
			walk.writeString(out, ")")
		} else {
			walk.writeString(out, label.String())
		}

		return
	}
	if isBlockElement(name) || strings.EqualFold(n.Data, "br") {
		walk.writeString(out, "\n")
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.walkConditionalNode(child, out, walk, depth+1)
	}
	if isBlockElement(name) {
		walk.writeString(out, "\n")
	}
	return
}

func (e *htmlExtraction) writeText(n *xhtml.Node, mode HTMLExtractionMode, out *annotatedOutput, visible *guardedBuilder) {
	stop := e.textStopCallback()

	text := prepareVisibleText(n.Data, e.memory, stop)

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
		outText = rewritePlainTextURLs(text, e.compactURLs, nil, e.memory, e.textClockCheck)
		outText = escapeMarkdown(outText, false, e.memory, e.textClockCheck)
	} else {
		outText = rewritePlainTextURLs(text, e.compactURLs, &e.links, e.memory, e.textClockCheck)
	}
	// Presentation annotations around whitespace add noise without carrying a
	// visibility claim about message content. This includes decoded HTML space
	// entities such as &nbsp; (U+00A0) and standalone runs of invisible formatting
	// characters. Formatting characters embedded in meaningful text still follow
	// that text's visibility state and remain available as obfuscation evidence.
	if annotationWhitespaceOnly(text, stop) {
		// Source indentation between inline elements is ordinary collapsible HTML
		// whitespace, not a rendered line break. Preserve non-collapsible Unicode
		// spacing and formatting evidence, while folding ASCII HTML whitespace to
		// the single space a browser would render.
		spacing := outText
		if inlineFormattingGap(n, stop) {
			spacing = collapseHTMLFormattingWhitespace(outText, e.memory, stop)
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

func inlineFormattingGap(n *xhtml.Node, stop resourceguard.Stop) bool {
	return inlineRenderedNode(n.PrevSibling, stop) && inlineRenderedNode(n.NextSibling, stop)
}

func inlineRenderedNode(n *xhtml.Node, stop resourceguard.Stop) bool {
	if n == nil {
		return false
	}
	if n.Type == xhtml.TextNode {
		return !annotationWhitespaceOnly(n.Data, stop)
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

func collapseHTMLFormattingWhitespace(value string, memory *resourceguard.Memory, stop resourceguard.Stop) string {
	out := newGuardedBuilder(memory)
	out.Grow(len(value))
	pendingSpace := false
	nextCheck := 0
	for offset, r := range value {
		if offset >= nextCheck {
			if stop != nil {
				stop()
			}
			nextCheck = offset + resourceguard.WorkChunk
		}
		switch r {
		case ' ', '\t', '\n', '\f', '\r':
			pendingSpace = true
		default:
			if pendingSpace {
				out.appendByte(' ')
				pendingSpace = false
			}
			out.appendRune(r)
		}
	}
	if pendingSpace {
		out.appendByte(' ')
	}
	return out.String()
}

// Email preheaders commonly repeat a mixture of spaces and default-ignorable
// Unicode characters hundreds of times to occupy inbox-preview width. Preserve
// a small sample as evidence, but do not let formatting-only padding dominate
// the LLM input. Ordinary whitespace and short obfuscation runs are unchanged.
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

func annotationWhitespaceOnly(value string, stop resourceguard.Stop) bool {
	if value == "" {
		return false
	}
	nextCheck := 0
	for offset, r := range value {
		if offset >= nextCheck {
			if stop != nil {
				stop()
			}
			nextCheck = offset + resourceguard.WorkChunk
		}
		if !preheaderPaddingRune(r) {
			return false
		}
	}
	return true
}

func annotationWhitespaceOnlyBytesWithStop(value []byte, stop resourceguard.Stop) bool {
	if len(value) == 0 {
		return false
	}
	checked := 0
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if !preheaderPaddingRune(r) {
			return false
		}
		value = value[size:]
		checked += size
		if checked >= resourceguard.WorkChunk {
			if stop != nil {
				stop()
			}
			checked = 0
		}
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

	e.textStopCallback()

	raw := strings.TrimSpace(firstAttr(n, "src"))
	alt := sanitizeSenderTextWithResources(firstAttr(n, "alt"), e.memory, e.textStopCallback())
	alt = rewritePlainTextURLs(alt, e.compactURLs, nil, e.memory, e.textClockCheck)
	var destination string
	if len(raw) >= 4 && strings.EqualFold(raw[:4], "cid:") {
		e.memory.Reserve(int64(len(raw)-4) * 4)
		id := normalizeContentID(raw[4:])
		if id == "" {
			return
		}
		if alt == "" {
			alt = "embedded image"
		}
		destination = resourceguard.Concat(e.memory, "cid:", escapeMarkdown(id, true, e.memory, e.stopNow), e.stopNow)
		e.images.Add(id)
	} else {

		if resolved, ok := e.destination(raw); ok && (strings.HasPrefix(resolved, "http://") || strings.HasPrefix(resolved, "https://")) {
			if alt == "" {
				alt = "image"
			}
			destination = escapeMarkdown(e.links.AddDestination(resolved), true, e.memory, e.stopNow)
		}

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
				{
					reason, value := elementConcealmentReason(state)
					annotation = outputAnnotation{kind: "concealed", reason: reason, value: value}
				}
			}
		case "client-dependent":
			annotation = outputAnnotation{kind: "client-dependent"}
		case "unknown":
			annotation = outputAnnotation{kind: "unknown"}
		}
	}
	out.write(annotation, " ![")
	out.write(annotation, escapeMarkdown(alt, false, e.memory, e.textClockCheck))
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

func (e *htmlExtraction) findBase(n *xhtml.Node) {
	if n == nil || e.baseSeen {
		return
	}
	e.stopRequested()

	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "template") {
		return
	}
	if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, "base") {
		raw, present := attrPresent(n, "href")
		if present {
			e.baseSeen = true

			if parsed, err := resourceguard.ParseURL(e.memory, strings.TrimSpace(raw)); err == nil && parsed.IsAbs() && (parsed.Scheme == "http" || parsed.Scheme == "https") {
				e.base = parsed
			}

			return // first base href wins even when unusable
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		e.findBase(child)
	}
	return
}

func (e *htmlExtraction) destination(raw string) (string, bool) {
	stop := e.stopNow
	// Preserve URL cleaning semantics, but own any replacement buffers.
	clean := newGuardedBuilder(e.memory)
	changed := false
	nextCheck := 0
	for offset, r := range raw {
		if offset >= nextCheck {
			stop()
			nextCheck = offset + resourceguard.WorkChunk
		}
		removed := r == '\r' || r == '\n' || r == '\t' || r == 0
		invalid := false
		// RuneError also represents invalid leading bytes; inspect its decoded width.
		if r == utf8.RuneError {
			_, width := utf8.DecodeRuneInString(raw[offset:])
			invalid = width == 1
		}
		if !changed && (removed || invalid) {
			clean.Grow(len(raw))
			clean.WriteString(raw[:offset])
			changed = true
		}
		if changed && !removed {
			clean.appendRune(r)
		}
	}
	if changed {
		raw = clean.String()
	}
	raw = strings.TrimSpace(raw)
	authorityEnd := 0
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		authorityEnd = len(raw)
		if rest := strings.IndexAny(raw[scheme+3:], "/?#"); rest >= 0 {
			authorityEnd = scheme + 3 + rest
		}
	}
	encoded := newGuardedBuilder(e.memory)
	changed = false
	for i := 0; i < len(raw); i++ {
		if i%resourceguard.WorkChunk == 0 {
			stop()
		}
		c := raw[i]
		if c < 0x20 || c == 0x7f {
			if authorityEnd > 0 && i < authorityEnd {
				return "", false
			}
			if !changed {
				encoded.Grow(len(raw))
				encoded.WriteString(raw[:i])
				changed = true
			}
			const hex = "0123456789ABCDEF"
			encoded.appendByte('%')
			encoded.appendByte(hex[c>>4])
			encoded.appendByte(hex[c&15])
		} else if changed {
			encoded.appendByte(c)
		}
	}
	if changed {
		raw = encoded.String()
	}
	if raw == "" {
		return "", false
	}
	parsed, err := resourceguard.ParseURL(e.memory, raw)
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
		reserveResolvedURL(e.memory, raw, nil)
		return parsed.String(), true
	}
	if e.base != nil {
		reserveResolvedURL(e.memory, raw, e.base)
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

func normalizeHTMLTextWithResources(value string, memory *resourceguard.Memory, stop func()) string {
	b := newGuardedBuilder(memory)

	b.Grow(len(value))

	space, newlines := false, 0
	nextCheck := 0
	for offset := 0; offset < len(value); {
		if offset >= nextCheck {
			if stop != nil {
				stop()
			}

			nextCheck = offset + resourceguard.WorkChunk
		}
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

	return strings.Trim(b.String(), " \t\r\n\f")
}

func (collector *linkCollector) AddDestination(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return ""
	}

	if rendered, exists := collector.rendered.Get(candidate); exists {
		return rendered
	}

	if collector.Full() {
		return candidate
	}
	raw := candidate
	candidate = promptURLWithBudget(raw, collector.compactURLs, collector.memory, collector.shouldStop)

	if _, exists := collector.seen.Get(candidate); exists {
		return candidate
	}

	characters := utf8.RuneCountInString(candidate)
	if len(collector.links) >= maxExtractedLinks || collector.chars+characters > maxExtractedLinkChars {
		collector.full = true
		return candidate
	}

	collector.rendered.Set(collector.memory, raw, candidate)
	collector.seen.Set(collector.memory, candidate, struct{}{})

	grown := growGuardedSlice(collector.links, len(collector.links)+1, collector.memory)

	collector.links = append(grown, candidate)
	collector.chars += characters
	return candidate
}

func analyzeControlledHTML(source string, limits htmlextract.Limits, budget *extractionBudget) (htmlextract.Document, error) {
	var usage htmlextract.ResourceUsage
	defer func() { budget.consumeHTML(usage) }()
	return htmlextract.AnalyzeControlledString(source, limits, budget.stageStop, &usage)
}
