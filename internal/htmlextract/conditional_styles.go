package htmlextract

import (
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

// parseMSOConditionalStyles extracts style elements from a downlevel-hidden
// Microsoft Office conditional comment. These rules apply only in some mail
// clients, so their origin is always uncertain.
func (s *sheet) parseMSOConditionalStyles(data string) {
	if !s.checkCPU() {
		return
	}
	fragment, ok := msoConditionalFragment(data)
	if !ok || s.cascadeIncomplete || s.stopped {
		return
	}
	// Most MSO comments contain alternate table markup rather than CSS. Avoid
	// constructing a tokenizer for those very common fragments.
	if !containsASCIIFold(fragment, "<style") {
		return
	}
	// Tokenizing the conditional markup is work in addition to parsing any CSS
	// it contains. Sample before starting; the tokenizer samples during its scan.
	if !s.checkCPU() {
		return
	}
	z := html.NewTokenizerWithStop(strings.NewReader(fragment), s.shouldStop)
	var style strings.Builder
	var styleNode html.Node
	inStyle := false
	flush := func() bool {
		if !inStyle {
			return true
		}
		inStyle = false
		if !cssTypeAttributeApplies(&styleNode) {
			style.Reset()
			return true
		}
		s.parseStylesheet(style.String(), attr(&styleNode, "media"), uncertainStylesheetOrigin)
		style.Reset()
		return !s.cascadeIncomplete && !s.stopped
	}
	for {
		tokenType := z.Next()
		switch tokenType {
		case html.ErrorToken:
			if errors.Is(z.Err(), html.ErrResourceStopped) {
				s.stopped = true
				return
			}
			if z.Err() != nil && z.Err() != io.EOF {
				s.abandonCascade()
				return
			}
			flush()
			return
		case html.StartTagToken:
			name, hasAttributes := z.TagName()
			if inStyle || !bytes.Equal(name, []byte("style")) {
				continue
			}
			styleNode = html.Node{Type: html.ElementNode, Data: "style"}
			for hasAttributes {
				key, value, more := z.TagAttr()
				retainConditionalStyleAttribute(&styleNode, key, value)
				hasAttributes = more
			}
			inStyle = true
		case html.TextToken:
			if !inStyle {
				continue
			}
			raw := z.Raw()
			remaining := s.limits.CSSBytes - s.cssBytes
			if remaining < 0 || len(raw) > remaining-style.Len() {
				s.abandonCascade()
				return
			}
			style.Write(raw)
		case html.EndTagToken:
			name, _ := z.TagName()
			if inStyle && bytes.Equal(name, []byte("style")) && !flush() {
				return
			}
		}
	}
}

// retainConditionalStyleAttribute bounds retained state while tokenizing the
// HTML fragment inside an MSO conditional comment. Only these attributes can
// affect stylesheet processing; retaining arbitrary attributes would let one
// comment allocate a large synthetic html.Node outside the document's normal
// attribute accounting. Keep the first occurrence, matching x/net/html's tree
// builder treatment of duplicate HTML attributes.
func retainConditionalStyleAttribute(style *html.Node, key, value []byte) {
	name := string(key)
	if (name != "type" && name != "media") || hasAttr(style, name) {
		return
	}
	style.Attr = append(style.Attr, html.Attribute{Key: name, Val: string(value)})
}

func msoConditionalFragment(data string) (string, bool) {
	trimmed := strings.TrimSpace(data)
	if len(trimmed) < len("[if ]>") || !hasASCIIFoldPrefix(trimmed, "[if ") {
		return "", false
	}
	start := strings.Index(trimmed, "]>")
	if start < 0 || !containsASCIIFold(trimmed[len("[if "):start], "mso") {
		return "", false
	}
	end := lastASCIIFoldIndex(trimmed, "<![endif]")
	if end <= start+2 {
		return "", false
	}
	return trimmed[start+2 : end], true
}

type msoRevealedMarker int8

const (
	msoRevealedNone msoRevealedMarker = iota
	msoRevealedStart
	msoRevealedUniversalStart
	msoRevealedEnd
)

const (
	maxMSOConditionBytes = 1024
	maxMSOConditionDepth = 128
	minMSOVersion        = 9
	maxMSOVersion        = 16
)

const msoConditionUniverse uint32 = 1<<(2*(maxMSOVersion-minMSOVersion+1)) - 1

// msoDownlevelRevealedMarker recognizes the paired comments used to expose
// markup to ordinary HTML clients conditionally in Word-based Outlook:
//
// <!--[if !mso]><!--> ... <!--<![endif]-->
//
// x/net/html preserves these as separate comment nodes. Conditions that are
// not true throughout the supported Outlook environment range make the region
// client-dependent. Malformed or over-limit conditions are uncertain too.
func msoDownlevelRevealedMarker(data string) msoRevealedMarker {
	trimmed := strings.TrimSpace(data)
	if equalASCIIFold(trimmed, "<![endif]") {
		return msoRevealedEnd
	}
	if !hasASCIIFoldPrefix(trimmed, "[if ") {
		return msoRevealedNone
	}
	end := strings.Index(trimmed, "]>")
	if end < 0 {
		return msoRevealedNone
	}
	if !strings.HasPrefix(strings.TrimSpace(trimmed[end+2:]), "<!") {
		return msoRevealedNone
	}
	condition := trimmed[len("[if "):end]
	if msoConditionAlwaysTrue(condition) {
		// This downlevel-revealed wrapper does not create a client-dependent
		// region when every supported Word/IE environment includes its body.
		return msoRevealedUniversalStart
	}
	// False, version-dependent, unsupported, and malformed predicates all mean
	// that the ordinary-client body cannot be called confidently visible.
	return msoRevealedStart
}

type msoConditionParser struct {
	input  string
	pos    int
	failed bool
}

func msoConditionAlwaysTrue(condition string) bool {
	if len(condition) == 0 || len(condition) > maxMSOConditionBytes {
		return false
	}
	p := msoConditionParser{input: condition}
	mask := p.parseOr(0)
	p.skipSpace()
	return !p.failed && p.pos == len(p.input) && mask == msoConditionUniverse
}

func (p *msoConditionParser) parseOr(depth int) uint32 {
	mask := p.parseAnd(depth)
	for !p.failed && p.take('|') {
		mask |= p.parseAnd(depth)
	}
	return mask
}

func (p *msoConditionParser) parseAnd(depth int) uint32 {
	mask := p.parseUnary(depth)
	for !p.failed && p.take('&') {
		mask &= p.parseUnary(depth)
	}
	return mask
}

func (p *msoConditionParser) parseUnary(depth int) uint32 {
	if depth >= maxMSOConditionDepth {
		p.failed = true
		return 0
	}
	if p.take('!') {
		return msoConditionUniverse ^ p.parseUnary(depth+1)
	}
	if p.take('(') {
		mask := p.parseOr(depth + 1)
		if !p.take(')') {
			p.failed = true
		}
		return mask
	}
	return p.parseAtom()
}

func (p *msoConditionParser) parseAtom() uint32 {
	word := p.word()
	if word == "" {
		p.failed = true
		return 0
	}
	switch {
	case equalASCIIFold(word, "true"):
		return msoConditionUniverse
	case equalASCIIFold(word, "false"):
		return 0
	case equalASCIIFold(word, "IE"):
		return msoIEMask()
	case equalASCIIFold(word, "mso"):
		if version, ok := p.optionalNumber(); ok {
			return msoVersionMask("eq", version)
		}
		return msoConditionUniverse
	case equalASCIIFold(word, "lt"), equalASCIIFold(word, "lte"), equalASCIIFold(word, "gt"), equalASCIIFold(word, "gte"):
		feature := p.word()
		if !equalASCIIFold(feature, "mso") {
			p.failed = true
			return 0
		}
		version, ok := p.number()
		if !ok {
			p.failed = true
			return 0
		}
		return msoVersionMask(asciiLower(word), version)
	default:
		p.failed = true
		return 0
	}
}

func (p *msoConditionParser) take(want byte) bool {
	p.skipSpace()
	if p.pos >= len(p.input) || p.input[p.pos] != want {
		return false
	}
	p.pos++
	return true
}

func (p *msoConditionParser) word() string {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c < 'A' || c > 'Z' {
			if c < 'a' || c > 'z' {
				break
			}
		}
		p.pos++
	}
	if p.pos == start {
		return ""
	}
	return p.input[start:p.pos]
}

func (p *msoConditionParser) optionalNumber() (int, bool) {
	p.skipSpace()
	if p.pos >= len(p.input) || p.input[p.pos] < '0' || p.input[p.pos] > '9' {
		return 0, false
	}
	return p.number()
}

func (p *msoConditionParser) number() (int, bool) {
	p.skipSpace()
	start := p.pos
	value := 0
	for p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
		digit := int(p.input[p.pos] - '0')
		if value > (1<<31-1-digit)/10 {
			p.failed = true
			return 0, false
		}
		value = value*10 + digit
		p.pos++
	}
	if p.pos == start {
		return 0, false
	}
	return value, true
}

func (p *msoConditionParser) skipSpace() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\t', '\r', '\n', '\f':
			p.pos++
		default:
			return
		}
	}
}

func msoIEMask() uint32 {
	var mask uint32
	for version := minMSOVersion; version <= maxMSOVersion; version++ {
		mask |= 1 << msoEnvironmentBit(version, true)
	}
	return mask
}

func msoVersionMask(operator string, wanted int) uint32 {
	var mask uint32
	for version := minMSOVersion; version <= maxMSOVersion; version++ {
		matches := false
		switch operator {
		case "eq":
			matches = version == wanted
		case "lt":
			matches = version < wanted
		case "lte":
			matches = version <= wanted
		case "gt":
			matches = version > wanted
		case "gte":
			matches = version >= wanted
		}
		if matches {
			mask |= 1 << msoEnvironmentBit(version, false)
			mask |= 1 << msoEnvironmentBit(version, true)
		}
	}
	return mask
}

func msoEnvironmentBit(version int, ie bool) uint {
	bit := 2 * (version - minMSOVersion)
	if ie {
		bit++
	}
	return uint(bit)
}

func hasASCIIFoldPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && equalASCIIFold(value[:len(prefix)], prefix)
}

func containsASCIIFold(value, target string) bool {
	for start := 0; start+len(target) <= len(value); start++ {
		if equalASCIIFold(value[start:start+len(target)], target) {
			return true
		}
	}
	return false
}

func lastASCIIFoldIndex(value, target string) int {
	for start := len(value) - len(target); start >= 0; start-- {
		if equalASCIIFold(value[start:start+len(target)], target) {
			return start
		}
	}
	return -1
}

// Every opener participates in pairing, even if its predicate is universally
// true. Only uncertain entries contribute to the presentation uncertainty.
type msoRevealedState struct {
	stack     []bool
	uncertain int
}

func (s *msoRevealedState) update(marker msoRevealedMarker, budget *cpuGuard) bool {
	switch marker {
	case msoRevealedStart, msoRevealedUniversalStart:
		var ok bool
		s.stack, ok = growSlice(s.stack, 1, budget.allocationMemory())
		if !ok {
			return false
		}
		uncertain := marker == msoRevealedStart
		s.stack = append(s.stack, uncertain)
		if uncertain {
			s.uncertain++
		}
	case msoRevealedEnd:
		if len(s.stack) > 0 {
			last := len(s.stack) - 1
			if s.stack[last] {
				s.uncertain--
			}
			s.stack = s.stack[:last]
		}
	}
	return true
}
