// Package cascadia is an implementation of CSS selectors.
package cascadia

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// a parser for CSS selectors
type parser struct {
	s          string // the source text
	i          int    // the current position
	components int
	depth      int
	memory     *resourceguard.Memory

	// if `false`, parsing a pseudo-element
	// returns an error.
	acceptPseudoElements bool
}

const (
	maxSelectorBytes      = 16 << 10
	maxSelectorComponents = 1_024
	maxSelectorDepth      = 64
)

func validateSelectorInput(selector string) error {
	if len(selector) > maxSelectorBytes {
		return ErrInvalidSelector
	}
	return nil
}

func (p *parser) takeComponent() error {
	p.components++
	if p.components > maxSelectorComponents {
		return ErrInvalidSelector
	}
	return nil
}

// parseEscape parses a backslash escape.
func (p *parser) parseEscape() (result string, err error) {
	if len(p.s) < p.i+2 || p.s[p.i] != '\\' {
		return "", ErrInvalidSelector
	}

	start := p.i + 1
	c := p.s[start]
	switch {
	case c == '\r' || c == '\n' || c == '\f':
		return "", ErrInvalidSelector
	case hexDigit(c):
		// unicode escape (hex)
		var i int
		for i = start; i < start+6 && i < len(p.s) && hexDigit(p.s[i]); i++ {
			// empty
		}
		v, _ := strconv.ParseUint(p.s[start:i], 16, 64)
		if len(p.s) > i {
			switch p.s[i] {
			case '\r':
				i++
				if len(p.s) > i && p.s[i] == '\n' {
					i++
				}
			case ' ', '\t', '\n', '\f':
				i++
			}
		}
		p.i = i
		var encoded [4]byte
		n := utf8.EncodeRune(encoded[:], rune(v))
		text, ok := resourceguard.CopyString(p.memory, encoded[:n], nil)
		requireSelectorStorage(ok)
		return text, nil
	}

	// Return the literal character after the backslash.
	result = p.s[start : start+1]
	p.i += 2
	return result, nil
}

// toLowerASCII is retained for unguarded package callers and tests.
func toLowerASCII(s string) string { out, _ := resourceguard.LowerASCII(nil, s, nil); return out }

func hexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// nameStart returns whether c can be the first character of an identifier
// (not counting an initial hyphen, or an escape sequence).
func nameStart(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c > 127
}

// nameChar returns whether c can be a character within an identifier
// (not counting an escape sequence).
func nameChar(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_' || c > 127 ||
		c == '-' || '0' <= c && c <= '9'
}

// parseIdentifier parses an identifier.
func (p *parser) parseIdentifier() (result string, err error) {
	const prefix = '-'
	var numPrefix int

	for len(p.s) > p.i && p.s[p.i] == prefix {
		p.i++
		numPrefix++
	}

	if len(p.s) <= p.i {
		return "", ErrInvalidSelector
	}

	if c := p.s[p.i]; !(nameStart(c) || c == '\\') {
		return "", ErrInvalidSelector
	}

	result, err = p.parseName()
	if numPrefix > 0 && err == nil {
		var b strings.Builder
		requireSelectorStorage(resourceguard.GrowText(p.memory, &b, numPrefix+len(result), nil))
		for range numPrefix {
			b.WriteByte(prefix)
		}
		p.writeString(&b, result)
		result = b.String()
	}
	return
}

// parseName parses a name (which is like an identifier, but doesn't have
// extra restrictions on the first character).
func (p *parser) parseName() (string, error) {
	i := p.i
	start := i
	segmentStart := i
	var result strings.Builder
	hasEscape := false
loop:
	for i < len(p.s) {
		c := p.s[i]
		switch {
		case nameChar(c):
			for i < len(p.s) && nameChar(p.s[i]) {
				i++
			}
		case c == '\\':
			hasEscape = true
			p.writeString(&result, p.s[segmentStart:i])
			p.i = i
			val, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			i = p.i
			p.writeString(&result, val)
			segmentStart = i
		default:
			break loop
		}
	}

	if i == start {
		return "", ErrInvalidSelector
	}

	p.i = i
	if !hasEscape {
		return p.s[start:i], nil
	}
	p.writeString(&result, p.s[segmentStart:i])
	return result.String(), nil
}

// parseString parses a single- or double-quoted string.
func (p *parser) parseString() (string, error) {
	i := p.i
	if len(p.s) < i+2 {
		return "", ErrInvalidSelector
	}

	quote := p.s[i]
	i++
	start := i
	segmentStart := i
	var result strings.Builder
	hasEscape := false

loop:
	for i < len(p.s) {
		switch p.s[i] {
		case '\\':
			hasEscape = true
			p.writeString(&result, p.s[segmentStart:i])
			if len(p.s) > i+1 {
				switch c := p.s[i+1]; c {
				case '\r':
					if len(p.s) > i+2 && p.s[i+2] == '\n' {
						i += 3
						segmentStart = i
						continue loop
					}
					fallthrough
				case '\n', '\f':
					i += 2
					segmentStart = i
					continue loop
				}
			}
			p.i = i
			val, err := p.parseEscape()
			if err != nil {
				return "", err
			}
			i = p.i
			p.writeString(&result, val)
			segmentStart = i
		case quote:
			break loop
		case '\r', '\n', '\f':
			return "", ErrInvalidSelector
		default:
			i++
		}
	}

	if i >= len(p.s) {
		return "", ErrInvalidSelector
	}

	// Consume the final quote.
	i++

	p.i = i
	if !hasEscape {
		return p.s[start : i-1], nil
	}
	p.writeString(&result, p.s[segmentStart:i-1])
	return result.String(), nil
}

// skipWhitespace consumes whitespace characters and comments.
// It returns true if there was actually anything to skip.
func (p *parser) skipWhitespace() bool {
	i := p.i
	for i < len(p.s) {
		switch p.s[i] {
		case ' ', '\t', '\r', '\n', '\f':
			i++
			continue
		case '/':
			if strings.HasPrefix(p.s[i:], "/*") {
				end := strings.Index(p.s[i+len("/*"):], "*/")
				if end != -1 {
					i += end + len("/**/")
					continue
				}
			}
		}
		break
	}

	if i > p.i {
		p.i = i
		return true
	}

	return false
}

// consumeParenthesis consumes an opening parenthesis and any following
// whitespace. It returns true if there was actually a parenthesis to skip.
func (p *parser) consumeParenthesis() bool {
	if p.i < len(p.s) && p.s[p.i] == '(' {
		p.i++
		p.skipWhitespace()
		return true
	}
	return false
}

// consumeClosingParenthesis consumes a closing parenthesis and any preceding
// whitespace. It returns true if there was actually a parenthesis to skip.
func (p *parser) consumeClosingParenthesis() bool {
	i := p.i
	p.skipWhitespace()
	if p.i < len(p.s) && p.s[p.i] == ')' {
		p.i++
		return true
	}
	p.i = i
	return false
}

// parseTypeSelector parses a type selector (one that matches by tag name).
func (p *parser) parseTypeSelector() (result tagSelector, err error) {
	tag, err := p.parseIdentifier()
	if err != nil {
		return
	}
	return tagSelector{tag: p.lowerASCII(tag), original: tag}, nil
}

// parseIDSelector parses a selector that matches by id attribute.
func (p *parser) parseIDSelector() (idSelector, error) {
	if p.i >= len(p.s) {
		return idSelector{}, ErrInvalidSelector
	}
	if p.s[p.i] != '#' {
		return idSelector{}, ErrInvalidSelector
	}

	p.i++
	id, err := p.parseName()
	if err != nil {
		return idSelector{}, err
	}

	return idSelector{id: id}, nil
}

// parseClassSelector parses a selector that matches by class attribute.
func (p *parser) parseClassSelector() (classSelector, error) {
	if p.i >= len(p.s) {
		return classSelector{}, ErrInvalidSelector
	}
	if p.s[p.i] != '.' {
		return classSelector{}, ErrInvalidSelector
	}

	p.i++
	class, err := p.parseIdentifier()
	if err != nil {
		return classSelector{}, err
	}

	return classSelector{class: class}, nil
}

// parseAttributeSelector parses a selector that matches by attribute value.
func (p *parser) parseAttributeSelector() (attrSelector, error) {
	if p.i >= len(p.s) {
		return attrSelector{}, ErrInvalidSelector
	}
	if p.s[p.i] != '[' {
		return attrSelector{}, ErrInvalidSelector
	}

	p.i++
	p.skipWhitespace()
	key, err := p.parseIdentifier()
	if err != nil {
		return attrSelector{}, err
	}
	key = p.lowerASCII(key)

	p.skipWhitespace()
	if p.i >= len(p.s) {
		return attrSelector{}, ErrInvalidSelector
	}

	if p.s[p.i] == ']' {
		p.i++
		return attrSelector{key: key, operation: ""}, nil
	}

	if p.i+2 >= len(p.s) {
		if p.s[p.i] == '=' {
			return attrSelector{}, ErrInvalidAttributeValue
		}
		return attrSelector{}, ErrInvalidSelector
	}

	op := p.s[p.i : p.i+2]
	if op[0] == '=' {
		op = "="
	} else if op[1] != '=' {
		return attrSelector{}, ErrInvalidSelector
	}
	if op == "#=" {
		return attrSelector{}, ErrInvalidSelector
	}
	p.i += len(op)

	p.skipWhitespace()
	if p.i >= len(p.s) {
		return attrSelector{}, ErrInvalidSelector
	}
	var val string
	switch p.s[p.i] {
	case '\'', '"':
		val, err = p.parseString()
	default:
		val, err = p.parseIdentifier()
	}
	if err != nil {
		return attrSelector{}, ErrInvalidAttributeValue
	}

	p.skipWhitespace()
	if p.i >= len(p.s) {
		return attrSelector{}, ErrInvalidSelector
	}

	// check if the attribute contains an ignore case flag
	ignoreCase := false
	if p.s[p.i] == 'i' || p.s[p.i] == 'I' {
		ignoreCase = true
		p.i++
	}

	p.skipWhitespace()
	if p.i >= len(p.s) {
		return attrSelector{}, ErrInvalidSelector
	}

	if p.s[p.i] != ']' {
		return attrSelector{}, ErrInvalidSelector
	}
	p.i++

	switch op {
	case "=", "!=", "~=", "|=", "^=", "$=", "*=":
		selector := attrSelector{key: key, val: val, operation: op, insensitive: ignoreCase}
		if op == "*=" && len(val) > 0 {
			selector.failure = substringFailureWithMemory(val, ignoreCase, p.memory)
		}
		return selector, nil
	default:
		return attrSelector{}, ErrInvalidSelector
	}
}

// parsePseudoclassSelector parses a pseudoclass selector like :not(p) or a pseudo-element
// For backwards compatibility, both ':' and '::' prefix are allowed for pseudo-elements.
// https://drafts.csswg.org/selectors-3/#pseudo-elements
// Returning a nil `Sel` (and a nil `error`) means we found a pseudo-element.
func (p *parser) parsePseudoclassSelector() (out Sel, pseudoElement string, err error) {
	if p.i >= len(p.s) {
		return nil, "", ErrInvalidSelector
	}
	if p.s[p.i] != ':' {
		return nil, "", ErrInvalidSelector
	}

	p.i++
	var mustBePseudoElement bool
	if p.i >= len(p.s) {
		return nil, "", ErrInvalidSelector
	}
	if p.s[p.i] == ':' { // we found a pseudo-element
		mustBePseudoElement = true
		p.i++
	}

	name, err := p.parseIdentifier()
	if err != nil {
		return
	}
	name = p.lowerASCII(name)
	if mustBePseudoElement && (name != "after" && name != "backdrop" && name != "before" &&
		name != "cue" && name != "first-letter" && name != "first-line" && name != "grammar-error" &&
		name != "marker" && name != "placeholder" && name != "selection" && name != "spelling-error") {
		return out, "", ErrInvalidSelector
	}

	switch name {
	case "not", "has", "haschild":
		if !p.consumeParenthesis() {
			return out, "", ErrInvalidSelector
		}
		sel, parseErr := p.parseSelectorGroup()
		if parseErr != nil {
			return out, "", parseErr
		}
		if !p.consumeClosingParenthesis() {
			return out, "", ErrInvalidSelector
		}

		out = selectorObject(p.memory, relativePseudoClassSelector{name: name, match: sel})

	case "contains", "containsown":
		return out, "", ErrInvalidSelector

	case "matches", "matchesown":
		return out, "", ErrInvalidSelector

	case "nth-child", "nth-last-child", "nth-of-type", "nth-last-of-type":
		if !p.consumeParenthesis() {
			return out, "", ErrInvalidSelector
		}
		a, b, err := p.parseNth()
		if err != nil {
			return out, "", err
		}
		if !p.consumeClosingParenthesis() {
			return out, "", ErrInvalidSelector
		}
		last := name == "nth-last-child" || name == "nth-last-of-type"
		ofType := name == "nth-of-type" || name == "nth-last-of-type"
		out = selectorObject(p.memory, nthPseudoClassSelector{a: a, b: b, last: last, ofType: ofType})

	case "first-child":
		out = selectorObject(p.memory, nthPseudoClassSelector{a: 0, b: 1, ofType: false, last: false})
	case "last-child":
		out = selectorObject(p.memory, nthPseudoClassSelector{a: 0, b: 1, ofType: false, last: true})
	case "first-of-type":
		out = selectorObject(p.memory, nthPseudoClassSelector{a: 0, b: 1, ofType: true, last: false})
	case "last-of-type":
		out = selectorObject(p.memory, nthPseudoClassSelector{a: 0, b: 1, ofType: true, last: true})
	case "only-child":
		out = selectorObject(p.memory, onlyChildPseudoClassSelector{ofType: false})
	case "only-of-type":
		out = selectorObject(p.memory, onlyChildPseudoClassSelector{ofType: true})
	case "input":
		out = selectorObject(p.memory, inputPseudoClassSelector{})
	case "empty":
		out = selectorObject(p.memory, emptyElementPseudoClassSelector{})
	case "root":
		out = selectorObject(p.memory, rootPseudoClassSelector{})
	case "link":
		out = selectorObject(p.memory, linkPseudoClassSelector{})
	case "lang":
		if !p.consumeParenthesis() {
			return out, "", ErrInvalidSelector
		}
		if p.i == len(p.s) {
			return out, "", ErrInvalidSelector
		}
		val, err := p.parseIdentifier()
		if err != nil {
			return out, "", err
		}
		val = p.lowerUnicode(val)
		p.skipWhitespace()
		if p.i >= len(p.s) {
			return out, "", ErrInvalidSelector
		}
		if !p.consumeClosingParenthesis() {
			return out, "", ErrInvalidSelector
		}
		out = selectorObject(p.memory, langPseudoClassSelector{lang: val})
	case "enabled":
		out = selectorObject(p.memory, enabledPseudoClassSelector{})
	case "disabled":
		out = selectorObject(p.memory, disabledPseudoClassSelector{})
	case "checked":
		out = selectorObject(p.memory, checkedPseudoClassSelector{})
	case "visited", "hover", "active", "focus", "target":
		// Not applicable in a static context: never match.
		out = selectorObject(p.memory, neverMatchSelector{value: p.concat(":", name)})
	case "after", "backdrop", "before", "cue", "first-letter", "first-line", "grammar-error", "marker", "placeholder", "selection", "spelling-error":
		return nil, name, nil
	default:
		return out, "", ErrInvalidSelector
	}
	return
}

// parseInteger parses a non-negative decimal integer without error allocations.
func (p *parser) parseInteger() (int, error) {
	i := p.i
	start := i
	const maxInt = int(^uint(0) >> 1)
	val := 0
	for i < len(p.s) && '0' <= p.s[i] && p.s[i] <= '9' {
		digit := int(p.s[i] - '0')
		if val > (maxInt-digit)/10 {
			return 0, ErrInvalidSelector
		}
		val = val*10 + digit
		i++
	}
	if i == start {
		return 0, ErrInvalidSelector
	}
	p.i = i

	return val, nil
}

// parseNth parses the argument for :nth-child (normally of the form an+b).
func (p *parser) parseNth() (a, b int, err error) {
	// initial state
	if p.i >= len(p.s) {
		goto eof
	}
	switch p.s[p.i] {
	case '-':
		p.i++
		goto negativeA
	case '+':
		p.i++
		goto positiveA
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		goto positiveA
	case 'n', 'N':
		a = 1
		p.i++
		goto readN
	case 'o', 'O', 'e', 'E':
		id, nameErr := p.parseName()
		if nameErr != nil {
			return 0, 0, nameErr
		}
		id = p.lowerASCII(id)
		if id == "odd" {
			return 2, 1, nil
		}
		if id == "even" {
			return 2, 0, nil
		}
		return 0, 0, ErrInvalidSelector
	default:
		goto invalid
	}

positiveA:
	if p.i >= len(p.s) {
		goto eof
	}
	switch p.s[p.i] {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		a, err = p.parseInteger()
		if err != nil {
			return 0, 0, err
		}
		goto readA
	case 'n', 'N':
		a = 1
		p.i++
		goto readN
	default:
		goto invalid
	}

negativeA:
	if p.i >= len(p.s) {
		goto eof
	}
	switch p.s[p.i] {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		a, err = p.parseInteger()
		if err != nil {
			return 0, 0, err
		}
		a = -a
		goto readA
	case 'n', 'N':
		a = -1
		p.i++
		goto readN
	default:
		goto invalid
	}

readA:
	if p.i >= len(p.s) {
		goto eof
	}
	switch p.s[p.i] {
	case 'n', 'N':
		p.i++
		goto readN
	default:
		// The number we read as a is actually b.
		return 0, a, nil
	}

readN:
	p.skipWhitespace()
	if p.i >= len(p.s) {
		goto eof
	}
	switch p.s[p.i] {
	case '+':
		p.i++
		p.skipWhitespace()
		b, err = p.parseInteger()
		if err != nil {
			return 0, 0, err
		}
		return a, b, nil
	case '-':
		p.i++
		p.skipWhitespace()
		b, err = p.parseInteger()
		if err != nil {
			return 0, 0, err
		}
		return a, -b, nil
	default:
		return a, 0, nil
	}

eof:
	return 0, 0, ErrInvalidSelector

invalid:
	return 0, 0, ErrInvalidSelector
}

// parseSimpleSelectorSequence parses a selector sequence that applies to
// a single element.
func (p *parser) parseSimpleSelectorSequence() (Sel, error) {
	var selectors []Sel

	if p.i >= len(p.s) {
		return nil, ErrInvalidSelector
	}
	switch p.s[p.i] {
	case '*':
		if err := p.takeComponent(); err != nil {
			return nil, err
		}
		// It's the universal selector. Just skip over it, since it doesn't affect the meaning.
		p.i++
		if p.i+2 < len(p.s) && p.s[p.i:p.i+2] == "|*" { // other version of universal selector
			p.i += 2
		}
	case '#', '.', '[', ':':
		// There's no type selector. Wait to process the other till the main loop.
	default:
		if err := p.takeComponent(); err != nil {
			return nil, err
		}
		r, err := p.parseTypeSelector()
		if err != nil {
			return nil, err
		}
		selectors = selectorAppend(p.memory, selectors, selectorObject(p.memory, r))
	}

	var pseudoElement string
loop:
	for p.i < len(p.s) {
		var (
			ns               Sel
			newPseudoElement string
			err              error
		)
		switch p.s[p.i] {
		case '#':
			if err = p.takeComponent(); err != nil {
				return nil, err
			}
			value, parseErr := p.parseIDSelector()
			err = parseErr
			if err == nil {
				ns = selectorObject(p.memory, value)
			}
		case '.':
			if err = p.takeComponent(); err != nil {
				return nil, err
			}
			value, parseErr := p.parseClassSelector()
			err = parseErr
			if err == nil {
				ns = selectorObject(p.memory, value)
			}
		case '[':
			if err = p.takeComponent(); err != nil {
				return nil, err
			}
			value, parseErr := p.parseAttributeSelector()
			err = parseErr
			if err == nil {
				ns = selectorObject(p.memory, value)
			}
		case ':':
			if err = p.takeComponent(); err != nil {
				return nil, err
			}
			ns, newPseudoElement, err = p.parsePseudoclassSelector()
		default:
			break loop
		}
		if err != nil {
			return nil, err
		}
		// From https://drafts.csswg.org/selectors-3/#pseudo-elements :
		// "Only one pseudo-element may appear per selector, and if present
		// it must appear after the sequence of simple selectors that
		// represents the subjects of the selector.""
		if ns == nil { // we found a pseudo-element
			if pseudoElement != "" {
				return nil, ErrInvalidSelector
			}
			if !p.acceptPseudoElements {
				return nil, ErrInvalidSelector
			}
			pseudoElement = newPseudoElement
		} else {
			if pseudoElement != "" {
				return nil, ErrInvalidSelector
			}
			selectors = selectorAppend(p.memory, selectors, ns)
		}

	}
	if len(selectors) == 1 && pseudoElement == "" { // no need wrap the selectors in compoundSelector
		return selectors[0], nil
	}
	return selectorObject(p.memory, compoundSelector{selectors: selectors, pseudoElement: pseudoElement}), nil
}

// parseSelector parses a selector that may include combinators.
func (p *parser) parseSelector() (Sel, error) {
	p.skipWhitespace()
	result, err := p.parseSimpleSelectorSequence()
	if err != nil {
		return nil, err
	}

	for {
		var (
			combinator byte
			c          Sel
		)
		if p.skipWhitespace() {
			combinator = ' '
		}
		if p.i >= len(p.s) {
			return result, nil
		}

		switch p.s[p.i] {
		case '+', '>', '~':
			combinator = p.s[p.i]
			p.i++
			p.skipWhitespace()
		case ',', ')':
			// These characters can't begin a selector, but they can legally occur after one.
			return result, nil
		}

		if combinator == 0 {
			return result, nil
		}

		c, err = p.parseSimpleSelectorSequence()
		if err != nil {
			return nil, err
		}
		result = selectorObject(p.memory, combinedSelector{first: result, combinator: combinator, second: c})
	}
}

// parseSelectorGroup parses a group of selectors, separated by commas.
func (p *parser) parseSelectorGroup() (SelectorGroup, error) {
	p.depth++
	if p.depth > maxSelectorDepth {
		p.depth--
		return nil, ErrInvalidSelector
	}
	defer func() { p.depth-- }()
	current, err := p.parseSelector()
	if err != nil {
		return nil, err
	}
	result := SelectorGroup(selectorAppend(p.memory, []Sel(nil), current))

	for p.i < len(p.s) {
		if p.s[p.i] != ',' {
			break
		}
		p.i++
		c, err := p.parseSelector()
		if err != nil {
			return nil, err
		}
		result = selectorAppend(p.memory, result, c)
	}
	return result, nil
}

func (p *parser) writeString(b *strings.Builder, text string) {
	requireSelectorStorage(resourceguard.WriteString(p.memory, b, text, nil))
}
func (p *parser) concat(left, right string) string {
	s, ok := resourceguard.Concat(p.memory, left, right, nil)
	requireSelectorStorage(ok)
	return s
}
func (p *parser) lowerASCII(s string) string {
	out, ok := resourceguard.LowerASCII(p.memory, s, nil)
	requireSelectorStorage(ok)
	return out
}

// lowerUnicode preserves strings.ToLower semantics, including replacement of
// malformed UTF-8, while admitting one exactly sized output buffer.
func (p *parser) lowerUnicode(s string) string {
	size, changed := 0, false
	for _, r := range s {
		lower := unicode.ToLower(r)
		size += utf8.RuneLen(lower)
		changed = changed || lower != r
	}
	// A malformed byte becomes a three-byte RuneError. Valid RuneError runes
	// retain their original size and do not require a copy.
	if !changed && size == len(s) {
		return s
	}
	var b strings.Builder
	requireSelectorStorage(resourceguard.GrowText(p.memory, &b, size, nil))
	for _, r := range s {
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
