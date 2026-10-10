// Package repair implements conservative lexical boundary recovery. It never
// decodes entities or MIME encodings and does not balance the HTML tree.
package repair

import (
	"bytes"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"strings"
)

type Change struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Reason string `json:"reason"`
}

// Apply returns the original slice if no repair is demonstrated. Log ranges
// refer to original bytes; a zero-width range denotes insertion.
func Apply(src []byte) ([]byte, []Change, error) {
	budget := 16*len(src) + 1
	s := string(src)
	lowerBytes := append([]byte(nil), src...)
	for i, c := range lowerBytes {
		if c >= 'A' && c <= 'Z' {
			lowerBytes[i] = c + 32
		}
	}
	lower := string(lowerBytes)
	var changes []Change
	var out bytes.Buffer
	copied := 0
	for i := 0; i < len(s); {
		if s[i] != '<' || !lexicalMarkupStart(s, i) {
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "<!--") {
			end, ok := commentEnd(s, i+4)
			if !ok {
				break
			}
			i = end
			continue
		}
		end, ok := lexicalTagEnd(s, i+1, &budget)
		if budget <= 0 {
			return nil, nil, fmt.Errorf("limit: repair scan work")
		}
		if !ok {
			if budget <= 0 {
				return nil, nil, fmt.Errorf("limit: repair scan work")
			}
			break
		}
		raw := s[i+1 : end]
		name, closing := tagName(raw)
		// The scanner recovered at a > still inside a quote. Add just that
		// quote; do not remove bytes, decode attributes or invent closing tags.
		if q := openQuote(raw); q != 0 {
			out.Write(src[copied:end])
			out.WriteByte(q)
			copied = end
			changes = append(changes, Change{end, end, "quote-before-recovered-boundary"})
		}
		i = end + 1
		if !closing && name == "script" {
			// HTML script has escaped and double-escaped raw-text states.
			// Delegate those states to the tokenizer, without constructing a
			// tree or decoding entities. Raw spans are visited only once.
			z := html.NewTokenizer(io.MultiReader(strings.NewReader("<script>"), strings.NewReader(s[i:])))
			consumed := i - len("<script>")
			for {
				kind := z.Next()
				if kind == html.ErrorToken {
					i = len(s)
					break
				}
				if kind == html.EndTagToken {
					n, _ := z.TagName()
					if string(n) == "script" {
						i = consumed
						break
					}
				}
				consumed += len(z.Raw())
			}
			continue
		}
		if !closing && rawText(name) {
			if name == "plaintext" {
				break
			}
			at := i
			for {
				j := strings.Index(lower[at:], "</"+name)
				if j < 0 {
					i = len(s)
					break
				}
				j += at
				k := j + 2 + len(name)
				if k == len(s) || s[k] == '>' || s[k] == '/' || lexicalSpace(s[k]) {
					i = j
					break
				}
				at = k
			}
		}
	}
	if len(changes) == 0 {
		return src, nil, nil
	}
	out.Write(src[copied:])
	return out.Bytes(), changes, nil
}
func rawText(n string) bool {
	switch n {
	case "style", "script", "title", "textarea", "xmp", "iframe", "noembed", "noframes", "plaintext":
		return true
	}
	return false
}
func tagName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	c := strings.HasPrefix(s, "/")
	s = strings.TrimPrefix(s, "/")
	i := 0
	for i < len(s) && !lexicalSpace(s[i]) && s[i] != '/' && s[i] != '=' {
		i++
	}
	return strings.ToLower(s[:i]), c
}
func commentEnd(s string, i int) (int, bool) {
	if i < len(s) && s[i] == '>' {
		return i + 1, true
	}
	if strings.HasPrefix(s[i:], "->") {
		return i + 2, true
	}
	for ; i < len(s); i++ {
		if strings.HasPrefix(s[i:], "-->") {
			return i + 3, true
		}
		if strings.HasPrefix(s[i:], "--!>") {
			return i + 4, true
		}
	}
	return 0, false
}

// openQuote uses the same attribute states as lexicalTagEnd, over its selected
// prefix. A quote inside an unquoted value is never treated as a delimiter.
func openQuote(s string) byte {
	state := 0
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case 0:
			if lexicalSpace(c) {
				state = 1
			}
		case 1:
			if !lexicalSpace(c) && c != '/' {
				state = 2
			}
		case 2:
			if c == '=' {
				state = 4
			} else if lexicalSpace(c) || c == '/' {
				state = 3
			}
		case 3:
			if c == '=' {
				state = 4
			} else if !lexicalSpace(c) && c != '/' {
				state = 2
			}
		case 4:
			if c == '\'' || c == '"' {
				q = c
				state = 5
			} else if !lexicalSpace(c) {
				state = 6
			}
		case 5:
			if c == q {
				q = 0
				state = 3
			}
		case 6:
			if lexicalSpace(c) {
				state = 1
			}
		}
	}
	return q
}
func lexicalSpace(c byte) bool       { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' }
func lexicalASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func lexicalMarkupStart(s string, i int) bool {
	if i+1 >= len(s) {
		return false
	}
	c := s[i+1]
	return lexicalASCIILetter(c) || c == '!' || c == '?' || c == '/' && i+2 < len(s) && lexicalASCIILetter(s[i+2])
}
func lexicalAttributeNameByte(c byte) bool {
	return lexicalASCIILetter(c) || c >= '0' && c <= '9' || c == '-' || c == '_' || c == ':'
}
func lexicalHiddenElement(n string) bool {
	return n == "style" || n == "script" || n == "template" || n == "iframe" || n == "title"
}
func lexicalTagName(s string) (string, bool) { return tagName(s) }
func lexicalTagEnd(source string, offset int, budget *int) (end int, found bool) {
	const (
		lexicalTagName = iota
		lexicalBeforeAttributeName
		lexicalAttributeName
		lexicalAfterAttributeName
		lexicalBeforeAttributeValue
		lexicalQuotedAttributeValue
		lexicalUnquotedAttributeValue
	)
	state := lexicalTagName
	var quote byte
	quotedTagEnd := -1
	quotedTagContainsMarkup := false
	for offset < len(source) {
		*budget--
		if *budget <= 0 {
			return 0, false
		}
		value := source[offset]
		switch state {
		case lexicalQuotedAttributeValue:
			if value == quote {
				// Some malformed email HTML ends a quoted value only after
				// swallowing subsequent tags. If the purported closing quote is
				// itself followed by invalid attribute syntax, recover at the first
				// '>' instead of promoting following CSS/markup to visible text.
				// A valid quoted value containing '>' and '<' remains untouched.
				if quotedTagEnd >= 0 && quotedTagContainsMarkup && offset+1 < len(source) &&
					!lexicalSpace(source[offset+1]) && source[offset+1] != '>' && source[offset+1] != '/' {
					if !lexicalAttributeNameByte(source[offset+1]) ||
						lexicalQuotedMarkupNeedsRecovery(source[quotedTagEnd+1:offset], budget) {
						return quotedTagEnd, true
					}
				}
				quote = 0
				quotedTagEnd = -1
				quotedTagContainsMarkup = false
				state = lexicalAfterAttributeName
			} else if value == '>' && quotedTagEnd < 0 {
				quotedTagEnd = offset
			} else if value == '<' && quotedTagEnd >= 0 && lexicalMarkupStart(source, offset) {
				quotedTagContainsMarkup = true
			}
		case lexicalTagName:
			switch {
			case value == '>':
				return offset, true
			case lexicalSpace(value):
				state = lexicalBeforeAttributeName
			}
		case lexicalBeforeAttributeName:
			switch {
			case value == '>':
				return offset, true
			case lexicalSpace(value), value == '/':
			default:
				state = lexicalAttributeName
			}
		case lexicalAttributeName:
			switch {
			case value == '>':
				return offset, true
			case lexicalSpace(value):
				state = lexicalAfterAttributeName
			case value == '=':
				state = lexicalBeforeAttributeValue
			case value == '/':
				state = lexicalAfterAttributeName
			}
		case lexicalAfterAttributeName:
			switch {
			case value == '>':
				return offset, true
			case lexicalSpace(value), value == '/':
			case value == '=':
				state = lexicalBeforeAttributeValue
			default:
				state = lexicalAttributeName
			}
		case lexicalBeforeAttributeValue:
			switch {
			case lexicalSpace(value):
			case value == '\'', value == '"':
				quote = value
				state = lexicalQuotedAttributeValue
			case value == '>':
				return offset, true
			default:
				state = lexicalUnquotedAttributeValue
			}
		case lexicalUnquotedAttributeValue:
			switch {
			case value == '>':
				return offset, true
			case lexicalSpace(value):
				state = lexicalBeforeAttributeName
			}
		}
		offset++
	}
	return 0, false
}

// lexicalQuotedMarkupNeedsRecovery preserves the legacy recovery needed by
// broken email HTML that swallows actual non-rendered elements into an
// unterminated quoted attribute. Unknown tag-like text inside an otherwise
// valid quoted value is not enough to override normal HTML tokenization.
func lexicalQuotedMarkupNeedsRecovery(value string, budget *int) bool {
	for i := 0; i < len(value); i++ {
		*budget--
		if *budget <= 0 {
			return false
		}
		if value[i] != '<' {
			continue
		}
		for _, name := range []string{"style", "script", "template", "iframe", "title"} {
			k := i + 1 + len(name)
			if k <= len(value) && strings.EqualFold(value[i+1:k], name) && (k == len(value) || lexicalSpace(value[k]) || value[k] == '/' || value[k] == '>') {
				return true
			}
		}
	}
	return false
}

func lexicalExactOpeningTag(rawTag, name string) bool {
	rawTag = strings.TrimLeft(rawTag, " \t\r\n\f")
	if name == "" || strings.HasPrefix(rawTag, "/") || len(rawTag) < len(name) || !strings.EqualFold(rawTag[:len(name)], name) {
		return false
	}
	return len(rawTag) == len(name) || lexicalSpace(rawTag[len(name)]) || rawTag[len(name)] == '/'
}
