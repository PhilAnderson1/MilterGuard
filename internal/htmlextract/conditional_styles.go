package htmlextract

import (
	"bytes"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// parseMSOConditionalStyles extracts style elements from a downlevel-hidden
// Microsoft Office conditional comment. These rules apply only in some mail
// clients, so their origin is always uncertain.
func (s *sheet) parseMSOConditionalStyles(data string) {
	fragment, ok := msoConditionalFragment(data)
	if !ok || s.cascadeIncomplete || s.workIncomplete {
		return
	}
	// Most MSO comments contain alternate table markup rather than CSS. Avoid
	// constructing a tokenizer for those very common fragments.
	if !containsASCIIFold(fragment, "<style") {
		return
	}
	// Tokenizing the conditional markup is work in addition to parsing any CSS
	// it contains. Charge that scan before starting it.
	if !s.chargePlanningBytes(len(fragment)) {
		return
	}
	z := html.NewTokenizer(strings.NewReader(fragment))
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
		s.parseStylesheet(style.String(), attr(&styleNode, "media"), true)
		style.Reset()
		return !s.cascadeIncomplete && !s.workIncomplete
	}
	for {
		tokenType := z.Next()
		switch tokenType {
		case html.ErrorToken:
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
	msoRevealedEnd
)

// msoDownlevelRevealedMarker recognizes the paired comments used to expose
// markup to ordinary HTML clients while excluding it from Word-based Outlook:
//
// <!--[if !mso]><!--> ... <!--<![endif]-->
//
// x/net/html preserves these as separate comment nodes, although tree
// construction may move the intervening head/body elements. Tracking them in
// document order therefore works across those parser insertions.
func msoDownlevelRevealedMarker(data string) msoRevealedMarker {
	trimmed := strings.TrimSpace(data)
	if equalASCIIFold(trimmed, "<![endif]") {
		return msoRevealedEnd
	}
	if !hasASCIIFoldPrefix(trimmed, "[if ") {
		return msoRevealedNone
	}
	end := strings.Index(trimmed, "]>")
	if end < 0 || !equalASCIIFold(strings.TrimSpace(trimmed[len("[if "):end]), "!mso") {
		return msoRevealedNone
	}
	if strings.HasPrefix(strings.TrimSpace(trimmed[end+2:]), "<!") {
		return msoRevealedStart
	}
	return msoRevealedNone
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
