package htmlextract

import (
	"encoding/base64"
	"mime"
	"net/url"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml"
)

const (
	maxCSSMediaTypeBytes = 1024
)

func htmlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func oversizedCSSMediaTypeMayApply(value string) bool {
	start := 0
	for start < len(value) && htmlSpace(value[start]) {
		start++
	}
	if start == len(value) {
		return true
	}
	const cssMediaType = "text/css"
	end := start + len(cssMediaType)
	if end > len(value) || !equalASCIIFold(value[start:end], cssMediaType) {
		return false
	}
	return end == len(value) || value[end] == ';' || htmlSpace(value[end])
}

func cssTypeAttributeApplies(n *html.Node) bool {
	typ := attr(n, "type")
	// mime.ParseMediaType builds a map for every parameter. Avoid allowing one
	// HTML attribute to turn an input-sized parameter list into a much larger
	// transient allocation. A text/css prefix remains potentially applicable;
	// accepting malformed trailing parameters is conservative for visibility.
	if len(typ) > maxCSSMediaTypeBytes {
		return oversizedCSSMediaTypeMayApply(typ)
	}
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(typ)
	return err == nil && equalASCIIFold(mediaType, "text/css")
}

func (s *sheet) stylesheetLink(n *html.Node) (href, media string, applies bool) {
	if s.cascadeIncomplete || s.stopped {
		return "", "", false
	}
	if n.Namespace != "" || n.Data != "link" || hasAttr(n, "disabled") {
		return "", "", false
	}
	relations := strings.Fields(asciiLower(attr(n, "rel")))
	stylesheet, alternate := false, false
	for _, relation := range relations {
		stylesheet = stylesheet || relation == "stylesheet"
		alternate = alternate || relation == "alternate"
	}
	if !stylesheet || alternate {
		return "", "", false
	}
	if !cssTypeAttributeApplies(n) {
		return "", "", false
	}
	media = attr(n, "media")
	if !s.mediaCanApply(media) {
		return "", "", false
	}
	href = strings.TrimSpace(attr(n, "href"))
	return href, media, href != ""
}

func (s *sheet) parseMediaCondition(value string) mediaCondition {
	if !s.checkCPU() {
		return mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
	}
	return parseMediaBudgeted(value, s.memory)
}

func (s *sheet) mediaCanApply(value string) bool {
	if trimCSSWhitespace(value) == "" {
		return true
	}
	// Applicability is a one-shot question; do not retain its parsed condition.
	if !s.checkCPU() {
		return true
	}
	for _, alternative := range parseMedia(value) {
		if !alternative.never {
			return true
		}
	}
	return false
}

func (s *sheet) loadStylesheetReference(href, media string) {
	// Once stylesheet analysis is unusable, decoding another data URL can only
	// consume CPU and transient memory; the resulting rules would be discarded.
	// Keep this guard at the shared boundary so it covers both link elements and
	// nested @import rules.
	if s.cascadeIncomplete || s.stopped {
		return
	}
	remaining := s.limits.CSSBytes - s.cssBytes
	if remaining < 0 {
		remaining = 0
	}
	data, isData, valid := decodeCSSDataURL(href, remaining)
	if !isData {
		s.unresolvedStylesheet = true
		return
	}
	if !valid {
		s.unresolvedStylesheet = true
		return
	}
	s.parseImportedStylesheet(string(data), media)
}

func (s *sheet) parseImportedStylesheet(text, media string) {
	firstRule := len(s.rules)
	s.parseStylesheetCSS(text)
	// Email clients disagree on whether data-URL stylesheets are applicable.
	// Retain their possible cascade effects, but do not let them establish a
	// definite visibility result. This also marks rules from nested imports
	// parsed during this call.
	s.markRulesUncertain(firstRule)
	s.attachMediaCondition(firstRule, media)
}

func (s *sheet) parseImport(values []css.Token) {
	reference := importReference(values)
	if !reference.valid {
		return
	}
	if reference.unsupported {
		s.unresolvedStylesheet = true
		return
	}
	if !s.mediaCanApply(reference.media) {
		return
	}
	s.loadStylesheetReference(reference.href, reference.media)
}

type cssImportReference struct {
	href, media string
	valid       bool
	unsupported bool
}

func importReference(values []css.Token) cssImportReference {
	start := 0
	for start < len(values) && (values[start].TokenType == css.WhitespaceToken || values[start].TokenType == css.CommentToken) {
		start++
	}
	if start == len(values) {
		return cssImportReference{}
	}
	href, ok := cssURL(values[start])
	if !ok {
		return cssImportReference{}
	}
	start++
	for start < len(values) && (values[start].TokenType == css.WhitespaceToken || values[start].TokenType == css.CommentToken) {
		start++
	}
	if start < len(values) {
		first := normalizeCSSKeyword(string(values[start].Data))
		if first == "layer" || strings.HasPrefix(first, "layer(") || strings.HasPrefix(first, "supports(") {
			// Cascade layers and supports() need semantics the extractor does not
			// model. Do not apply the imported sheet unconditionally.
			return cssImportReference{href: href, valid: true, unsupported: true}
		}
		return cssImportReference{href: href, media: tokenString(values[start:]), valid: true}
	}
	return cssImportReference{href: href, valid: true}
}

func cssURL(token css.Token) (string, bool) {
	raw := trimCSSWhitespace(string(token.Data))
	switch token.TokenType {
	case css.StringToken:
		return unquoteCSSURL(raw)
	case css.URLToken:
		open := strings.IndexByte(raw, '(')
		if open < 0 {
			return "", false
		}
		raw = trimCSSWhitespace(raw[open+1:])
		if strings.HasSuffix(raw, ")") {
			raw = trimCSSWhitespace(raw[:len(raw)-1])
		}
		return unquoteCSSURL(raw)
	default:
		return "", false
	}
}

func unquoteCSSURL(value string) (string, bool) {
	if len(value) >= 1 && (value[0] == '\'' || value[0] == '"') {
		quote := value[0]
		value = value[1:]
		if len(value) > 0 && value[len(value)-1] == quote {
			value = value[:len(value)-1]
		}
	}
	value = cssUnescape(value)
	return value, value != ""
}

func decodeCSSDataURL(reference string, maxBytes int) ([]byte, bool, bool) {
	if !hasASCIIFoldPrefix(reference, "data:") {
		return nil, false, false
	}
	comma := strings.IndexByte(reference, ',')
	if comma < 5 {
		return nil, true, false
	}
	metadata := reference[5:comma]
	// The payload is bounded separately by the remaining stylesheet budget.
	// Bound metadata before mime.ParseMediaType can allocate a parameter map
	// proportional to an otherwise multi-megabyte href value.
	if len(metadata) > maxCSSMediaTypeBytes {
		return nil, true, false
	}
	base64Encoded := false
	if separator := strings.LastIndexByte(metadata, ';'); separator >= 0 &&
		equalASCIIFold(strings.TrimSpace(metadata[separator+1:]), "base64") {
		base64Encoded = true
		metadata = metadata[:separator]
	}
	mediaType, params, err := mime.ParseMediaType(metadata)
	if err != nil || !equalASCIIFold(mediaType, "text/css") {
		return nil, true, false
	}
	if charset := asciiLower(strings.TrimSpace(params["charset"])); charset != "" && charset != "utf-8" && charset != "us-ascii" {
		return nil, true, false
	}
	payload := reference[comma+1:]
	if base64Encoded {
		if base64.StdEncoding.DecodedLen(len(payload)) > maxBytes {
			return nil, true, false
		}
		decoded, err := base64.StdEncoding.DecodeString(payload)
		return decoded, true, err == nil && len(decoded) <= maxBytes
	}
	if len(payload) > maxBytes*3 {
		return nil, true, false
	}
	decoded, err := url.PathUnescape(payload)
	return []byte(decoded), true, err == nil && len(decoded) <= maxBytes
}
