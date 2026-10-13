package htmlextract

import (
	"encoding/base64"
	"mime"
	"net/url"
	"strings"

	"github.com/tdewolff/parse/v2/css"
	"golang.org/x/net/html"
)

const maxImportDepth = 8

func cssTypeAttributeApplies(n *html.Node) bool {
	typ := strings.TrimSpace(attr(n, "type"))
	if typ == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(typ)
	return err == nil && strings.EqualFold(mediaType, "text/css")
}

func stylesheetLink(n *html.Node) (href, media string, applies bool) {
	if n.Namespace != "" || n.Data != "link" || hasAttr(n, "disabled") {
		return "", "", false
	}
	relations := strings.Fields(strings.ToLower(attr(n, "rel")))
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
	if !mediaCanApply(media) {
		return "", "", false
	}
	href = strings.TrimSpace(attr(n, "href"))
	return href, media, href != ""
}

func mediaCanApply(value string) bool {
	if strings.TrimSpace(value) == "" {
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
	data, isData, valid := decodeCSSDataURL(href, s.limits.CSSBytes)
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
	if s.importDepth >= maxImportDepth {
		s.unresolvedStylesheet = true
		return
	}
	s.importDepth++
	firstRule := len(s.rules)
	s.parseCSS(text, false)
	s.importDepth--
	s.attachMediaCondition(firstRule, media)
}

func (s *sheet) parseImport(values []css.Token) {
	href, media, ok, unsupported := importReference(values)
	if !ok {
		return
	}
	if unsupported {
		s.unresolvedStylesheet = true
		return
	}
	if !mediaCanApply(media) {
		return
	}
	s.loadStylesheetReference(href, media)
}

func importReference(values []css.Token) (href, media string, ok, unsupported bool) {
	start := 0
	for start < len(values) && (values[start].TokenType == css.WhitespaceToken || values[start].TokenType == css.CommentToken) {
		start++
	}
	if start == len(values) {
		return "", "", false, false
	}
	href, ok = cssURL(values[start])
	if !ok {
		return "", "", false, false
	}
	start++
	for start < len(values) && (values[start].TokenType == css.WhitespaceToken || values[start].TokenType == css.CommentToken) {
		start++
	}
	if start < len(values) {
		first := strings.ToLower(strings.TrimSpace(string(values[start].Data)))
		if first == "layer" || strings.HasPrefix(first, "layer(") || strings.HasPrefix(first, "supports(") {
			// Cascade layers and supports() need semantics the extractor does not
			// model. Do not apply the imported sheet unconditionally.
			return href, "", true, true
		}
		media = tokenString(values[start:])
	}
	return href, media, true, false
}

func cssURL(token css.Token) (string, bool) {
	raw := strings.TrimSpace(string(token.Data))
	switch token.TokenType {
	case css.StringToken:
		return unquoteCSSURL(raw)
	case css.URLToken:
		open := strings.IndexByte(raw, '(')
		if open < 0 {
			return "", false
		}
		raw = strings.TrimSpace(raw[open+1:])
		if strings.HasSuffix(raw, ")") {
			raw = strings.TrimSpace(raw[:len(raw)-1])
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
	value = strings.TrimSpace(cssUnescape(value))
	return value, value != ""
}

func decodeCSSDataURL(reference string, maxBytes int) ([]byte, bool, bool) {
	if !strings.HasPrefix(strings.ToLower(reference), "data:") {
		return nil, false, false
	}
	comma := strings.IndexByte(reference, ',')
	if comma < 5 {
		return nil, true, false
	}
	metadata := reference[5:comma]
	base64Encoded := false
	if fields := strings.Split(metadata, ";"); len(fields) > 1 && strings.EqualFold(strings.TrimSpace(fields[len(fields)-1]), "base64") {
		base64Encoded = true
		metadata = strings.Join(fields[:len(fields)-1], ";")
	}
	mediaType, params, err := mime.ParseMediaType(metadata)
	if err != nil || !strings.EqualFold(mediaType, "text/css") {
		return nil, true, false
	}
	if charset := strings.ToLower(strings.TrimSpace(params["charset"])); charset != "" && charset != "utf-8" && charset != "us-ascii" {
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
