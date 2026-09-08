package message

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/url"
	"strings"
)

type extractedContent struct {
	Text        string
	VisibleText string
	Links       []string
	ImageRefs   []string
	Images      []extractedImage
}

type extractedImage struct {
	ContentID string
	Data      []byte
}

func extractMIME(contentType, encoding, contentID string, data []byte, depth int) extractedContent {
	if depth > 8 {
		return extractedContent{Text: "[MIME nesting limit reached]"}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	decoded := decodeTransfer(encoding, data)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]"}
		}
		reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []extractedContent
		var alternativeHTML, alternativePlain extractedContent
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			// The complete message body has already been bounded by Message.MaxBytes.
			// Do not impose a smaller per-part limit here: doing so would silently
			// discard evidence from otherwise retained messages.
			body, _ := io.ReadAll(part)
			partContentType := part.Header.Get("Content-Type")
			content := extractMIME(partContentType, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-ID"), body, depth+1)
			if !hasExtractedContent(content) {
				continue
			}
			parts = append(parts, content)
			if mediaType == "multipart/alternative" {
				partMediaType, _, _ := mime.ParseMediaType(partContentType)
				switch partMediaType {
				case "text/html":
					alternativeHTML = content
				case "text/plain":
					alternativePlain = content
				}
			}
		}
		if mediaType == "multipart/alternative" {
			switch {
			case hasExtractedContent(alternativeHTML):
				return alternativeHTML
			case hasExtractedContent(alternativePlain):
				return alternativePlain
			case len(parts) > 0:
				return parts[len(parts)-1]
			default:
				return extractedContent{}
			}
		}
		var combined extractedContent
		var textParts, visibleTextParts []string
		for _, part := range parts {
			textParts = append(textParts, part.Text)
			visibleTextParts = append(visibleTextParts, part.VisibleText)
			combined.Links = append(combined.Links, part.Links...)
			combined.ImageRefs = append(combined.ImageRefs, part.ImageRefs...)
			combined.Images = append(combined.Images, part.Images...)
		}
		combined.Text = strings.Join(textParts, "\n\n")
		combined.VisibleText = strings.Join(visibleTextParts, "\n\n")
		return combined
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		content := extractedContent{Text: "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]"}
		if strings.HasPrefix(mediaType, "image/") {
			content.Images = []extractedImage{{ContentID: normalizeContentID(contentID), Data: decoded}}
		}
		return content
	}
	text := string(decoded)
	if mediaType == "text/html" {
		return htmlToText(text)
	}
	return extractedContent{Text: text, VisibleText: text, Links: findHTTPURLs(text)}
}

func hasExtractedContent(content extractedContent) bool {
	return strings.TrimSpace(content.Text) != "" || len(content.Links) > 0 || len(content.ImageRefs) > 0 || len(content.Images) > 0
}

func normalizeContentID(value string) string {
	value = strings.TrimSpace(strings.Trim(value, "<>"))
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	return strings.ToLower(value)
}

func decodeTransfer(encoding string, data []byte) []byte {
	var reader io.Reader = bytes.NewReader(data)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedprintable.NewReader(reader)
	}
	// Transfer decoding cannot expand base64 or quoted-printable input beyond
	// the already bounded source message, so a second fixed-size limit would
	// only create an undocumented truncation point.
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return data
	}
	return decoded
}
