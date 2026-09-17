package message

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"strings"

	"golang.org/x/net/html/charset"
)

type extractedContent struct {
	Text        string
	VisibleText string
	Links       []string
	ImageRefs   []string
	Images      []extractedImage
	HTML        bool
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
	mediaType = strings.ToLower(mediaType)
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
			if mediaType == "multipart/digest" && strings.TrimSpace(partContentType) == "" {
				partContentType = "message/rfc822"
			}
			content := extractMIME(partContentType, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-ID"), body, depth+1)
			if !hasExtractedContent(content) {
				continue
			}
			parts = append(parts, content)
			if mediaType == "multipart/alternative" {
				partMediaType, _, _ := mime.ParseMediaType(partContentType)
				switch {
				case content.HTML:
					// HTML with CID resources is normally wrapped in
					// multipart/related. Preserve that complete branch rather
					// than selecting the direct text/plain alternative.
					alternativeHTML = content
				case partMediaType == "text/plain":
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
		var imageRefs imageRefCollector
		var textParts, visibleTextParts []string
		for _, part := range parts {
			textParts = append(textParts, part.Text)
			visibleTextParts = append(visibleTextParts, part.VisibleText)
			combined.Links = append(combined.Links, part.Links...)
			imageRefs.AddAll(part.ImageRefs)
			combined.Images = append(combined.Images, part.Images...)
			combined.HTML = combined.HTML || part.HTML
		}
		combined.ImageRefs = imageRefs.refs
		combined.Text = strings.Join(textParts, "\n\n")
		combined.VisibleText = strings.Join(visibleTextParts, "\n\n")
		return combined
	}
	if mediaType == "message/rfc822" {
		return extractAttachedMessage(decoded, depth)
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		content := extractedContent{Text: "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]"}
		if strings.HasPrefix(mediaType, "image/") {
			content.Images = []extractedImage{{ContentID: normalizeContentID(contentID), Data: decoded}}
		}
		return content
	}
	text := decodeCharset(params["charset"], decoded)
	if mediaType == "text/html" {
		content := htmlToText(text)
		content.HTML = true
		return content
	}
	return extractedContent{Text: text, VisibleText: text, Links: findHTTPURLs(text)}
}

func extractAttachedMessage(data []byte, depth int) extractedContent {
	attached, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return extractedContent{Text: "[attached message could not be parsed]"}
	}
	body, err := io.ReadAll(attached.Body)
	if err != nil {
		return extractedContent{Text: "[attached message body could not be read]"}
	}
	return extractMIME(
		attached.Header.Get("Content-Type"),
		attached.Header.Get("Content-Transfer-Encoding"),
		attached.Header.Get("Content-ID"),
		body,
		depth+1,
	)
}

// decodeCharset converts MIME text bodies to UTF-8 after their transfer
// encoding has been decoded. Unknown labels and malformed encoded text retain
// the original content so that a bad charset declaration cannot erase the
// message body.
func decodeCharset(label string, data []byte) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return string(data)
	}
	reader, err := charset.NewReaderLabel(label, bytes.NewReader(data))
	if err != nil {
		return string(data)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(data)
	}
	return string(decoded)
}

func hasExtractedContent(content extractedContent) bool {
	return strings.TrimSpace(content.Text) != "" || len(content.Links) > 0 || len(content.ImageRefs) > 0 || len(content.Images) > 0
}

func normalizeContentID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '<' && value[len(value)-1] == '>' {
		value = strings.TrimSpace(value[1 : len(value)-1])
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	return strings.ToLower(value)
}

func decodeTransfer(encoding string, data []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		if err == nil {
			return decoded
		}
		// Some senders omit the final MIME padding. RawStdEncoding accepts that
		// specific variation without ignoring arbitrary corrupt characters.
		if unpadded, rawErr := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(data))); rawErr == nil {
			return unpadded
		}
		if len(decoded) > 0 {
			return decoded
		}
		return data
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data)))
		if err == nil || len(decoded) > 0 {
			return decoded
		}
		return data
	default:
		return data
	}
}
