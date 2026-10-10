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
	Text                 string
	VisibleText          string
	StrippedText         string
	Links                []string
	ImageRefs            []string
	Images               []extractedImage
	HTML                 bool
	MIMEIncomplete       bool
	TransferIncomplete   bool
	ExtractionIncomplete bool
	HasConcealedContent  bool
	Annotations          annotationUsage
}

type extractedImage struct {
	ContentID string
	Data      []byte
}

func extractMIME(contentType, encoding, contentID string, data []byte, depth int) extractedContent {
	if depth > 8 {
		return extractedContent{Text: "[MIME nesting limit reached]", MIMEIncomplete: true}
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" {
		mediaType = "text/plain"
	}
	mediaType = strings.ToLower(mediaType)
	decoded, transferIncomplete := decodeTransferRecovering(encoding, data)
	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return extractedContent{Text: "[multipart message has no boundary]", MIMEIncomplete: true, TransferIncomplete: transferIncomplete}
		}
		reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
		var parts []extractedContent
		var alternativeHTML, alternativePlain extractedContent
		var mimeIncomplete, nestedTransferIncomplete bool
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				mimeIncomplete = true
				break
			}
			// The complete message body has already been bounded by Message.maxBytes.
			// Do not impose a smaller per-part limit here: doing so would silently
			// discard evidence from otherwise retained messages.
			body, readErr := io.ReadAll(part)
			mimeIncomplete = mimeIncomplete || readErr != nil
			partContentType := part.Header.Get("Content-Type")
			if mediaType == "multipart/digest" && strings.TrimSpace(partContentType) == "" {
				partContentType = "message/rfc822"
			}
			content := extractMIME(partContentType, part.Header.Get("Content-Transfer-Encoding"), part.Header.Get("Content-ID"), body, depth+1)
			mimeIncomplete = mimeIncomplete || content.MIMEIncomplete
			nestedTransferIncomplete = nestedTransferIncomplete || content.TransferIncomplete
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
			var selected extractedContent
			switch {
			case hasExtractedContent(alternativeHTML):
				selected = alternativeHTML
			case hasExtractedContent(alternativePlain):
				selected = alternativePlain
			case len(parts) > 0:
				selected = parts[len(parts)-1]
			}
			selected.MIMEIncomplete = mimeIncomplete
			selected.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
			return selected
		}
		var combined extractedContent
		var imageRefs imageRefCollector
		var textParts, visibleTextParts []string
		for _, part := range parts {
			textParts = append(textParts, part.Text)
			visibleTextParts = append(visibleTextParts, part.VisibleText)
			stripped := part.StrippedText
			if stripped == "" && !part.HasConcealedContent {
				stripped = part.Text
			}
			combined.StrippedText = joinContent(combined.StrippedText, stripped)
			combined.Links = append(combined.Links, part.Links...)
			imageRefs.AddAll(part.ImageRefs)
			combined.Images = append(combined.Images, part.Images...)
			combined.HTML = combined.HTML || part.HTML
			combined.HasConcealedContent = combined.HasConcealedContent || part.HasConcealedContent
			combined.ExtractionIncomplete = combined.ExtractionIncomplete || part.ExtractionIncomplete
			combined.Annotations = mergeAnnotationUsage(combined.Annotations, part.Annotations)
		}
		combined.ImageRefs = imageRefs.refs
		combined.Text = strings.Join(textParts, "\n\n")
		combined.VisibleText = strings.Join(visibleTextParts, "\n\n")
		combined.MIMEIncomplete = mimeIncomplete
		combined.TransferIncomplete = transferIncomplete || nestedTransferIncomplete
		return combined
	}
	if mediaType == "message/rfc822" {
		content := extractAttachedMessage(decoded, depth)
		content.TransferIncomplete = content.TransferIncomplete || transferIncomplete
		return content
	}
	if mediaType != "text/plain" && mediaType != "text/html" {
		content := extractedContent{Text: "[attachment: " + sanitize(params["name"]) + "; type=" + mediaType + "]", TransferIncomplete: transferIncomplete}
		if strings.HasPrefix(mediaType, "image/") {
			content.Images = []extractedImage{{ContentID: normalizeContentID(contentID), Data: decoded}}
		}
		return content
	}
	if mediaType == "text/html" {
		text := decodeHTMLCharset(params["charset"], decoded)
		content := htmlToText(text)
		content.HTML = true
		content.TransferIncomplete = transferIncomplete
		return content
	}
	text := decodeCharset(params["charset"], decoded)
	return extractedContent{Text: text, VisibleText: text, Links: findHTTPURLs(text), TransferIncomplete: transferIncomplete}
}

func joinContent(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	return left + "\n\n" + right
}

func mergeAnnotationUsage(a, b annotationUsage) annotationUsage {
	return annotationUsage{
		UsedConcealedTag:                      a.UsedConcealedTag || b.UsedConcealedTag,
		UsedVisibilityVariesByViewportSizeTag: a.UsedVisibilityVariesByViewportSizeTag || b.UsedVisibilityVariesByViewportSizeTag,
		UsedVisibilityUncertainTag:            a.UsedVisibilityUncertainTag || b.UsedVisibilityUncertainTag,
		UsedHiddenContentStrippedTag:          a.UsedHiddenContentStrippedTag || b.UsedHiddenContentStrippedTag,
	}
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

// decodeHTMLCharset keeps a usable MIME declaration authoritative. Without
// one, HTML's own BOM or early meta declaration can identify its encoding;
// this does not parse the document or change the HTML extractor.
func decodeHTMLCharset(label string, data []byte) string {
	if encoding, _ := charset.Lookup(strings.TrimSpace(label)); encoding != nil {
		return strings.TrimPrefix(decodeCharset(label, data), "\ufeff")
	}
	reader, err := charset.NewReader(bytes.NewReader(data), "text/html")
	if err != nil {
		return string(data)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return string(data)
	}
	return strings.TrimPrefix(string(decoded), "\ufeff")
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

// decodeTransferRecovering is deliberately recovery-oriented: message extraction keeps
// readable evidence from malformed encodings and accepts omitted Base64
// padding. Attachment inspection uses a separate strict decoder so incomplete
// data cannot be reported as successfully scanned.
func decodeTransferRecovering(encoding string, data []byte) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(data)))
		if err == nil {
			return decoded, false
		}
		// Some senders omit the final MIME padding. RawStdEncoding accepts that
		// specific variation without ignoring arbitrary corrupt characters.
		if unpadded, rawErr := io.ReadAll(base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(data))); rawErr == nil {
			return unpadded, false
		}
		if len(decoded) > 0 {
			return decoded, true
		}
		return data, true
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(data)))
		if err == nil || len(decoded) > 0 {
			return decoded, err != nil
		}
		return data, true
	case "", "7bit", "8bit", "binary":
		return data, false
	default:
		return data, len(data) > 0
	}
}
