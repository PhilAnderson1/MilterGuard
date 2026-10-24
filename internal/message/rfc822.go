package message

import (
	"bytes"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Attached messages retain structural fields and bounded attribution metadata.
// Limiting the complete header prevents irrelevant fields from consuming
// unbounded parsing work before the ordinary message resource limits apply.
const maxAttachedMessageHeaderBytes = 1 << 20

type attachedMessage struct {
	contentType      string
	transferEncoding string
	contentID        string
	disposition      string
	body             []byte
	headers          string
}

type attachedHeader uint8

const (
	attachedHeaderIgnored attachedHeader = iota
	attachedHeaderContentType
	attachedHeaderTransferEncoding
	attachedHeaderContentID
	attachedHeaderDisposition
	attachedHeaderFrom
	attachedHeaderTo
	attachedHeaderCc
	attachedHeaderDate
	attachedHeaderSubject
)

// parseAttachedMessage scans RFC 822 headers without constructing a general
// header map. It retains bounded attribution and structural MIME fields; the
// returned body borrows data and therefore needs no allocation.
func parseAttachedMessage(data []byte, budget *extractionBudget) (attachedMessage, bool) {
	var message attachedMessage
	memory := budget.allocationMemory()

	var value guardedBuilder
	var current attachedHeader
	metadata := newGuardedBuilder(memory)
	metadataOmitted, fieldTruncated := false, false
	writeValue := func(part []byte) {
		if current >= attachedHeaderFrom && len(part) > maxAttachmentFieldBytes-value.Len() {
			part = part[:max(0, maxAttachmentFieldBytes-value.Len())]
			fieldTruncated = true
		}
		_, _ = value.Write(part)
	}
	finish := func() {
		if metadataOmitted {
			metadata.WriteString("[additional attachment metadata omitted]\n")
		}
		message.headers = metadata.String()
	}
	haveField := false
	keepField := false
	seenContentType, seenTransferEncoding, seenContentID := false, false, false
	seenDisposition := false

	commit := func() {
		if !keepField {
			return
		}
		switch current {
		case attachedHeaderContentType:
			message.contentType = value.String()
		case attachedHeaderTransferEncoding:
			message.transferEncoding = value.String()
		case attachedHeaderContentID:
			message.contentID = value.String()
		case attachedHeaderDisposition:
			message.disposition = value.String()
		default:
			if current >= attachedHeaderFrom {
				if metadata.Len()+maxAttachmentFieldBytes*2 > maxAttachmentMetadataBytes {
					metadataOmitted = true
					break
				}
				name := [...]string{"From", "To", "Cc", "Date", "Subject"}[current-attachedHeaderFrom]
				metadata.WriteString(name + ": ")
				metadata.WriteString(attachmentMetadataValue(value.String(), budget))
				if fieldTruncated {
					metadata.WriteString(" [metadata truncated]")
				}
				metadata.WriteString("\n")
			}
		}
		keepField = false
	}

	start := 0
	colon := -1
	for offset := 0; ; offset++ {
		end := offset == len(data)
		if offset > maxAttachedMessageHeaderBytes || offset == maxAttachedMessageHeaderBytes && !end {
			return attachedMessage{}, false
		}
		if offset%resourceguard.WorkChunk == 0 {
			budget.decodingShouldStop()
		}

		if !end && data[offset] != '\n' {
			if data[offset] == ':' && colon < 0 {
				colon = offset - start
			}
			continue
		}

		line := data[start:offset]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			if end && !haveField {
				return attachedMessage{}, false
			}
			commit()
			if end {
				message.body = data[len(data):]
			} else {
				message.body = data[offset+1:]
			}
			finish()
			return message, true
		}

		if line[0] == ' ' || line[0] == '\t' {
			if !haveField {
				return attachedMessage{}, false
			}
			if keepField {
				continuation := trimAttachedHeaderSpace(line, budget)
				if len(continuation) != 0 {
					if value.Len() != 0 && (current < attachedHeaderFrom || value.Len() < maxAttachmentFieldBytes) {
						value.appendByte(' ')
					}
					writeValue(continuation)
				}
			}
		} else {
			commit()
			if colon < 0 {
				return attachedMessage{}, false
			}
			haveField = true
			current = classifyAttachedHeader(line[:colon])
			switch current {
			case attachedHeaderContentType:
				keepField = !seenContentType
				seenContentType = true
			case attachedHeaderTransferEncoding:
				keepField = !seenTransferEncoding
				seenTransferEncoding = true
			case attachedHeaderContentID:
				keepField = !seenContentID
				seenContentID = true
			case attachedHeaderDisposition:
				keepField = !seenDisposition
				seenDisposition = true
			default:
				keepField = current >= attachedHeaderFrom && !budget.omitAttachmentContext && metadata.Len()+maxAttachmentFieldBytes*2 <= maxAttachmentMetadataBytes
				if current >= attachedHeaderFrom && !keepField && !budget.omitAttachmentContext {
					metadataOmitted = true
				}
			}
			if keepField {
				value = newGuardedBuilder(memory)
				fieldTruncated = false
				writeValue(trimAttachedHeaderSpace(line[colon+1:], budget))
			}
		}

		if end {
			commit()
			message.body = data[len(data):]
			finish()
			return message, true
		}
		start = offset + 1
		colon = -1
	}
}

func classifyAttachedHeader(name []byte) attachedHeader {
	if len(name) > len("Content-Transfer-Encoding") {
		return attachedHeaderIgnored
	}
	switch {
	case bytes.EqualFold(name, []byte("Content-Type")):
		return attachedHeaderContentType
	case bytes.EqualFold(name, []byte("Content-Transfer-Encoding")):
		return attachedHeaderTransferEncoding
	case bytes.EqualFold(name, []byte("Content-ID")):
		return attachedHeaderContentID
	case bytes.EqualFold(name, []byte("Content-Disposition")):
		return attachedHeaderDisposition
	case bytes.EqualFold(name, []byte("From")):
		return attachedHeaderFrom
	case bytes.EqualFold(name, []byte("To")):
		return attachedHeaderTo
	case bytes.EqualFold(name, []byte("Cc")):
		return attachedHeaderCc
	case bytes.EqualFold(name, []byte("Date")):
		return attachedHeaderDate
	case bytes.EqualFold(name, []byte("Subject")):
		return attachedHeaderSubject
	default:
		return attachedHeaderIgnored
	}
}

func trimAttachedHeaderSpace(value []byte, budget *extractionBudget) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t') {
		start++
		if start%resourceguard.WorkChunk == 0 {
			budget.decodingShouldStop()
		}
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t') {
		end--
		if (len(value)-end)%resourceguard.WorkChunk == 0 {
			budget.decodingShouldStop()
		}
	}
	return value[start:end]
}

func extractAttachedMessage(data []byte, depth int, budget *extractionBudget, filenames ...string) extractedContent {
	filename := ""
	if len(filenames) > 0 {
		filename = filenames[0]
	}
	attached, ok := parseAttachedMessage(data, budget)
	if !ok {
		return wrapAttachment(extractedContent{Text: "[attached message could not be parsed]", VisibleText: "[attached message could not be parsed]", MIMEIncomplete: true}, "attached-email", filename, "", "", budget)
	}
	content := extractMIMEWithBudget(
		attached.contentType,
		attached.transferEncoding,
		attached.contentID,
		attached.body,
		depth+1,
		budget,
		mimePartInfo{Disposition: attached.disposition},
	)
	return wrapAttachment(content, "attached-email", filename, "", attached.headers, budget)
}
