package message

import (
	"bytes"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Attached messages need only the structural fields used by MIME extraction.
// Limiting the complete header prevents irrelevant fields from consuming
// unbounded parsing work before the ordinary message resource limits apply.
const maxAttachedMessageHeaderBytes = 1 << 20

type attachedMessage struct {
	contentType      string
	transferEncoding string
	contentID        string
	body             []byte
}

type attachedHeader uint8

const (
	attachedHeaderIgnored attachedHeader = iota
	attachedHeaderContentType
	attachedHeaderTransferEncoding
	attachedHeaderContentID
)

// parseAttachedMessage scans RFC 822 headers without constructing a general
// header map. It retains only fields used by recursive MIME extraction; the
// returned body borrows data and therefore needs no allocation.
func parseAttachedMessage(data []byte, budget *extractionBudget) (attachedMessage, bool) {
	var message attachedMessage
	memory := budget.allocationMemory()

	var value guardedBuilder
	var current attachedHeader
	haveField := false
	keepField := false
	seenContentType, seenTransferEncoding, seenContentID := false, false, false

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
			return message, true
		}

		if line[0] == ' ' || line[0] == '\t' {
			if !haveField {
				return attachedMessage{}, false
			}
			if keepField {
				continuation := trimAttachedHeaderSpace(line, budget)
				if len(continuation) != 0 {
					if value.Len() != 0 {
						value.appendByte(' ')
					}
					_, _ = value.Write(continuation)
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
			default:
				keepField = false
			}
			if keepField {
				value = newGuardedBuilder(memory)
				_, _ = value.Write(trimAttachedHeaderSpace(line[colon+1:], budget))
			}
		}

		if end {
			commit()
			message.body = data[len(data):]
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

func extractAttachedMessage(data []byte, depth int, budget *extractionBudget) extractedContent {
	attached, ok := parseAttachedMessage(data, budget)
	if !ok {
		return extractedContent{Text: "[attached message could not be parsed]", MIMEIncomplete: true}
	}
	return extractMIMEWithBudget(
		attached.contentType,
		attached.transferEncoding,
		attached.contentID,
		attached.body,
		depth+1,
		budget,
	)
}
