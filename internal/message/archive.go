package message

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"strings"
)

const archiveTruncationHeader = "X-MilterGuard-Archive-Truncated: yes\r\n"

func (m *Message) addArchiveHeader(name, value string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, ":\r\n\x00") {
		m.archiveHeadersTruncated = true
		return
	}
	for _, char := range name {
		if char < 33 || char > 126 {
			m.archiveHeadersTruncated = true
			return
		}
	}
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.ReplaceAll(value, "\n", "\r\n ")
	line := name + ": " + value + "\r\n"
	// Reserve at least half of the configured message budget for the body so
	// excessive headers cannot suppress all content presented for analysis.
	headerLimit := m.maxBytes / 2
	if m.archiveHeaderBytes+int64(len(line)) > headerLimit {
		m.archiveHeadersTruncated = true
		return
	}
	m.archiveHeaderBytes += int64(len(line))
	_, _ = m.archiveHeaders.WriteString(line)
}

// ArchiveBytes returns a syntactically valid bounded RFC 5322/MIME message
// reconstructed from the retained headers and body for rejected-message
// storage.
func (m *Message) ArchiveBytes() []byte {
	limit := m.maxBytes
	if limit < 2 {
		return nil
	}
	truncated := m.archiveHeadersTruncated || m.BodyTruncated
	reserved := int64(2)
	includeMarker := truncated && limit >= int64(len(archiveTruncationHeader))+reserved
	if includeMarker {
		reserved += int64(len(archiveTruncationHeader))
	}
	headers := completeArchiveHeaderPrefix(m.archiveHeaders.Bytes(), limit-reserved)
	var output bytes.Buffer
	estimated := int64(len(headers)) + reserved + m.bodySize
	if estimated > limit {
		estimated = limit
	}
	if estimated > 0 && estimated <= int64(int(^uint(0)>>1)) {
		output.Grow(int(estimated))
	}
	_, _ = output.Write(headers)
	if includeMarker {
		_, _ = output.WriteString(archiveTruncationHeader)
	}
	_, _ = output.WriteString("\r\n")
	remaining := limit - int64(output.Len())
	if remaining <= 0 {
		return output.Bytes()[:min(int64(output.Len()), limit)]
	}
	body := m.BodyBytes()
	if int64(len(body)) > remaining {
		body = body[:remaining]
	}
	_, _ = output.Write(body)
	return output.Bytes()
}

// completeArchiveHeaderPrefix returns only complete RFC 5322 fields. Folded
// continuation lines remain attached to their field, so the archive is never
// cut in the middle of a header or continuation line.
func completeArchiveHeaderPrefix(headers []byte, maxBytes int64) []byte {
	if maxBytes <= 0 {
		return nil
	}
	if int64(len(headers)) <= maxBytes {
		return headers
	}
	lastComplete := 0
	lineStart := 0
	for lineStart < len(headers) {
		lineLength := bytes.Index(headers[lineStart:], []byte("\r\n"))
		if lineLength < 0 {
			break
		}
		lineEnd := lineStart + lineLength + 2
		continuationFollows := lineEnd < len(headers) && (headers[lineEnd] == ' ' || headers[lineEnd] == '\t')
		if !continuationFollows {
			if int64(lineEnd) > maxBytes {
				break
			}
			lastComplete = lineEnd
		}
		lineStart = lineEnd
	}
	return headers[:lastComplete]
}

// ParseArchived reconstructs Message state from a bounded saved RFC 5322
// message so retrieval commands use the same processing pipeline as live mail.
func ParseArchived(raw []byte, maxBytes int64) (*Message, error) {
	if maxBytes < 1 || int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("archived message exceeds configured size limit")
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse archived message: %w", err)
	}
	msg := New(maxBytes)
	for name, values := range parsed.Header {
		if strings.EqualFold(name, "X-MilterGuard-Archive-Truncated") {
			for _, value := range values {
				if strings.EqualFold(strings.TrimSpace(value), "yes") {
					msg.SavedArchiveTruncated = true
					break
				}
			}
		}
	}
	for name, values := range parsed.Header {
		for _, value := range values {
			msg.AddHeader(name, value)
		}
	}
	body, err := io.ReadAll(parsed.Body)
	if err != nil {
		return nil, fmt.Errorf("read archived message body: %w", err)
	}
	msg.AddBody(body)
	return msg, nil
}
