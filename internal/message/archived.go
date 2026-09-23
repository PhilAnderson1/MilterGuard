package message

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"strings"
)

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
					msg.ArchiveTruncated = true
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
