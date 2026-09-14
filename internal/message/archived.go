package message

import (
	"bytes"
	"fmt"
	"io"
	"net/mail"
)

// ParseArchived parses a bounded RFC 5322 message into the same Message type
// used by live Milter processing.
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
