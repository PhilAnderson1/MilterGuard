package message

import (
	"io"
	"mime"
	"net/mail"
	"strings"

	"golang.org/x/net/html/charset"
)

var headerWordDecoder = &mime.WordDecoder{
	CharsetReader: func(label string, input io.Reader) (io.Reader, error) {
		return charset.NewReaderLabel(label, input)
	},
}

func decodeHeaderValue(value string) string {
	if decoded, err := headerWordDecoder.DecodeHeader(value); err == nil {
		value = decoded
	}
	return strings.ToValidUTF8(value, "�")
}

// MailboxAddress parses a single mailbox. If a malformed display name makes
// the complete header invalid, an unambiguous angle-enclosed mailbox is tried
// separately rather than discarding the usable address with the display name.
func MailboxAddress(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if address, err := mail.ParseAddress(value); err == nil && address.Address != "" {
		return address.Address, true
	}
	if strings.Count(value, "<") != 1 || strings.Count(value, ">") != 1 {
		return "", false
	}
	start := strings.IndexByte(value, '<')
	end := strings.IndexByte(value, '>')
	if start < 0 || end <= start+1 {
		return "", false
	}
	enclosed := strings.TrimSpace(value[start+1 : end])
	address, err := mail.ParseAddress(enclosed)
	if err != nil || address.Address == "" || address.Name != "" {
		return "", false
	}
	return address.Address, true
}
