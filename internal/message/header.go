package message

import (
	"io"
	"mime"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/xnethtml/charset"
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
