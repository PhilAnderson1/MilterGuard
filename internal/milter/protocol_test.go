package milter

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func readFrame(reader io.Reader) ([]byte, error) {
	frame, _, err := readFrameProgress(reader)
	return frame, err
}

func TestReadFrameRejectsZeroLengthDeclaration(t *testing.T) {
	header := make([]byte, 4)
	frame, bytesRead, err := readFrameProgress(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "invalid frame length 0") {
		t.Fatalf("zero-length frame error = %v", err)
	}
	if frame != nil {
		t.Fatalf("zero-length frame returned %d bytes", len(frame))
	}
	if bytesRead != len(header) {
		t.Fatalf("bytes read = %d, want %d-byte header only", bytesRead, len(header))
	}
}

func TestReadFrameRejectsOversizedDeclarationBeforeReadingPayload(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrameBytes+1)

	frame, bytesRead, err := readFrameProgress(bytes.NewReader(header[:]))
	if err == nil || !strings.Contains(err.Error(), "invalid frame length") {
		t.Fatalf("oversized frame error = %v", err)
	}
	if frame != nil {
		t.Fatalf("oversized frame returned %d bytes", len(frame))
	}
	if bytesRead != len(header) {
		t.Fatalf("bytes read = %d, want %d-byte header only", bytesRead, len(header))
	}
}

func TestReadFrameAcceptsMaximumFrameSize(t *testing.T) {
	payload := make([]byte, maxFrameBytes)
	payload[0] = commandBody
	var encoded bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	encoded.Write(header[:])
	encoded.Write(payload)

	frame, bytesRead, err := readFrameProgress(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, payload) {
		t.Fatal("maximum-size frame payload changed")
	}
	if bytesRead != len(header)+len(payload) {
		t.Fatalf("bytes read = %d, want %d", bytesRead, len(header)+len(payload))
	}
}

func TestTruncateUTF8NormalizesInvalidInput(t *testing.T) {
	if got, want := truncateUTF8("a\xffb", maxSMTPReplyBytes), "a�b"; got != want {
		t.Fatalf("normalized reply = %q, want %q", got, want)
	}
}

func TestTruncateUTF8DropsPartialFinalRune(t *testing.T) {
	value := strings.Repeat("a", maxSMTPReplyBytes-1) + "€"
	got := truncateUTF8(value, maxSMTPReplyBytes)
	if want := strings.Repeat("a", maxSMTPReplyBytes-1); got != want {
		t.Fatalf("truncated reply length = %d, want %d", len(got), len(want))
	}
}

func TestEnvelopeHasSMTPUTF8(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
		want    bool
	}{
		{name: "no arguments", payload: []byte("<sender@example.net>\x00")},
		{name: "other argument", payload: []byte("<sender@example.net>\x00SIZE=123\x00")},
		{name: "SMTPUTF8", payload: []byte("<sender@example.net>\x00SIZE=123\x00SMTPUTF8\x00"), want: true},
		{name: "case insensitive", payload: []byte("<sender@example.net>\x00smtputf8\x00"), want: true},
		{name: "malformed unterminated", payload: []byte("<sender@example.net>\x00SMTPUTF8")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := envelopeHasSMTPUTF8(test.payload); got != test.want {
				t.Fatalf("envelopeHasSMTPUTF8() = %v, want %v", got, test.want)
			}
		})
	}
}
