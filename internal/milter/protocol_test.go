package milter

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

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
