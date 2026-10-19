package message

import (
	"io"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Limit reads on both sides of a decoder. Input checks also bound work on
// whitespace, soft line breaks and state changes that produce no output.
type decodeReader struct {
	reader     io.Reader
	shouldStop func() bool
}

func newDecodeReader(reader io.Reader, shouldStop func() bool) io.Reader {
	if shouldStop == nil {
		return reader
	}
	return &decodeReader{reader: reader, shouldStop: shouldStop}
}
func (r *decodeReader) Read(p []byte) (int, error) {
	if r.shouldStop() {
		return 0, resourceguard.ErrStopped
	}
	return r.reader.Read(p[:min(len(p), 32<<10)])
}
func stoppedMIMEContent() extractedContent {
	return extractedContent{Text: "[MIME decoding stopped]", ExtractionIncomplete: true, HTMLCPULimitExceeded: true}
}

// Some recovery-oriented decoders replace input errors with their own syntax
// errors. Keep cancellation separate so those errors cannot start a retry.
type decodeControl struct {
	shouldStop func() bool
	stopped    bool
}

func (c *decodeControl) check() bool {
	if !c.stopped && c.shouldStop != nil {
		c.stopped = c.shouldStop()
	}
	return c.stopped
}
