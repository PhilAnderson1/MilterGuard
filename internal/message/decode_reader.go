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
	memory     func() *resourceguard.Memory
}

func (c *decodeControl) check() bool {
	if !c.stopped && c.shouldStop != nil {
		c.stopped = c.shouldStop()
	}
	return c.stopped
}

// The coordinator selects an allocation owner; decoding never needs the
// primary ledger. Fixed-size decoder scratch remains outside the ledger.
func (c *decodeControl) allocationMemory() *resourceguard.Memory {
	if c.memory == nil {
		return nil
	}
	return c.memory()
}
func (c *decodeControl) copyString(value []byte) string {
	if c.check() {
		return ""
	}
	text, ok := resourceguard.CopyString(c.allocationMemory(), value, c.check)
	if !ok {
		c.stopped = true
	}
	return text
}
func (c *decodeControl) readAll(reader io.Reader) ([]byte, error) {
	if c.memory == nil {
		return io.ReadAll(reader)
	}
	var scratch [resourceguard.WorkChunk]byte
	buffer := newGuardedBuilder(nil)
	for {
		if c.check() {
			return buffer.Bytes(), resourceguard.ErrStopped
		}
		n, err := reader.Read(scratch[:])
		buffer.memory = c.allocationMemory()
		if _, writeErr := buffer.Write(scratch[:n]); writeErr != nil {
			c.stopped = true
			return buffer.Bytes(), writeErr
		}
		if err == io.EOF {
			return buffer.Bytes(), nil
		}
		if err != nil {
			return buffer.Bytes(), err
		}
	}
}
