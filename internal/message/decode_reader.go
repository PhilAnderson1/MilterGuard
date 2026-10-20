package message

import (
	"io"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Limit reads on both sides of a decoder. Input checks also bound work on
// whitespace, soft line breaks and state changes that produce no output.
type decodeReader struct {
	reader     io.Reader
	shouldStop func()
}

func newDecodeReader(reader io.Reader, shouldStop func()) io.Reader {
	if shouldStop == nil {
		return reader
	}
	return &decodeReader{reader: reader, shouldStop: shouldStop}
}
func (r *decodeReader) Read(p []byte) (int, error) {
	r.shouldStop()

	return r.reader.Read(p[:min(len(p), 32<<10)])
}

// Some recovery-oriented decoders replace input errors with their own syntax
// errors. Checkpoints unwind past that ordinary error channel, preventing retries.
type decodeControl struct {
	shouldStop func()
	memory     func() *resourceguard.Memory
}

func (c *decodeControl) check() {
	if c.shouldStop != nil {
		c.shouldStop()
	}
}

// The coordinator supplies the active primary or fallback ledger. Body
// buffering and copies are charged; fixed-size decoder scratch remains outside
// the ledger. Nil is reserved for standalone unbudgeted helpers.
func (c *decodeControl) allocationMemory() *resourceguard.Memory {
	if c.memory == nil {
		return nil
	}
	return c.memory()
}
func (c *decodeControl) copyString(value []byte) string {
	c.check()
	text := resourceguard.CopyString(c.allocationMemory(), value, c.check)

	return text
}
func (c *decodeControl) readAll(reader io.Reader) ([]byte, error) {
	if c.memory == nil {
		return io.ReadAll(reader)
	}
	var scratch [resourceguard.WorkChunk]byte
	buffer := newGuardedBuilder(nil)
	for {
		c.check()
		n, err := reader.Read(scratch[:])
		buffer.memory = c.allocationMemory()
		_, _ = buffer.Write(scratch[:n])
		if err == io.EOF {
			return buffer.Bytes(), nil
		}
		if err != nil {
			return buffer.Bytes(), err
		}
	}
}
