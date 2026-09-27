package mailauth

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	ErrExactMessageClosed   = errors.New("exact message is closed")
	ErrExactMessageTooLarge = errors.New("exact message exceeds configured size limit")
)

// ExactMessage preserves the RFC 5322 representation required by DKIM while
// it is received through Milter callbacks. ReaderAt may be called after the
// end-of-headers marker has been appended and all body chunks have been added.
type ExactMessage interface {
	AddHeader(name, value string) error
	EndHeaders() error
	AddBody(payload []byte) error
	ReaderAt() (io.ReaderAt, int64, error)
	Close() error
}

// NewExactMessage returns a bounded exact-message store. Supported storage
// modes are "memory" and "file".
func NewExactMessage(storage string, maxBytes int64) (ExactMessage, error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("exact message maximum must be positive")
	}
	switch storage {
	case "memory":
		return &memoryExactMessage{maxBytes: maxBytes}, nil
	case "file":
		return newFileExactMessage(maxBytes, "")
	default:
		return nil, fmt.Errorf("unknown exact message storage %q", storage)
	}
}

type exactMessageWriter interface {
	append([]byte) error
}

func addExactHeader(store exactMessageWriter, name, value string) error {
	value = strings.ReplaceAll(value, "\n", "\r\n")
	return store.append([]byte(name + ": " + value + "\r\n"))
}

type memoryExactMessage struct {
	data     []byte
	maxBytes int64
	closed   bool
}

func (m *memoryExactMessage) append(payload []byte) error {
	if m.closed {
		return ErrExactMessageClosed
	}
	if int64(len(m.data))+int64(len(payload)) > m.maxBytes {
		return ErrExactMessageTooLarge
	}
	m.data = append(m.data, payload...)
	return nil
}

func (m *memoryExactMessage) AddHeader(name, value string) error {
	return addExactHeader(m, name, value)
}

func (m *memoryExactMessage) EndHeaders() error            { return m.append([]byte("\r\n")) }
func (m *memoryExactMessage) AddBody(payload []byte) error { return m.append(payload) }

func (m *memoryExactMessage) ReaderAt() (io.ReaderAt, int64, error) {
	if m.closed {
		return nil, 0, ErrExactMessageClosed
	}
	return exactBytes(m.data), int64(len(m.data)), nil
}

func (m *memoryExactMessage) Close() error {
	m.closed = true
	m.data = nil
	return nil
}

type exactBytes []byte

func (b exactBytes) ReadAt(payload []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative exact-message offset")
	}
	if len(payload) == 0 {
		return 0, nil
	}
	if offset >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(payload, b[offset:])
	if n < len(payload) {
		return n, io.EOF
	}
	return n, nil
}

type fileExactMessage struct {
	file     *os.File
	maxBytes int64
	size     int64
	closed   bool
}

func newFileExactMessage(maxBytes int64, directory string) (ExactMessage, error) {
	file, err := os.CreateTemp(directory, "milterguard-exact-message-*")
	if err != nil {
		return nil, fmt.Errorf("create exact-message temporary file: %w", err)
	}
	// Keep only the open descriptor. This prevents stale message files after a
	// crash and retains mode 0600 from os.CreateTemp.
	if err := os.Remove(file.Name()); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("unlink exact-message temporary file: %w", err)
	}
	return &fileExactMessage{file: file, maxBytes: maxBytes}, nil
}

func (m *fileExactMessage) append(payload []byte) error {
	if m.closed {
		return ErrExactMessageClosed
	}
	if m.size+int64(len(payload)) > m.maxBytes {
		return ErrExactMessageTooLarge
	}
	written, err := m.file.Write(payload)
	m.size += int64(written)
	if err != nil {
		return err
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}

func (m *fileExactMessage) AddHeader(name, value string) error {
	return addExactHeader(m, name, value)
}

func (m *fileExactMessage) EndHeaders() error            { return m.append([]byte("\r\n")) }
func (m *fileExactMessage) AddBody(payload []byte) error { return m.append(payload) }

func (m *fileExactMessage) ReaderAt() (io.ReaderAt, int64, error) {
	if m.closed {
		return nil, 0, ErrExactMessageClosed
	}
	return m.file, m.size, nil
}

func (m *fileExactMessage) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	return m.file.Close()
}
