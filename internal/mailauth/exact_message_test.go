package mailauth

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestExactMessageImplementationsPreserveCallbackRepresentation(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			message, err := NewExactMessage(storage, 1024)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = message.Close() })
			if err := message.AddHeader("Subject", "first\n\tsecond"); err != nil {
				t.Fatal(err)
			}
			if err := message.AddHeader("X-Repeat", " one "); err != nil {
				t.Fatal(err)
			}
			if err := message.EndHeaders(); err != nil {
				t.Fatal(err)
			}
			body := []byte{'a', 0, 'b', '\r', '\n'}
			if err := message.AddBody(body); err != nil {
				t.Fatal(err)
			}
			reader, size, err := message.ReaderAt()
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, size)
			if _, err := reader.ReadAt(got, 0); err != nil {
				t.Fatal(err)
			}
			want := append([]byte("Subject: first\r\n\tsecond\r\nX-Repeat:  one \r\n\r\n"), body...)
			if string(got) != string(want) {
				t.Fatalf("exact message = %q, want %q", got, want)
			}
		})
	}
}

func TestExactMessageSizeAndCloseAreEnforced(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		t.Run(storage, func(t *testing.T) {
			message, err := NewExactMessage(storage, 4)
			if err != nil {
				t.Fatal(err)
			}
			if err := message.AddBody([]byte("1234")); err != nil {
				t.Fatal(err)
			}
			if err := message.AddBody([]byte("5")); !errors.Is(err, ErrExactMessageTooLarge) {
				t.Fatalf("oversize error = %v", err)
			}
			if err := message.Close(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := message.ReaderAt(); !errors.Is(err, ErrExactMessageClosed) {
				t.Fatalf("read after close error = %v", err)
			}
			if err := message.Close(); err != nil {
				t.Fatalf("second close: %v", err)
			}
		})
	}
}

func TestFileExactMessageIsUnlinkedImmediately(t *testing.T) {
	directory := t.TempDir()
	message, err := newFileExactMessage(1024, directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = message.Close() })
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary exact message remains visible: %v", entries)
	}
	if matches, err := filepath.Glob(filepath.Join(directory, "milterguard-exact-message-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary exact-message paths = %v, error %v", matches, err)
	}
	if err := message.AddBody([]byte("still writable")); err != nil {
		t.Fatal(err)
	}
}

func TestExactBytesReaderAtEOF(t *testing.T) {
	reader := exactBytes("abc")
	buffer := make([]byte, 4)
	if n, err := reader.ReadAt(buffer, 1); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}
