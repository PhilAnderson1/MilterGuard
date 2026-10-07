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

func TestExactMessageCanonicalizesFoldedHeaderLineEndings(t *testing.T) {
	for _, storage := range []string{"memory", "file"} {
		for _, test := range []struct {
			name  string
			value string
		}{
			{name: "LF", value: "first\n\tsecond"},
			{name: "CRLF", value: "first\r\n\tsecond"},
			{name: "CR", value: "first\r\tsecond"},
		} {
			t.Run(storage+"/"+test.name, func(t *testing.T) {
				message, err := NewExactMessage(storage, 1024)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = message.Close() })
				if err := message.AddHeader("Subject", test.value); err != nil {
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
				if want := "Subject: first\r\n\tsecond\r\n"; string(got) != want {
					t.Fatalf("exact folded header = %q, want %q", got, want)
				}
			})
		}
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

func TestHybridExactMessageFactoryFallsBackAndReusesMemorySlots(t *testing.T) {
	factory := NewExactMessageFactory(2)
	first, err := factory.New("hybrid", 1024)
	if err != nil {
		t.Fatal(err)
	}
	second, err := factory.New("hybrid", 1024)
	if err != nil {
		t.Fatal(err)
	}
	third, err := factory.New("hybrid", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first.(*limitedMemoryExactMessage); !ok {
		t.Fatalf("first hybrid store = %T, want memory", first)
	}
	if _, ok := second.(*limitedMemoryExactMessage); !ok {
		t.Fatalf("second hybrid store = %T, want memory", second)
	}
	if _, ok := third.(*fileExactMessage); !ok {
		t.Fatalf("overflow hybrid store = %T, want file", third)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	reused, err := factory.New("hybrid", 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reused.(*limitedMemoryExactMessage); !ok {
		t.Fatalf("reused hybrid store = %T, want memory", reused)
	}
	for _, message := range []ExactMessage{second, third, reused} {
		if err := message.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExactBytesReaderAtEOF(t *testing.T) {
	reader := exactBytes("abc")
	buffer := make([]byte, 4)
	if n, err := reader.ReadAt(buffer, 1); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt = %d, %v", n, err)
	}
}
