package main

import (
	"bytes"
	"io"
	"os"
	"testing"
)

var benchmarkByte byte

func BenchmarkReaderAt(b *testing.B) {
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB.
	b.Run("memory", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			r := bytes.NewReader(payload)
			var one [1]byte
			_, _ = r.ReadAt(one[:], int64(len(payload)-1))
			benchmarkByte = one[0]
		}
	})
	b.Run("file", func(b *testing.B) {
		f, err := os.CreateTemp(b.TempDir(), "exact-message-")
		if err != nil {
			b.Fatal(err)
		}
		defer f.Close()
		if _, err := f.Write(payload); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			var one [1]byte
			_, _ = f.ReadAt(one[:], int64(len(payload)-1))
			benchmarkByte = one[0]
		}
	})
	b.Run("file-copy", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			f, err := os.CreateTemp(b.TempDir(), "exact-message-")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(f, bytes.NewReader(payload)); err != nil {
				b.Fatal(err)
			}
			_ = f.Close()
		}
	})
}
