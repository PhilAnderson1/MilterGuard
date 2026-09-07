package rejectedmail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveUsesDateDirectoriesAndEnforcesCapacity(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 34, 56, 123, time.UTC)
	archive := New(Options{Directory: root, Retention: 30 * 24 * time.Hour, MaxMessages: 2, MaxTotalBytes: 100}, nil)
	archive.now = func() time.Time { return now }
	for _, body := range []string{"one", "two", "three"} {
		path, err := archive.Save([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(path) != filepath.Join(root, "2026", "09", "07") || !strings.HasSuffix(path, ".eml") {
			t.Fatalf("unexpected archive path %q", path)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0640 {
			t.Fatalf("message mode = %o", info.Mode().Perm())
		}
		now = now.Add(time.Nanosecond)
	}
	if len(archive.files) != 2 || archive.bytes != int64(len("two")+len("three")) {
		t.Fatalf("capacity state = %d files, %d bytes", len(archive.files), archive.bytes)
	}
}

func TestCleanupRemovesExpiredTreesHierarchically(t *testing.T) {
	root := t.TempDir()
	for _, relative := range []string{
		"2025/12/31/old.eml",
		"2026/07/31/old.eml",
		"2026/08/07/old.eml",
		"2026/08/08/keep.eml",
		"2026/09/07/keep.eml",
		"notes/do-not-delete.txt",
	} {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(relative), 0640); err != nil {
			t.Fatal(err)
		}
	}
	archive := New(Options{Directory: root, Retention: 30 * 24 * time.Hour, MaxMessages: 100, MaxTotalBytes: 1 << 20}, nil)
	archive.now = func() time.Time { return time.Date(2026, 9, 7, 18, 0, 0, 0, time.UTC) }
	if err := archive.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"2025", "2026/07", "2026/08/07"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("expired path %s was not removed: %v", relative, err)
		}
	}
	for _, relative := range []string{"2026/08/08/keep.eml", "2026/09/07/keep.eml", "notes/do-not-delete.txt"} {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("retained path %s: %v", relative, err)
		}
	}
}

func TestSaveEnforcesTotalByteLimit(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	archive := New(Options{Directory: root, Retention: 24 * time.Hour, MaxMessages: 10, MaxTotalBytes: 5}, nil)
	archive.now = func() time.Time { return now }
	if _, err := archive.Save([]byte("123")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := archive.Save([]byte("456")); err != nil {
		t.Fatal(err)
	}
	if len(archive.files) != 1 || archive.bytes != 3 {
		t.Fatalf("byte capacity state = %d files, %d bytes", len(archive.files), archive.bytes)
	}
}

func TestSaveWithRecordIDUsesRecordIDAndDoesNotOverwrite(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	archive := New(Options{Directory: root, Retention: 24 * time.Hour, MaxMessages: 10, MaxTotalBytes: 100}, nil)
	archive.now = func() time.Time { return now }

	path, err := archive.SaveWithRecordID([]byte("first"), 123)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "2026", "09", "07", "123.eml"); path != want {
		t.Fatalf("path = %q, want %q", path, want)
	}
	if _, err := archive.SaveWithRecordID([]byte("replacement"), 123); err == nil {
		t.Fatal("expected duplicate record ID to be refused")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "first" {
		t.Fatalf("saved contents = %q", contents)
	}
}
