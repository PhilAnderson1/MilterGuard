package rejectedmail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveUsesDateDirectoriesWithoutSynchronousCapacityWork(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 34, 56, 123, time.UTC)
	archive := New(Options{Directory: root, Retention: 30 * 24 * time.Hour, MaxTotalBytes: 5}, nil)
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
	var count int
	if err := filepath.WalkDir(root, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() && filepath.Ext(entry.Name()) == ".eml" {
			count++
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("saved message count = %d, want 3 before cleanup", count)
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
	archive := New(Options{Directory: root, Retention: 30 * 24 * time.Hour, MaxTotalBytes: 1 << 20}, nil)
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

func TestCleanupEnforcesTotalByteLimit(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	archive := New(Options{Directory: root, Retention: 24 * time.Hour, MaxTotalBytes: 5}, nil)
	archive.now = func() time.Time { return now }
	if _, err := archive.Save([]byte("123")); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := archive.Save([]byte("456")); err != nil {
		t.Fatal(err)
	}
	if err := archive.Cleanup(); err != nil {
		t.Fatal(err)
	}
	total, err := archive.archiveSize()
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("archive size after cleanup = %d, want 3", total)
	}
}

func TestSaveWithRecordIDUsesRecordIDAndDoesNotOverwrite(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	archive := New(Options{Directory: root, Retention: 24 * time.Hour, MaxTotalBytes: 100}, nil)
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

func TestCapacityCleanupUsesModificationTime(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "2026", "09", "07")
	if err := os.MkdirAll(directory, 0750); err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(directory, "2.eml")
	newPath := filepath.Join(directory, "10.eml")
	for _, path := range []string{oldPath, newPath} {
		if err := os.WriteFile(path, []byte(path), 0640); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatal(err)
	}

	archive := New(Options{Directory: root, Retention: 30 * 24 * time.Hour, MaxTotalBytes: int64(len(newPath) + len("newest"))}, nil)
	archive.now = func() time.Time { return newTime.Add(time.Hour) }
	if _, err := archive.SaveWithRecordID([]byte("newest"), 11); err != nil {
		t.Fatal(err)
	}
	if err := archive.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("oldest file was not evicted: %v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("newer file was incorrectly evicted: %v", err)
	}
}
