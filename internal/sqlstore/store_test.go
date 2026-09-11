package sqlstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesAndReopensSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.db")
	store, err := Open(context.Background(), path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("database mode = %o, want 640", info.Mode().Perm())
	}
	var version int
	if err := store.QueryRow(context.Background(), "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != CurrentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, CurrentSchemaVersion)
	}
	if _, err := store.Exec(context.Background(), `INSERT INTO rejections
		(sender, rejected_at_ms) VALUES (?, ?)`, "sender@example.com", 1); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(context.Background(), path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err := store.QueryRow(context.Background(), "SELECT count(*) FROM rejections").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rejection count = %d, want 1", count)
	}
}

func TestOpenDisablesAutomaticWALCheckpointing(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "checkpoint.db"), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var pages int
	if err := store.QueryRow(context.Background(), "PRAGMA wal_autocheckpoint").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != 0 {
		t.Fatalf("wal_autocheckpoint = %d, want 0", pages)
	}
}

func TestPassiveWALCheckpoint(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "checkpoint.db"), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Exec(context.Background(), `INSERT INTO rejections
		(sender, rejected_at_ms) VALUES (?, ?)`, "sender@example.com", 1); err != nil {
		t.Fatal(err)
	}
	result, err := store.CheckpointPassive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Busy != 0 || result.LogFrames < 1 || result.CheckpointedFrames < 1 {
		t.Fatalf("checkpoint result = %+v", result)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.db")
	store, err := Open(context.Background(), path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(context.Background(), "PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), path, DefaultOptions())
	if !errors.Is(err, ErrIncompatibleDatabase) {
		t.Fatalf("Open() error = %v, want ErrIncompatibleDatabase", err)
	}
}

func TestOpenRejectsUnversionedNonemptyDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unversioned.db")
	store, err := Open(context.Background(), path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(context.Background(), "PRAGMA user_version = 0"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = Open(context.Background(), path, DefaultOptions())
	if !errors.Is(err, ErrIncompatibleDatabase) {
		t.Fatalf("Open() error = %v, want ErrIncompatibleDatabase", err)
	}
}

func TestForeignKeysCascade(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "cascade.db"), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	result, err := store.Exec(context.Background(), `INSERT INTO rejections
		(sender, rejected_at_ms) VALUES (?, ?)`, "sender@example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(context.Background(), `INSERT INTO rejection_recipients
		(rejection_id, recipient) VALUES (?, ?)`, id, "local@example.net"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Exec(context.Background(), "DELETE FROM rejections WHERE id = ?", id); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.QueryRow(context.Background(), "SELECT count(*) FROM rejection_recipients").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("recipient count = %d, want 0", count)
	}
}

func TestNewDatabasePassesSQLiteIntegrityChecks(t *testing.T) {
	store, err := Open(context.Background(), filepath.Join(t.TempDir(), "integrity.db"), DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var integrity string
	if err := store.QueryRow(context.Background(), "PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q", integrity)
	}
	rows, err := store.Query(context.Background(), "PRAGMA foreign_key_check")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("foreign_key_check reported a violation")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}
