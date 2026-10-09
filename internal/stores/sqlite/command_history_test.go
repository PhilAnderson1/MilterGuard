package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
)

func TestCommandHistoryPersistsOnlyTenNewestCommands(t *testing.T) {
	database, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	repository := NewCommandHistory(database)
	commands := make([]string, 12)
	for index := range commands {
		commands[index] = fmt.Sprintf("command-%02d", index)
	}
	if err := repository.SaveCommandHistory(context.Background(), commands); err != nil {
		t.Fatal(err)
	}
	got, err := repository.LoadCommandHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := commands[2:]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded history = %#v, want %#v", got, want)
	}

	if err := repository.SaveCommandHistory(context.Background(), []string{"ACTIVITY", "IP LIST"}); err != nil {
		t.Fatal(err)
	}
	got, err = repository.LoadCommandHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want = []string{"ACTIVITY", "IP LIST"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("replaced history = %#v, want %#v", got, want)
	}
}

func TestCommandHistoryReplacementRollsBackOnInvalidEntry(t *testing.T) {
	database, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "milterguard.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	repository := NewCommandHistory(database)
	if err := repository.SaveCommandHistory(context.Background(), []string{"HELP"}); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveCommandHistory(context.Background(), []string{"ACTIVITY", ""}); err == nil {
		t.Fatal("SaveCommandHistory accepted an empty command")
	}
	got, err := repository.LoadCommandHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"HELP"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history after failed replacement = %#v, want %#v", got, want)
	}
}
