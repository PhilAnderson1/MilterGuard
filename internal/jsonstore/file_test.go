package jsonstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type testDocument struct {
	Value string `json:"value"`
}

func TestWriteAndStrictRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeFile(path, testDocument{Value: "saved"}, 0750, 0640); err != nil {
		t.Fatal(err)
	}
	var document testDocument
	if err := readFile(path, 1024, &document); err != nil {
		t.Fatal(err)
	}
	if document.Value != "saved" {
		t.Fatalf("value = %q", document.Value)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestReadRejectsUnknownTrailingAndOversizedData(t *testing.T) {
	tests := []struct {
		name string
		data string
		max  int64
	}{
		{name: "unknown field", data: `{"value":"ok","extra":true}`, max: 1024},
		{name: "trailing value", data: `{"value":"ok"} {}`, max: 1024},
		{name: "oversized", data: `{"value":"too large"}`, max: 4},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(test.data), 0600); err != nil {
				t.Fatal(err)
			}
			var document testDocument
			if err := readFile(path, test.max, &document); err == nil {
				t.Fatal("invalid JSON file was accepted")
			} else if test.name != "oversized" && !errors.Is(err, ErrIncompatibleFormat) {
				t.Fatalf("invalid JSON error = %v, want incompatible format", err)
			} else if test.name == "oversized" && errors.Is(err, ErrIncompatibleFormat) {
				t.Fatalf("oversized-file error was misclassified as incompatible format: %v", err)
			}
		})
	}
}

func TestFailedWritePreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeFile(path, testDocument{Value: "original"}, 0750, 0640); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(path, make(chan int), 0750, 0640); err == nil {
		t.Fatal("unsupported JSON value was written")
	}
	var document testDocument
	if err := readFile(path, 1024, &document); err != nil {
		t.Fatal(err)
	}
	if document.Value != "original" {
		t.Fatalf("failed replacement changed existing value to %q", document.Value)
	}
}
