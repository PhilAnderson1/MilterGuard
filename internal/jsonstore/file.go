package jsonstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ErrIncompatibleFormat identifies persistent JSON that was read successfully
// but cannot be decoded or accepted as a valid store document.
var ErrIncompatibleFormat = errors.New("incompatible JSON file format")

// readFile decodes exactly one JSON value from path. Unknown object fields and
// trailing JSON values are rejected, and the file is never read beyond maxSize.
func readFile(path string, maxSize int64, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxSize {
		return fmt.Errorf("JSON file exceeds %d bytes", maxSize)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: %v", ErrIncompatibleFormat, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%w: JSON file contains trailing data", ErrIncompatibleFormat)
		}
		return fmt.Errorf("%w: %v", ErrIncompatibleFormat, err)
	}
	return nil
}

// writeFile atomically replaces path with an indented JSON representation. When
// running as root, ownership is inherited from the existing file or directory
// so command-line maintenance cannot make a daemon-owned store unwritable.
func writeFile(path string, value any, directoryMode, fileMode os.FileMode) error {
	if path == "" {
		return fmt.Errorf("JSON file path is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".milterguard-json-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryName)
	}
	if err := temporary.Chmod(fileMode); err != nil {
		cleanup()
		return err
	}
	if err := preserveOwnership(path, directory, temporary); err != nil {
		cleanup()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		_ = os.Remove(temporaryName)
		return err
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close()
	return directoryFile.Sync()
}

func preserveOwnership(path, directory string, temporary *os.File) error {
	if os.Geteuid() != 0 {
		return nil
	}
	source, err := os.Stat(path)
	if os.IsNotExist(err) {
		source, err = os.Stat(directory)
	}
	if err != nil {
		return err
	}
	stat, ok := source.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return temporary.Chown(int(stat.Uid), int(stat.Gid))
}
