package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/sqlstore"
)

func TestPersistentStateStartupErrorMessage(t *testing.T) {
	if got := persistentStateStartupErrorMessage(errors.New("permission denied")); got != "persistent state cannot be read" {
		t.Fatalf("read error message = %q", got)
	}
	sqliteErr := fmt.Errorf("correspondents: %w", sqlstore.ErrIncompatibleDatabase)
	if got := persistentStateStartupErrorMessage(sqliteErr); got != "incompatible SQLite database format" {
		t.Fatalf("SQLite format error message = %q", got)
	}
}

type trackedListener struct{ closed bool }

func (*trackedListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (listener *trackedListener) Close() error     { listener.closed = true; return nil }
func (*trackedListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestUnixSocketPermissionsAreRestricted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.sock")
	if err := os.WriteFile(path, nil, 0777); err != nil {
		t.Fatal(err)
	}
	listener := &trackedListener{}
	if err := setUnixSocketPermissions(listener, path, os.Chmod); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0660 {
		t.Fatalf("Unix socket permissions = %#o, want 0660", got)
	}
}

func TestUnixSocketPermissionFailureClosesAndRemovesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.sock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	listener := &trackedListener{}
	permissionErr := errors.New("chmod failed")
	err := setUnixSocketPermissions(listener, path, func(string, os.FileMode) error { return permissionErr })
	if !errors.Is(err, permissionErr) {
		t.Fatalf("permission error = %v", err)
	}
	if !listener.closed {
		t.Fatal("listener was not closed after permission failure")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after permission failure: %v", err)
	}
}

func TestMilterListenerActive(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:8895" || timeout != 250*time.Millisecond {
			t.Fatalf("dial called with network=%q address=%q timeout=%s", network, address, timeout)
		}
		return client, nil
	}
	if !milterListenerActiveUsing("tcp:127.0.0.1:8895", dial) {
		t.Fatal("active listener was not detected")
	}
	unavailable := func(string, string, time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	if milterListenerActiveUsing("tcp:127.0.0.1:8895", unavailable) {
		t.Fatal("closed listener was reported active")
	}
}
