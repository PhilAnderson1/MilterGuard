package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
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

func TestCheckMilterListenerAvailable(t *testing.T) {
	listener := &trackedListener{}
	listen := func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "127.0.0.1:8895" {
			t.Fatalf("listen called with network=%q address=%q", network, address)
		}
		return listener, nil
	}
	got, err := checkMilterListenerAvailable("tcp:127.0.0.1:8895", listen)
	if err != nil {
		t.Fatal(err)
	}
	if got != "Milter port 8895 is available" {
		t.Fatalf("result = %q", got)
	}
	if !listener.closed {
		t.Fatal("test listener was not closed")
	}
}

func TestCheckMilterUnixSocketPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.sock")
	got, err := checkMilterListenerAvailable("unix:"+path, nil)
	if err != nil || got != "Milter Unix socket path is available" {
		t.Fatalf("available path result = %q, error = %v", got, err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkMilterListenerAvailable("unix:"+path, nil); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("existing path error = %v, want EADDRINUSE", err)
	}
}

func TestPortCheckErrorMessage(t *testing.T) {
	got := portCheckErrorMessage("tcp:127.0.0.1:8895", "/etc/milterguard/milterguard.yaml", syscall.EADDRINUSE)
	want := "Milter port 8895 is already in use - check MilterGuard is not already running. If necessary, change milter.socket in /etc/milterguard/milterguard.yaml to an unused port on your machine"
	if got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

type endpointAnalyzerFunc func(context.Context, ai.Input) (ai.Decision, error)

func (f endpointAnalyzerFunc) Analyze(ctx context.Context, input ai.Input) (ai.Decision, error) {
	return f(ctx, input)
}

func TestAnalyzeEndpointTestUsesEmbeddedUnwantedMessage(t *testing.T) {
	analyzer := endpointAnalyzerFunc(func(_ context.Context, input ai.Input) (ai.Decision, error) {
		for _, wanted := range []string{"Bank Security", "urgent-account-security.invalid", "password", "security code"} {
			if !strings.Contains(input.Text, wanted) {
				t.Errorf("embedded test email missing %q", wanted)
			}
		}
		return ai.Decision{Classification: "unwanted", Score: .99}, nil
	})
	decision, err := analyzeEndpointTest(analyzer)
	if err != nil || decision.Classification != "unwanted" {
		t.Fatalf("decision = %+v, error = %v", decision, err)
	}
}

func TestValidateEndpointTestDecision(t *testing.T) {
	if err := validateEndpointTestDecision(ai.Decision{Classification: "unwanted"}); err != nil {
		t.Fatal(err)
	}
	err := validateEndpointTestDecision(ai.Decision{Classification: "legitimate"})
	if err == nil || err.Error() != "Test email incorrectly classified as legitimate" {
		t.Fatalf("error = %v", err)
	}
}

func TestEndpointCheckErrorMessage(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&endpointPromptError{err: errors.New("permission denied")}, "Cannot read detection prompt: permission denied"},
		{&ai.EndpointError{Kind: ai.ErrorCredentials, Err: errors.New("HTTP 401")}, "API key not valid"},
		{&ai.EndpointError{Kind: ai.ErrorPaymentRequired, StatusCode: 402, Err: errors.New("HTTP 402")}, "Insufficient API credit"},
		{&ai.EndpointError{Kind: ai.ErrorResponse, Err: errors.New("bad envelope")}, "Invalid endpoint response: bad envelope"},
		{&ai.EndpointError{Kind: ai.ErrorDecision, Err: errors.New("bad decision")}, "Invalid JSON decision returned: bad decision"},
		{&ai.EndpointError{Kind: ai.ErrorHTTP, StatusCode: 400, Err: errors.New("bad request")}, "Endpoint returned HTTP 400 (check the configured model name and endpoint type)"},
		{&ai.EndpointError{Kind: ai.ErrorHTTP, StatusCode: 404, Err: errors.New("large HTML response")}, "Endpoint returned HTTP 404"},
		{os.ErrDeadlineExceeded, "Endpoint request timed out"},
		{errors.New("connection refused"), "Endpoint connection failed: connection refused"},
	}
	for _, test := range tests {
		if got := endpointCheckErrorMessage(test.err); got != test.want {
			t.Errorf("endpointCheckErrorMessage(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
