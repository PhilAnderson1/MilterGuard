package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/peterh/liner"
)

func TestPersistentStateStartupErrorMessage(t *testing.T) {
	if got := persistentStateStartupErrorMessage(errors.New("permission denied")); got != "persistent state cannot be read" {
		t.Fatalf("read error message = %q", got)
	}
	sqliteErr := fmt.Errorf("correspondents: %w", sqlitedb.ErrIncompatibleDatabase)
	if got := persistentStateStartupErrorMessage(sqliteErr); got != "incompatible SQLite database format" {
		t.Fatalf("SQLite format error message = %q", got)
	}
}

func TestCommandModeLoggerEmitsWarningsButNotRoutineLogs(t *testing.T) {
	var output strings.Builder
	logger := commandModeLogger(&output)
	logger.Debug("debug detail")
	logger.Info("routine detail")
	logger.Warn("important warning")
	logger.Error("important error")
	text := output.String()
	if strings.Contains(text, "debug detail") || strings.Contains(text, "routine detail") {
		t.Fatalf("command logger emitted routine output: %s", text)
	}
	for _, want := range []string{"important warning", "important error"} {
		if !strings.Contains(text, want) {
			t.Fatalf("command logger omitted %q: %s", want, text)
		}
	}
}

func TestReportCommandModeCompletionPreservesExecutionAndShutdownErrors(t *testing.T) {
	var output strings.Builder
	if code := reportCommandModeCompletion(&output, errors.New("execution failed"), errors.New("close failed")); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, want := range []string{"command mode failed: execution failed", "command database shutdown failed: close failed"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("completion output missing %q: %s", want, output.String())
		}
	}
	output.Reset()
	if code := reportCommandModeCompletion(&output, nil, nil); code != 0 || output.Len() != 0 {
		t.Fatalf("successful completion code=%d output=%q", code, output.String())
	}
}

type scriptedCommandProcessor struct {
	lines  []string
	actors []admincmd.Actor
}

func (p *scriptedCommandProcessor) ExecuteLine(_ context.Context, line string, actor admincmd.Actor) (admincmd.Response, error) {
	p.lines = append(p.lines, line)
	p.actors = append(p.actors, actor)
	if line == "BAD" {
		return admincmd.Response{}, errors.New("bad command")
	}
	response := admincmd.Response{Text: "result for " + line + "\n"}
	if line == "HELP" {
		response.Attachments = []admincmd.Attachment{{Filename: "rejection-1.eml", Contents: []byte("mail"), SourcePath: "/archive/2026/09/17/1.eml"}}
	}
	return response, nil
}

func TestRunCommandMode(t *testing.T) {
	processor := &scriptedCommandProcessor{}
	var output strings.Builder
	err := runCommandMode(context.Background(), strings.NewReader("HELP\nBAD\nEXIT\nIGNORED\n"), &output, processor)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(processor.lines, ","), "HELP,BAD"; got != want {
		t.Fatalf("executed lines = %q, want %q", got, want)
	}
	for _, actor := range processor.actors {
		if !actor.Administrator || actor.DefaultRecipient != "*" || !actor.NewestLast {
			t.Fatalf("command actor = %#v", actor)
		}
	}
	if text := output.String(); !strings.Contains(text, "result for HELP") || !strings.Contains(text, "Error: bad command") ||
		!strings.Contains(text, "result for HELP\n\nSaved message: /archive/2026/09/17/1.eml (4 bytes)") {
		t.Fatalf("command output = %q", text)
	}
}

func TestRunCommandModeRedirectedInputSuppressesPrompts(t *testing.T) {
	processor := &scriptedCommandProcessor{}
	var output strings.Builder
	err := runCommandMode(context.Background(), strings.NewReader("HELP\n"), &output, processor)
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, "MilterGuard command mode") || strings.Contains(text, "milterguard>") {
		t.Fatalf("redirected command output contains interactive text: %q", text)
	}
	if !strings.Contains(text, "result for HELP") {
		t.Fatalf("redirected command output = %q", text)
	}
}

type scriptedLineEditor struct {
	lines   []string
	errors  []error
	index   int
	prompts []string
	history []string
}

func (editor *scriptedLineEditor) Prompt(prompt string) (string, error) {
	editor.prompts = append(editor.prompts, prompt)
	if editor.index >= len(editor.lines) {
		return "", io.EOF
	}
	index := editor.index
	editor.index++
	return editor.lines[index], editor.errors[index]
}

func (editor *scriptedLineEditor) AppendHistory(line string) {
	editor.history = append(editor.history, line)
}

func TestTerminalCommandModeKeepsSessionHistory(t *testing.T) {
	processor := &scriptedCommandProcessor{}
	editor := &scriptedLineEditor{
		lines:  []string{"HELP", "", "ignored", "BAD", "EXIT"},
		errors: []error{nil, nil, liner.ErrPromptAborted, nil, nil},
	}
	var output strings.Builder
	if err := runTerminalCommandMode(context.Background(), &output, processor, editor); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(processor.lines, ","); got != "HELP,BAD" {
		t.Fatalf("executed commands = %q, want HELP,BAD", got)
	}
	if got := strings.Join(editor.history, ","); got != "HELP,BAD,EXIT" {
		t.Fatalf("session history = %q, want HELP,BAD,EXIT", got)
	}
	for _, prompt := range editor.prompts {
		if prompt != "milterguard> " {
			t.Fatalf("terminal prompt = %q", prompt)
		}
	}
	if !strings.Contains(output.String(), "Error: bad command") {
		t.Fatalf("terminal output = %q", output.String())
	}
}

type trackedListener struct{ closed bool }

func (*trackedListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (listener *trackedListener) Close() error     { listener.closed = true; return nil }
func (*trackedListener) Addr() net.Addr            { return &net.TCPAddr{} }

func shortUnixSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "mg-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "m.sock")
}

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

func TestListenRefusesToReplaceOrdinaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.sock")
	const original = "must not be removed"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	listener, cleanup, err := listen("unix:" + path)
	if err == nil || !strings.Contains(err.Error(), "refusing to replace non-socket path") {
		t.Fatalf("listen error = %v, want refusal to replace ordinary file", err)
	}
	if listener != nil {
		t.Fatal("listener returned after refusing ordinary file")
	}
	cleanup()
	content, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ordinary file was removed: %v", readErr)
	}
	if string(content) != original {
		t.Fatalf("ordinary file content = %q, want %q", content, original)
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
	path := shortUnixSocketPath(t)
	got, err := checkMilterListenerAvailable("unix:"+path, nil)
	if err != nil || got != "Milter Unix socket path is available" {
		t.Fatalf("available path result = %q, error = %v", got, err)
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = checkMilterListenerAvailable("unix:"+path, nil)
	if err != nil || got != "Milter Unix socket path is available" {
		t.Fatalf("stale socket result = %q, error = %v", got, err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("preflight altered stale socket: %v", err)
	}

	bound, cleanup, err := listen("unix:" + path)
	if err != nil {
		t.Fatalf("startup did not replace stale socket: %v", err)
	}
	cleanup()
	if bound == nil {
		t.Fatal("startup returned no listener after replacing stale socket")
	}
}

func TestUnixSocketChecksRejectActiveListener(t *testing.T) {
	path := shortUnixSocketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if _, err := checkMilterListenerAvailable("unix:"+path, nil); !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("active preflight error = %v, want EADDRINUSE", err)
	}
	if replacement, cleanup, err := listen("unix:" + path); !errors.Is(err, syscall.EADDRINUSE) {
		cleanup()
		if replacement != nil {
			_ = replacement.Close()
		}
		t.Fatalf("active startup error = %v, want EADDRINUSE", err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("active listener path was disturbed: %v", err)
	}
	_ = conn.Close()
}

func TestCheckMilterUnixSocketRefusesOrdinaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "milterguard.sock")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := checkMilterListenerAvailable("unix:"+path, nil); err == nil || !strings.Contains(err.Error(), "refusing to replace non-socket path") {
		t.Fatalf("ordinary path error = %v, want non-socket refusal", err)
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
