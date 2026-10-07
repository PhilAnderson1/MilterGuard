package milter

import (
	"bytes"
	"context"
	"errors"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/sqlitedb"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	storesqlite "github.com/PhilAnderson1/MilterGuard/internal/stores/sqlite"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionPanicIsRecoveredAndConnectionClosed(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	var logOutput bytes.Buffer
	server := &Server{log: slog.New(slog.NewJSONHandler(&logOutput, nil))}
	done := make(chan struct{})
	go func() {
		defer close(done)
		func() {
			defer server.recoverSessionPanic(context.Background(), serverConn)
			panic("test parser panic")
		}()
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if count, err := clientConn.Read(buffer); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after panic = (%d, %v), want (0, EOF) with no response frame", count, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("panic recovery did not return")
	}
	logs := logOutput.String()
	for _, wanted := range []string{"MilterGuard worker recovered from panic", `"worker":"milter session"`, "test parser panic", `"connection_closed":true`, "goroutine"} {
		if !strings.Contains(logs, wanted) {
			t.Errorf("panic recovery log does not contain %q: %s", wanted, logs)
		}
	}
}

func TestMaintenancePanicIsRecovered(t *testing.T) {
	var logOutput bytes.Buffer
	service := &maintenanceService{log: slog.New(slog.NewJSONHandler(&logOutput, nil))}
	completed := false
	service.runMaintenance("test maintenance", func() { panic("test maintenance panic") })
	completed = true
	if !completed {
		t.Fatal("maintenance recovery did not return")
	}
	logs := logOutput.String()
	for _, wanted := range []string{"MilterGuard worker recovered from panic", `"worker":"test maintenance"`, "test maintenance panic", "goroutine"} {
		if !strings.Contains(logs, wanted) {
			t.Errorf("maintenance recovery log does not contain %q: %s", wanted, logs)
		}
	}
}

func TestRejectedMailCleanupRunsImmediatelyAtStartup(t *testing.T) {
	root := t.TempDir()
	expiredDirectory := filepath.Join(root, "2000", "01", "01")
	if err := os.MkdirAll(expiredDirectory, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(expiredDirectory, "1.eml"), []byte("expired message"), 0600); err != nil {
		t.Fatal(err)
	}

	service := &maintenanceService{archive: rejectedmail.New(rejectedmail.Options{
		Directory: root, Retention: 24 * time.Hour, MaxTotalBytes: 1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))}
	ctx, cancel := context.WithCancel(context.Background())
	service.startDailyCleanup(ctx)
	cancel()

	if _, err := os.Lstat(filepath.Join(root, "2000")); !os.IsNotExist(err) {
		t.Fatalf("expired archive tree remains after startup cleanup: %v", err)
	}
}

func TestDailyActivityCleanupRunsWhenArchiveIsDisabled(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	database, err := sqlitedb.Open(context.Background(), filepath.Join(t.TempDir(), "activity.db"), sqlitedb.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	repository := storesqlite.NewActivity(database, storesqlite.ActivityOptions{
		Expiry: 24 * time.Hour, Now: func() time.Time { return now },
	})
	if err := repository.AddActivity(context.Background(), stores.ActivityEvent{
		OccurredAt: now.Add(-25 * time.Hour), EventType: stores.ActivityEventScan, Outcome: stores.ActivityOutcomeAccepted,
	}); err != nil {
		t.Fatal(err)
	}
	service := &maintenanceService{activity: repository, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	service.startDailyCleanup(ctx)
	cancel()
	if count, err := repository.Count(context.Background()); err != nil || count != 0 {
		t.Fatalf("activity count after daily cleanup = %d, err = %v", count, err)
	}
}

func TestServerServiceStatusLifecycle(t *testing.T) {
	server := NewServer(config.Config{
		Mode:        "enforce",
		Milter:      config.MilterConfig{MaxConnections: 1},
		AI:          config.AIConfig{MaxConcurrent: 1},
		Activity:    config.ActivityConfig{Expiry: config.Duration(24 * time.Hour)},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "status.db")},
	}, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer server.Close()
	started := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	server.setServiceStatus(started)
	status, found, err := server.serviceStatus.ServiceStatus(context.Background())
	if err != nil || !found || !status.StartedAt.Equal(started) || status.Mode != stores.ServiceModeEnforce {
		t.Fatalf("service status = %+v, found=%t, err=%v", status, found, err)
	}
	server.clearServiceStatus()
	if _, found, err := server.serviceStatus.ServiceStatus(context.Background()); err != nil || found {
		t.Fatalf("service status remained after clear: found=%t err=%v", found, err)
	}
}

type failingStartupCleanupIPRepository struct {
	stores.PersistentIPReputationRepository
	err   error
	panic bool
}

func (r failingStartupCleanupIPRepository) Cleanup(context.Context) (int64, error) {
	if r.panic {
		panic("startup cleanup panic")
	}
	return 0, r.err
}

func TestServeContinuesAfterStartupCleanupFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		cleanup failingStartupCleanupIPRepository
		logText string
	}{
		{name: "error", cleanup: failingStartupCleanupIPRepository{err: errors.New("database busy")}, logText: "SQLite cleanup failed"},
		{name: "panic", cleanup: failingStartupCleanupIPRepository{panic: true}, logText: "startup cleanup panic"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			server := NewServer(config.Config{
				AI:     config.AIConfig{MaxConcurrent: 1},
				Milter: config.MilterConfig{MaxConnections: 1},
			}, fixedAnalyzer{}, logger)
			server.maintenance.ip = test.cleanup
			listenerError := errors.New("listener reached")
			listener := &scriptedListener{errors: []error{listenerError}}
			if err := server.Serve(context.Background(), listener); !errors.Is(err, listenerError) {
				t.Fatalf("Serve error = %v, want listener error", err)
			}
			if listener.accepts != 1 {
				t.Fatalf("listener accepts = %d, want 1", listener.accepts)
			}
			if !strings.Contains(logs.String(), test.logText) {
				t.Fatalf("startup cleanup failure was not logged: %s", logs.String())
			}
		})
	}
}

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string { return "temporary accept failure" }

func (temporaryAcceptError) Timeout() bool { return false }

func (temporaryAcceptError) Temporary() bool { return true }

type scriptedListener struct {
	errors  []error
	conn    net.Conn
	accepts int
}

func (listener *scriptedListener) Accept() (net.Conn, error) {
	listener.accepts++
	if len(listener.errors) > 0 {
		err := listener.errors[0]
		listener.errors = listener.errors[1:]
		return nil, err
	}
	if listener.conn != nil {
		conn := listener.conn
		listener.conn = nil
		return conn, nil
	}
	return nil, errors.New("permanent accept failure")
}

func (*scriptedListener) Close() error { return nil }

func (*scriptedListener) Addr() net.Addr { return &net.TCPAddr{} }

type tcpAddressConn struct{ net.Conn }

func (tcpAddressConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8895}
}

func (tcpAddressConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 25000}
}

type connectionThenErrorListener struct {
	conn net.Conn
	err  error
}

func (listener *connectionThenErrorListener) Accept() (net.Conn, error) {
	if listener.conn != nil {
		conn := listener.conn
		listener.conn = nil
		return conn, nil
	}
	return nil, listener.err
}

func (*connectionThenErrorListener) Close() error { return nil }

func (*connectionThenErrorListener) Addr() net.Addr { return &net.TCPAddr{} }

func TestAcceptConnectionRetriesTemporaryErrors(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	listener := &scriptedListener{errors: []error{temporaryAcceptError{}, temporaryAcceptError{}}, conn: serverSide}
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	conn, err := server.acceptConnection(context.Background(), listener)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if listener.accepts != 3 {
		t.Fatalf("accept attempts = %d, want 3", listener.accepts)
	}
}

func TestAcceptConnectionReturnsPermanentError(t *testing.T) {
	permanent := errors.New("listener closed unexpectedly")
	listener := &scriptedListener{errors: []error{permanent}}
	server := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if _, err := server.acceptConnection(context.Background(), listener); !errors.Is(err, permanent) {
		t.Fatalf("accept error = %v, want %v", err, permanent)
	}
	if listener.accepts != 1 {
		t.Fatalf("accept attempts = %d, want 1", listener.accepts)
	}
}

func TestServeCancelsIdleSessionsAfterPermanentAcceptError(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	permanent := errors.New("listener failed permanently")
	listener := &connectionThenErrorListener{conn: tcpAddressConn{serverSide}, err: permanent}
	server := NewServer(config.Config{
		Milter: config.MilterConfig{
			Timeout:        config.Duration(time.Hour),
			MaxConnections: 1,
			AllowedPeerIPs: []string{"127.0.0.0/8"},
		},
		AI: config.AIConfig{MaxConcurrent: 1},
	}, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// The scripted listener returns its connection once, followed by a permanent
	// accept failure. The accepted session remains idle until Serve cancels it.
	done := make(chan error, 1)
	go func() { done <- server.Serve(context.Background(), listener) }()
	select {
	case err := <-done:
		if !errors.Is(err, permanent) {
			t.Fatalf("Serve error = %v, want %v", err, permanent)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve remained blocked waiting for an idle session")
	}

	if _, err := clientSide.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("idle session was not closed: %v", err)
	}
}

func TestServerCloseIsConcurrentAndIdempotent(t *testing.T) {
	server := NewServer(config.Config{
		AI: config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{
			DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db"),
		},
		RejectionHistory: config.RejectionHistoryConfig{Expiry: config.Duration(time.Hour), MaxEntries: 10},
	}, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := server.StartupError(); err != nil {
		t.Fatal(err)
	}

	const callers = 8
	errorsSeen := make(chan error, callers)
	var callersDone sync.WaitGroup
	callersDone.Add(callers)
	for range callers {
		go func() {
			defer callersDone.Done()
			errorsSeen <- server.Close()
		}()
	}
	callersDone.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Close returned %v", err)
		}
	}
	if err := server.Close(); err != nil {
		t.Fatalf("repeated Close returned %v", err)
	}
}
