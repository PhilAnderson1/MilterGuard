package milter

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/admincmd"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type fixedAnalyzer struct {
	decision ai.Decision
}

type countingAnalyzer struct {
	decision ai.Decision
	calls    atomic.Int32
}

type authenticationObservation struct {
	transaction mailauth.Transaction
	message     []byte
}

type recordingVerifier struct {
	observations chan authenticationObservation
	evidence     mailauth.Evidence
}

func (v *recordingVerifier) Verify(_ context.Context, transaction mailauth.Transaction) (mailauth.Evidence, error) {
	messageBytes := make([]byte, transaction.MessageSize)
	if transaction.Message != nil && transaction.MessageSize > 0 {
		if _, err := transaction.Message.ReadAt(messageBytes, 0); err != nil {
			return mailauth.Evidence{}, err
		}
	}
	v.observations <- authenticationObservation{transaction: transaction, message: messageBytes}
	return v.evidence, nil
}

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
	cancel()
	service.startRejectedMailCleanup(ctx)

	if _, err := os.Lstat(filepath.Join(root, "2000")); !os.IsNotExist(err) {
		t.Fatalf("expired archive tree remains after startup cleanup: %v", err)
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

type recordingAnalyzer struct {
	inputs chan ai.Input
}

type failingAnalyzer struct{}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random source failed") }

type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "temporary accept failure" }
func (temporaryAcceptError) Timeout() bool   { return false }
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

func (*scriptedListener) Close() error   { return nil }
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

func (*connectionThenErrorListener) Close() error   { return nil }
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

func TestGenerateInternalToken(t *testing.T) {
	token, err := generateInternalToken(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d", len(token))
	}
	if _, err := generateInternalToken(failingReader{}); !errors.Is(err, ErrInternalTokenGeneration) {
		t.Fatalf("random-source error = %v", err)
	}
}

func TestInternalCommandReplyHeaderIsRemoved(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.commands.cfg.Enabled = true
	server.sessions.commands.cfg.SendReplies = true
	server.sessions.commands.internalToken = "test-token"
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithExpectedActions(t, conn, actionChangeHeaders, actionChangeHeaders)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "milterguard@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(internalMessageHeader, "test-token"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(internalMessageHeader)))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestInternalCommandReplyTempfailsWithoutHeaderRemoval(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.commands.cfg.Enabled = true
	server.sessions.commands.cfg.SendReplies = true
	server.sessions.commands.internalToken = "test-token"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "milterguard@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(internalMessageHeader, "test-token"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseTempfail}))
}

func TestMilterPeerAuthorizationUsesSocketPeerAddress(t *testing.T) {
	server := &Server{allowedPeerIPs: peerPrefixes([]string{"127.0.0.1", "192.0.2.0/24", "2001:db8::1"})}
	tests := []struct {
		name    string
		address net.Addr
		allowed bool
	}{
		{name: "loopback", address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, allowed: true},
		{name: "allowed prefix", address: &net.TCPAddr{IP: net.ParseIP("192.0.2.45"), Port: 1234}, allowed: true},
		{name: "allowed IPv6", address: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, allowed: true},
		{name: "unauthorized", address: &net.TCPAddr{IP: net.ParseIP("198.51.100.4"), Port: 1234}, allowed: false},
		{name: "missing", address: nil, allowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := server.peerAllowed(test.address); got != test.allowed {
				t.Fatalf("peerAllowed(%v) = %v, want %v", test.address, got, test.allowed)
			}
		})
	}
}

type shortWriter struct {
	max int
	b   strings.Builder
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.b.Write(p)
}

func (a fixedAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	return a.decision, nil
}

func (a *countingAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	a.calls.Add(1)
	return a.decision, nil
}

func (a *recordingAnalyzer) Analyze(_ context.Context, input ai.Input) (ai.Decision, error) {
	a.inputs <- input
	return ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}, nil
}

func (failingAnalyzer) Analyze(context.Context, ai.Input) (ai.Decision, error) {
	return ai.Decision{}, errors.New("endpoint unavailable")
}

func TestAuthenticationProviderReceivesExactTransactionAndFeedsPrompt(t *testing.T) {
	verifier := &recordingVerifier{
		observations: make(chan authenticationObservation, 1),
		evidence: mailauth.NewEvidence([]mailauth.Result{{
			Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "mail.example.com",
		}}, "example.com"),
	}
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, done := testServer(t, analyzer)
	server.sessions.authenticationMode = config.AuthenticationModeInternal
	server.sessions.authentication = verifier
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	if err := writeFrame(conn, macroFrame(commandConnect, "j", "mx.example.net", "{daemon_addr}", "192.0.2.25")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "198.51.100.9"),
		append([]byte{commandHelo}, []byte("helo.example.net\x00")...),
		envelopeFrame(commandMail, "bounce@example.net", "SIZE=123", "SMTPUTF8"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "Sender <sender@example.com>"),
		headerFrame("Subject", "first\n\tsecond ü"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte{'b', 'o', 'd', 'y', 0, '\r', '\n'}...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}

	observation := <-verifier.observations
	transaction := observation.transaction
	if transaction.RemoteIP.String() != "198.51.100.9" || transaction.ReceiverIP.String() != "192.0.2.25" ||
		transaction.ReceiverHostname != "mx.example.net" || transaction.HELO != "helo.example.net" ||
		transaction.EnvelopeSender != "bounce@example.net" || transaction.VisibleFromDomain != "example.com" || !transaction.SMTPUTF8 {
		t.Fatalf("authentication transaction = %#v", transaction)
	}
	wantMessage := "From: Sender <sender@example.com>\r\nSubject: first\r\n\tsecond ü\r\n\r\nbody\x00\r\n"
	if string(observation.message) != wantMessage {
		t.Fatalf("exact authentication message = %q, want %q", observation.message, wantMessage)
	}
	input := <-analyzer.inputs
	if !strings.Contains(input.Text, "DKIM: pass for signing domain mail.example.com (aligned with visible From domain: yes)") {
		t.Fatalf("provider evidence missing from prompt:\n%s", input.Text)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestPostDecisionUpdatesDoNotInheritExpiredAnalysisContext(t *testing.T) {
	store, _ := newTestRejectionHistoryStore(t, config.RejectionHistoryConfig{
		Expiry: config.Duration(24 * time.Hour), MaxEntries: 10,
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	policy := &messagePolicyService{log: log, rejectionHistory: store}
	msg := message.New(1024)
	msg.AddHeader("Subject", "context test")
	ss := &session{
		deps:               &sessionDependencies{mode: "enforce", policy: policy, log: log},
		message:            msg,
		visibleSender:      "sender@example.net",
		envelopeSender:     "bounce@example.net",
		envelopeRecipients: []string{"recipient@example.com"},
		authentication:     authenticationState{Authenticated: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ss.applyPostDecisionUpdates(ctx, evaluationResult{
		selected: actionReject,
		reasons:  []string{"test rejection"},
	}, inboundEvidence{})

	entries, err := store.list(context.Background(), "recipient@example.com", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Subject != "context test" {
		t.Fatalf("rejection history after expired analysis context = %#v", entries)
	}
}

func testServer(t *testing.T, analyzer Analyzer) (*Server, net.Conn, <-chan struct{}) {
	t.Helper()
	cfg := config.Config{
		Mode:      "enforce",
		Milter:    config.MilterConfig{Timeout: config.Duration(200 * time.Millisecond), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: 0.9, LegitimateLowConfidenceScore: 0.8, AIErrorAction: "accept", RejectMessage: "blocked"},
	}
	return testServerWithConfig(t, cfg, analyzer)
}

func testServerWithConfig(t *testing.T, cfg config.Config, analyzer Analyzer) (*Server, net.Conn, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	s := NewServer(cfg, analyzer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		s.handle(context.Background(), serverConn)
	}()
	return s, clientConn, done
}

func setTestMode(server *Server, mode string) {
	server.sessions.mode = mode
}

func setTestFiltering(server *Server, update func(*config.FilteringConfig)) {
	update(&server.sessions.filtering)
}

func setTestCorrespondents(server *Server, cfg config.CorrespondentsConfig, repository stores.CorrespondentRepository) {
	server.sessions.policy.correspondentCfg = cfg
	server.sessions.policy.correspondents = repository
	server.maintenance.correspondents = repository
}

func setTestIPReputation(server *Server, store *ipReputationStore) {
	server.sessions.policy.ipReputation = store
}

func setTestResolver(server *Server, resolver dnsResolver) {
	server.sessions.dns.resolver = resolver
}

func enableTestRejectedMail(t *testing.T, server *Server) string {
	t.Helper()
	root := t.TempDir()
	archive := rejectedmail.New(rejectedmail.Options{
		Directory: root, Retention: 24 * time.Hour, MaxTotalBytes: 1 << 20,
	}, server.log)
	server.sessions.policy.archive = archive
	server.sessions.attachments.policy.archive = archive
	server.maintenance.archive = archive
	return root
}

func TestServerUsesUnifiedRejectionHistoryArchiveSettings(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rejected-mail")
	cfg := config.Config{
		Milter:      config.MilterConfig{MaxConnections: 1},
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10, SaveMessages: true,
			MessageDirectory: root, MessageMaxTotalBytes: 1 << 20,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = server.Close() })
	if server.sessions.policy.archive == nil {
		t.Fatal("unified rejection-history settings did not enable the message archive")
	}
	now := time.Now().UTC()
	if _, err := server.sessions.policy.archive.SaveWithRecordIDAt([]byte("test"), 7, now); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, now.Format("2006"), now.Format("01"), now.Format("02"), "7.eml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive does not use configured message directory: %v", err)
	}
}

func TestRejectionCommandRetrievesProcessedArchivedMessage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rejected-mail")
	cfg := config.Config{
		Milter:      config.MilterConfig{MaxConnections: 1, MaxMessageSize: 1 << 20},
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10, SaveMessages: true,
			MessageDirectory: root, MessageMaxTotalBytes: 1 << 20,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = server.Close() })
	msg := message.New(cfg.Milter.MaxMessageSize)
	msg.AddHeader("From", "Sender <sender@example.net>")
	msg.AddHeader("Subject", "Archived subject")
	msg.AddHeader("Content-Type", "text/html; charset=UTF-8")
	msg.AddBody([]byte(`<p>Review <a href="https://example.net/account">account</a></p>`))
	server.sessions.policy.recordRejection(context.Background(), msg, "sender@example.net", "", []string{"owner@example.com"}, []string{"test reason"}, "ai")
	entries := rejectionEntries(t, server.sessions.policy.rejectionHistory, "owner@example.com")
	if len(entries) != 1 {
		t.Fatalf("rejection history = %#v", entries)
	}
	command := fmt.Sprintf("REJECTION %d", entries[0].ID)
	body, err := server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "owner@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	result := body
	for _, want := range []string{"Archived subject", "test reason", `[account](https://example.net/account)`} {
		if !strings.Contains(result.Text, want) {
			t.Errorf("retrieved message missing %q: %s", want, result.Text)
		}
	}
	if len(result.Attachments) != 1 || result.Attachments[0].Filename != fmt.Sprintf("rejection-%d.eml", entries[0].ID) ||
		result.Attachments[0].MediaType != "application/octet-stream" || !bytes.Contains(result.Attachments[0].Contents, []byte("Review")) {
		t.Fatalf("retrieved attachment = %#v", result.Attachments)
	}
	archivePath := filepath.Join(root, entries[0].RejectedAt.UTC().Format("2006"), entries[0].RejectedAt.UTC().Format("01"), entries[0].RejectedAt.UTC().Format("02"), fmt.Sprintf("%d.eml", entries[0].ID))
	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	body, err = server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "owner@example.com"})
	missing := body
	if err != nil || !strings.Contains(missing.Text, "Saved message is not available") || len(missing.Attachments) != 0 {
		t.Fatalf("missing archive result = %#v, %v", missing, err)
	}
	body, err = server.sessions.commands.processor.ExecuteLine(context.Background(), command,
		admincmd.Actor{DefaultRecipient: "other@example.com"})
	unauthorized := body
	if err != nil || unauthorized.Text != "Rejection record not found.\n" || len(unauthorized.Attachments) != 0 {
		t.Fatalf("unauthorized result = %#v, %v", unauthorized, err)
	}
}

func archivedMessages(t *testing.T, root string) []string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		matches, err := filepath.Glob(filepath.Join(root, "*", "*", "*", "*.eml"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) > 0 || time.Now().After(deadline) {
			return matches
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAIRejectedMessageIsArchived(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test rejection"}}}
	server, conn, done := testServer(t, analyzer)
	root := enableTestRejectedMail(t, server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("From", "sender@example.net"),
		headerFrame("X-Unselected", "archive me"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("rejected body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	files := archivedMessages(t, root)
	if len(files) != 1 {
		t.Fatalf("archived files = %v", files)
	}
	content, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"From: sender@example.net", "X-Unselected: archive me", "rejected body"} {
		if !strings.Contains(string(content), want) {
			t.Fatalf("archive missing %q: %q", want, content)
		}
	}
}

func TestRejectedMessageArchiveUsesRejectionRecordIDs(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		AI:          config.AIConfig{MaxConcurrent: 1},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(root, "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10,
		},
	}
	server := NewServer(cfg, fixedAnalyzer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	archiveRoot := enableTestRejectedMail(t, server)
	msg := message.New(1024)
	msg.AddHeader("From", "Sender <sender@example.net>")
	msg.AddHeader("Subject", "=?UTF-8?B?44Oc44O844OK44K544KS4oCN5Y+X44GR5Y+W44Gj44Gm44GP4oCN44Gg44GV44GE?=")
	msg.AddHeader("Message-ID", "<archive-id-test@example.net>")
	msg.AddBody([]byte("rejected body"))

	server.sessions.policy.recordRejection(context.Background(), msg, "sender@example.net", "bounce@example.net", []string{"one@example.com", "two@example.com"}, []string{"unwanted"}, "ai")

	entries := rejectionEntries(t, server.sessions.policy.rejectionHistory, "*")
	if len(entries) != 1 {
		t.Fatalf("rejection entries = %d, want 1", len(entries))
	}
	entry := entries[0]
	if len(entry.Recipients) != 2 {
		t.Fatalf("stored recipients = %#v", entry.Recipients)
	}
	if entry.Subject != "ボーナスを‍受け取ってく‍ださい" {
		t.Fatalf("stored subject = %q", entry.Subject)
	}
	path := filepath.Join(archiveRoot, time.Now().UTC().Format("2006"), time.Now().UTC().Format("01"), time.Now().UTC().Format("02"), fmt.Sprintf("%d.eml", entry.ID))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive for rejection ID %d: %v", entry.ID, err)
	}
}

func expectNoFrame(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := readFrame(conn)
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("expected no response, got %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func expectFrame(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	got, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != want {
		t.Fatalf("response = %q, want %q", got, want)
	}
}

func negotiate(t *testing.T, conn net.Conn) {
	negotiateWithActions(t, conn, 0)
}

func negotiateWithActions(t *testing.T, conn net.Conn, actions uint32) {
	t.Helper()
	wantActions := uint32(0)
	if actions&resultHeaderActions == resultHeaderActions {
		wantActions = resultHeaderActions
	}
	negotiateWithExpectedActions(t, conn, actions, wantActions)
}

func negotiateWithExpectedActions(t *testing.T, conn net.Conn, offeredActions, wantActions uint32) {
	t.Helper()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	binary.BigEndian.PutUint32(payload[5:9], offeredActions)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil || len(reply) != 13 || reply[0] != commandOptionNegotiation {
		t.Fatalf("option negotiation failed: reply=%q err=%v", reply, err)
	}
	if got := binary.BigEndian.Uint32(reply[5:9]); got != wantActions {
		t.Fatalf("negotiated actions = %#x, want %#x", got, wantActions)
	}
}

func sendContinueFrames(t *testing.T, conn net.Conn, frames ...[]byte) {
	t.Helper()
	for _, frame := range frames {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseContinue}))
	}
}

func TestEnvelopeRecipientLimitIsIndependentAndMarksTruncation(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	ss := newSession(&sessionDependencies{log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		protocol: protocolOptions{timeout: time.Second, maxMessageSize: 1024}}, serverConn)
	ss.phase = phaseEnvelope
	ss.connected = true
	for index := range maxEnvelopeRecipients + 1 {
		finished := make(chan bool, 1)
		go func(index int) {
			frame := envelopeFrame(commandRecipient, fmt.Sprintf("recipient-%d@example.net", index))
			finished <- ss.handleCommand(context.Background(), frame[0], frame[1:])
		}(index)
		expectFrame(t, clientConn, string([]byte{responseContinue}))
		if !<-finished {
			t.Fatal("recipient frame closed the session")
		}
	}
	if len(ss.envelopeRecipients) != maxEnvelopeRecipients || !ss.envelopeRecipientsTruncated {
		t.Fatalf("recipients=%d truncated=%v, want %d and true", len(ss.envelopeRecipients), ss.envelopeRecipientsTruncated, maxEnvelopeRecipients)
	}
}

func connectFrame(family byte, address string) []byte {
	return connectFrameWithHostname("mail.example", family, address)
}

func connectFrameWithHostname(hostname string, family byte, address string) []byte {
	payload := []byte{commandConnect}
	payload = append(payload, []byte(hostname+"\x00")...)
	payload = append(payload, family, 0, 25)
	payload = append(payload, []byte(address)...)
	return append(payload, 0)
}

func macroFrame(target byte, pairs ...string) []byte {
	payload := []byte{commandMacro, target}
	for _, value := range pairs {
		payload = append(payload, []byte(value)...)
		payload = append(payload, 0)
	}
	return payload
}

func envelopeFrame(command byte, address string, arguments ...string) []byte {
	payload := append(append([]byte{command}, []byte("<"+address+">")...), 0)
	for _, argument := range arguments {
		payload = append(payload, argument...)
		payload = append(payload, 0)
	}
	return payload
}

func headerFrame(name, value string) []byte {
	payload := append([]byte{commandHeader}, []byte(name)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(value)...)
	return append(payload, 0)
}

func TestBelowThresholdUnwantedAddsTrustedResultHeaders(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 0.85, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "legitimate"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unwanted")))
	expectFrame(t, conn, string(addHeaderResponse(scoreHeader, "0.85")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "low")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-below-threshold")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestResultHeaderRemovalSurvivesRetentionLimit(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	frames := [][]byte{
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
	}
	for range 3 {
		frames = append(frames, headerFrame("To", strings.Repeat("x", 8192)))
	}
	frames = append(frames,
		headerFrame("Date", strings.Repeat("x", 8170)),
		headerFrame(classificationHeader, "forged-first"),
		headerFrame(classificationHeader, "forged-second"),
		[]byte{commandEndHeaders},
	)
	sendContinueFrames(t, conn, frames...)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "legitimate")))
	expectFrame(t, conn, string(addHeaderResponse(scoreHeader, "1")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "high")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestSenderResultHeadersRemovedWhenResultGenerationDisabled(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}})
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = false })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "forged"),
		headerFrame(scoreHeader, "1"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string(deleteHeaderResponse(scoreHeader)))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestCounterfeitResultHeadersDoNotAffectDeliveryWithoutMTASupport(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}})
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "forged"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	// The message remains deliverable, but MilterGuard does not add a second,
	// conflicting result set when the supplied value cannot be removed.
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestAcceptedLegitimateAddsTrustedResultHeaders(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0.79, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "legitimate")))
	expectFrame(t, conn, string(addHeaderResponse(scoreHeader, "0.79")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "low")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestTagModeAddsHeadersForEveryAIClassification(t *testing.T) {
	for _, test := range []struct {
		decision       ai.Decision
		wantScore      string
		wantConfidence string
	}{
		{ai.Decision{Classification: "legitimate", Score: 0.8, Reasons: []string{"test"}}, "0.8", "high"},
		{ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}, "1", "high"},
	} {
		t.Run(test.decision.Classification, func(t *testing.T) {
			server, conn, done := testServer(t, fixedAnalyzer{decision: test.decision})
			setTestMode(server, "tag")
			defer func() { _ = conn.Close(); <-done }()

			negotiateWithActions(t, conn, resultHeaderActions)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "sender@example.com"),
				envelopeFrame(commandRecipient, "recipient@example.net"),
				headerFrame("From", "Sender <sender@example.com>"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string(addHeaderResponse(classificationHeader, test.decision.Classification)))
			expectFrame(t, conn, string(addHeaderResponse(scoreHeader, test.wantScore)))
			expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, test.wantConfidence)))
			expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-tag-mode")))
			expectFrame(t, conn, string([]byte{responseAccept}))
		})
	}
}

func TestAcceptedAIErrorAddsDiagnosticHeadersWithoutScore(t *testing.T) {
	server, conn, done := testServer(t, failingAnalyzer{})
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(classificationHeader, "forged"),
		headerFrame(scoreHeader, "1"),
		headerFrame(confidenceHeader, "high"),
		headerFrame(actionHeader, "reject"),
		headerFrame("From", "Sender <sender@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	for _, name := range resultHeaderNames {
		expectFrame(t, conn, string(deleteHeaderResponse(name)))
	}
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-ai-error")))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestResultHeadersDoNotAffectDeliveryWithoutMTASupport(t *testing.T) {
	analyzer := fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 0.85, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestConnectionIdentityAndDNSAreSuppliedOncePerConnection(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 2)}
	server, conn, done := testServer(t, analyzer)
	resolver := &connectionTestResolver{
		ptr:        []string{"dns.google."},
		forward:    map[string][]net.IPAddr{"dns.google": {{IP: net.ParseIP("8.8.8.8")}}},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	server.sessions.dns.timeout = time.Second
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrameWithHostname("mta-claimed.example", '4', "8.8.8.8"),
		append([]byte{commandHelo}, []byte("helo-claimed.example\x00")...),
	)
	for i := 0; i < 2; i++ {
		sendContinueFrames(t, conn,
			[]byte{commandMail},
			[]byte{commandEndHeaders},
			append([]byte{commandBody}, []byte("test")...),
		)
		if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseAccept}))
		input := <-analyzer.inputs
		for _, want := range []string{
			"Remote IP: 8.8.8.8",
			"MTA-reported client hostname: mta-claimed.example",
			"Reverse DNS: dns.google (forward-confirmed)",
			"Forward-confirmed reverse DNS: yes",
			"SMTP HELO/EHLO identity: helo-claimed.example",
		} {
			if !strings.Contains(input.Text, want) {
				t.Errorf("analysis input missing %q:\n%s", want, input.Text)
			}
		}
	}
	if got := resolver.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want exactly 1 for the SMTP connection", got)
	}
	if got := resolver.forwardCalls.Load(); got != 1 {
		t.Fatalf("forward lookups = %d, want exactly 1 for the SMTP connection", got)
	}
}

func TestAIInputDiagnosticLoggingIsExplicitAndOmitsImageData(t *testing.T) {
	msg := message.New(100)
	msg.AddHeader("Message-ID", "<diagnostic@example.com>")
	input := ai.Input{
		Text:   "SELECTED HEADERS:\nAuthentication-Results: mx.example; dkim=pass",
		Images: []ai.Image{{MediaType: "image/png", Data: []byte("SECRET_IMAGE_BYTES")}},
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := NewServer(config.Config{
		AI:           config.AIConfig{MaxConcurrent: 1},
		IPReputation: config.IPReputationConfig{MaxEntries: 1},
	}, fixedAnalyzer{}, logger)

	server.sessions.analysis.logAIInput(msg, input, server.sessions.logging.IncludeAIInput)
	if output.Len() != 0 {
		t.Fatalf("AI input logged while disabled: %s", output.String())
	}
	server.sessions.logging.IncludeAIInput = true
	server.sessions.analysis.logAIInput(msg, input, server.sessions.logging.IncludeAIInput)
	logged := output.String()
	for _, want := range []string{
		`"msg":"AI analysis input"`,
		`"message_id":"<diagnostic@example.com>"`,
		`"ai_input":"SELECTED HEADERS:\nAuthentication-Results: mx.example; dkim=pass"`,
		`"image_count":1`,
		`"media_type":"image/png"`,
		`"bytes":18`,
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("diagnostic log missing %s: %s", want, logged)
		}
	}
	if strings.Contains(logged, "SECRET_IMAGE_BYTES") {
		t.Fatalf("diagnostic log exposed image data: %s", logged)
	}
}

func TestRejectedIPDomainAllowlistReusesConnectionDNS(t *testing.T) {
	server, conn, _ := testServer(t, fixedAnalyzer{decision: ai.Decision{
		Classification: "unwanted", Score: 1, Reasons: []string{"test"},
	}})
	server.sessions.dns.timeout = time.Second
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100, DomainAllowlist: []string{"google.com"}}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	resolver := &connectionTestResolver{
		ptr: []string{"smtp.google.com."},
		forward: map[string][]net.IPAddr{
			"smtp.google.com": {{IP: net.ParseIP("8.8.8.8")}},
		},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "8.8.8.8"),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("unwanted")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if _, found := server.sessions.policy.ipReputation.lookup(context.Background(), netip.MustParseAddr("8.8.8.8")); found {
		t.Fatal("forward-confirmed domain-allowlisted IP was added to rejection cache")
	}
	if got := resolver.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want 1", got)
	}
	if got := resolver.forwardCalls.Load(); got != 1 {
		t.Fatalf("forward lookups = %d, want 1", got)
	}
}

func TestForwardConfirmedDomainAllowlistBypassesExistingIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	server.sessions.dns.timeout = time.Second
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100, DomainAllowlist: []string{"google.com"}}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("8.8.8.8")
	if !server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{status: message.ReverseDNSLookupFailed}) {
		t.Fatal("test IP was not initially blocked")
	}
	resolver := &connectionTestResolver{
		ptr:        []string{"smtp.google.com."},
		forward:    map[string][]net.IPAddr{"smtp.google.com": {{IP: net.ParseIP(addr.String())}}},
		forwardErr: map[string]error{},
	}
	setTestResolver(server, resolver)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', addr.String()),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("legitimate message")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1 after cached block bypass", got)
	}
	if resolver.ptrCalls.Load() != 1 || resolver.forwardCalls.Load() != 1 {
		t.Fatalf("DNS calls = PTR %d, forward %d; want one each", resolver.ptrCalls.Load(), resolver.forwardCalls.Load())
	}
	_, retained := server.sessions.policy.ipReputation.snapshot()[addr]
	if !retained {
		t.Fatal("domain allowlist bypass unexpectedly deleted persisted IP reputation")
	}
}

func TestAuthenticatedSubmissionBypassesExistingIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("192.0.2.25")
	if !server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{}) {
		t.Fatal("test IP was not initially blocked")
	}
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', addr.String()))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
	if _, retained := server.sessions.policy.ipReputation.lookup(context.Background(), addr); !retained {
		t.Fatal("authenticated bypass unexpectedly removed existing IP reputation")
	}
}

func TestRejectedAuthenticatedSubmissionDoesNotCreateIPBlock(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	addr := netip.MustParseAddr("192.0.2.26")
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', addr.String()))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if _, blocked := server.sessions.policy.ipReputation.lookup(context.Background(), addr); blocked {
		t.Fatal("authenticated submission created IP reputation block")
	}
}

func TestCommandResponseRequirements(t *testing.T) {
	for _, cmd := range []byte{commandConnect, commandHelo, commandMail, commandRecipient, commandData, commandEndHeaders, commandUnknown} {
		t.Run(string(cmd), func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if cmd != commandConnect {
				sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
			}
			if cmd == commandRecipient || cmd == commandData || cmd == commandEndHeaders {
				if err := writeFrame(conn, []byte{commandMail}); err != nil {
					t.Fatal(err)
				}
				expectFrame(t, conn, "c")
			}
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, "c")
		})
	}
	for _, cmd := range []byte{commandAbort, commandMacro, commandQuitConnection} {
		t.Run(string(cmd)+"_no_response", func(t *testing.T) {
			_, conn, _ := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if err := writeFrame(conn, []byte{cmd}); err != nil {
				t.Fatal(err)
			}
			expectNoFrame(t, conn)
		})
	}
}

func TestOptionNegotiationResponse(t *testing.T) {
	_, conn, _ := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	payload := make([]byte, 13)
	payload[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(payload[1:5], 6)
	if err := writeFrame(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 13 || reply[0] != commandOptionNegotiation || binary.BigEndian.Uint32(reply[1:5]) != 6 {
		t.Fatalf("unexpected negotiation response: %q", reply)
	}
}

func TestParseConnectIP(t *testing.T) {
	tests := []struct {
		family  byte
		address string
		want    string
	}{
		{family: '4', address: "192.0.2.25", want: "192.0.2.25"},
		{family: '6', address: "2001:db8::25", want: "2001:db8::25"},
		{family: '6', address: "2001:db8::25%untrusted", want: "2001:db8::25"},
	}
	for _, test := range tests {
		frame := connectFrame(test.family, test.address)
		addr, ok := parseConnectIP(frame[1:])
		if !ok || addr.String() != test.want {
			t.Errorf("parseConnectIP(%q) = %s, %v; want %s", test.address, addr, ok, test.want)
		}
	}
	for _, payload := range [][]byte{
		{},
		[]byte("host\x004\x00\x19not-an-ip\x00"),
		connectFrame('4', "2001:db8::1")[1:],
	} {
		if addr, ok := parseConnectIP(payload); ok {
			t.Errorf("accepted malformed CONNECT address %s", addr)
		}
	}
}

func TestParseAndCleanConnectAndHELOIdentities(t *testing.T) {
	frame := connectFrameWithHostname("claimed.example", '4', "192.0.2.25")
	if got, ok := parseConnectHostname(frame[1:]); !ok || got != "claimed.example" {
		t.Fatalf("CONNECT hostname = %q, %v", got, ok)
	}
	if got, ok := parseSMTPIdentity([]byte("helo.example\x00")); !ok || got != "helo.example" {
		t.Fatalf("HELO identity = %q, %v", got, ok)
	}
	for _, unavailable := range []string{"", "unknown", "[UNKNOWN]", " \tunknown\r\n"} {
		if got := cleanSMTPIdentity(unavailable); got != "" {
			t.Errorf("cleanSMTPIdentity(%q) = %q, want unavailable", unavailable, got)
		}
	}
	if got := cleanSMTPIdentity("mx.example\r\nforged"); got != "mx.exampleforged" {
		t.Errorf("sanitized identity = %q", got)
	}
	if _, ok := parseSMTPIdentity([]byte("embedded\x00value\x00")); ok {
		t.Fatal("accepted HELO identity containing an embedded NUL")
	}
}

func TestParseAuthenticationSessionMacro(t *testing.T) {
	target, values, valid := parseSessionMacros(macroFrame(commandMail,
		"{auth_type}", "PLAIN", "{auth_authen}", "philip@example.com")[1:])
	if !valid || !values.AuthenticationFound || target != commandMail || values.AuthenticationIdentity != "philip@example.com" {
		t.Fatalf("parsed macro = target %q values=%#v valid=%v", target, values, valid)
	}
	for _, payload := range [][]byte{
		{},
		{commandMail, '{', 'a', 'u', 't', 'h', '_', 'a', 'u', 't', 'h', 'e', 'n', '}', 0},
		macroFrame(commandMail, "{auth_authen}", "first", "{auth_authen}", "second")[1:],
	} {
		if _, _, valid := parseSessionMacros(payload); valid {
			t.Errorf("accepted malformed macro payload %q", payload)
		}
	}
}

func TestParseMTAHostnameMacro(t *testing.T) {
	target, values, valid := parseSessionMacros(macroFrame(commandConnect,
		"j", "mx.example.com", "{daemon_name}", "smtp", "{daemon_addr}", "2001:db8::25")[1:])
	if !valid || target != commandConnect || !values.MTAHostnameFound || values.MTAHostname != "mx.example.com" ||
		!values.ReceiverAddressFound || values.ReceiverAddress != "2001:db8::25" {
		t.Fatalf("parsed macro = target %q values=%#v valid=%v", target, values, valid)
	}
	if got := canonicalMacroIP("[IPv6:2001:db8::25]"); got.String() != "2001:db8::25" {
		t.Fatalf("canonical receiver address = %s", got)
	}
	if got := canonicalMacroIP("not-an-address"); got.IsValid() {
		t.Fatalf("invalid receiver address accepted as %s", got)
	}
}

func TestAuthenticatedMessagesCanBypassAndAuthenticationPersists(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	for i := 0; i < 2; i++ {
		sendContinueFrames(t, conn,
			[]byte{commandMail},
			[]byte{commandEndHeaders},
			append([]byte{commandBody}, []byte("outbound message")...),
		)
		if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, string([]byte{responseAccept}))
	}
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}

	if err := writeFrame(conn, []byte{commandQuitConnection}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls after a new unauthenticated connection = %d, want 1", got)
	}
}

func TestExplicitEmptyAuthenticationMacroClearsAuthentication(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls for authenticated message = %d, want 0", got)
	}

	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls after explicit authentication clear = %d, want 1", got)
	}
}

func TestAuthenticatedMessagesAreScannedWhenEnabled(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, _ := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = true })
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "auth_authen", "philip@example.com")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn, []byte{commandMail}, []byte{commandEndHeaders})
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	select {
	case input := <-analyzer.inputs:
		if !strings.Contains(input.Text, "Authenticated SMTP submission: yes") {
			t.Fatalf("authenticated submission context missing from AI input:\n%s", input.Text)
		}
		if strings.Contains(input.Text, "CONNECTION INFORMATION:") {
			t.Fatalf("authenticated submission includes client connection information:\n%s", input.Text)
		}
		if strings.Contains(input.Text, "DKIM: no trusted local result") ||
			strings.Contains(input.Text, "SPF: no trusted local result") ||
			strings.Contains(input.Text, "DMARC: no trusted local result") {
			t.Fatalf("authenticated submission includes unavailable inbound authentication results:\n%s", input.Text)
		}
	default:
		t.Fatal("AI analysis was not called")
	}
}

func TestSenderDomainAllowlistBypassPolicy(t *testing.T) {
	for _, test := range []struct {
		name           string
		from           string
		authentication string
		requireDKIM    bool
		wantAICalls    int32
	}{
		{name: "exact domain without authentication requirement", from: "Orders <orders@amazon.com>", wantAICalls: 0},
		{name: "subdomain match", from: "Orders <orders@mail.amazon.com>", wantAICalls: 0},
		{name: "unrelated domain", from: "Orders <orders@amazon.example>", wantAICalls: 1},
		{name: "aligned trusted DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=amazon.com", requireDKIM: true, wantAICalls: 0},
		{name: "missing DKIM", from: "Orders <orders@amazon.com>", requireDKIM: true, wantAICalls: 1},
		{name: "unaligned DKIM", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dkim=pass header.d=attacker.example", requireDKIM: true, wantAICalls: 1},
		{name: "untrusted authentication results", from: "Orders <orders@amazon.com>", authentication: "attacker.example; dkim=pass header.d=amazon.com", requireDKIM: true, wantAICalls: 1},
		{name: "DMARC alone is insufficient", from: "Orders <orders@amazon.com>", authentication: "nl.invades.net; dmarc=pass header.from=amazon.com", requireDKIM: true, wantAICalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlist = []string{"amazon.com"} })
			setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlistRequireDKIM = test.requireDKIM })
			server.sessions.policy.correspondentCfg.TrustedAuthservIDs = []string{"nl.invades.net"}
			defer func() {
				_ = conn.Close()
				<-done
			}()

			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "sender@example.com"),
				envelopeFrame(commandRecipient, "recipient@example.net"),
				headerFrame("From", test.from),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestAuthenticatedAcceptedMessageLearnsEnvelopeRecipients(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
	server, conn, _ := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	deadline := time.Now().Add(time.Second)
	for {
		match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"})
		if match.Known && match.AllRecipientsMatched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("authenticated recipient was not learned: %#v", match)
		}
		time.Sleep(time.Millisecond)
	}
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestAbortedAuthenticatedMessageDoesNotLearnRecipients(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, _ := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		envelopeFrame(commandMail, "philip@invades.net"),
		envelopeFrame(commandRecipient, "alice@example.com"),
	)
	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"}); match.Known {
		t.Fatalf("aborted recipient was learned: %#v", match)
	}
}

func TestEndOfBodyPayloadIsIncludedInAnalysis(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	_, conn, done := testServer(t, analyzer)
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("Content-Type", "text/plain; charset=UTF-8"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("first body section ")...),
	)
	if err := writeFrame(conn, append([]byte{commandEndBody}, []byte("final body section")...)); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	input := <-analyzer.inputs
	if !strings.Contains(input.Text, "SMTP envelope sender: sender@example.net") {
		t.Fatalf("AI input missing SMTP envelope sender:\n%s", input.Text)
	}
	first := strings.Index(input.Text, "first body section")
	final := strings.Index(input.Text, "final body section")
	if first < 0 || final <= first {
		t.Fatalf("AI input does not contain the complete ordered body:\n%s", input.Text)
	}
}

func TestNullEnvelopeSenderIsSuppliedAsAIEvidence(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	_, conn, done := testServer(t, analyzer)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, ""),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if input := <-analyzer.inputs; !strings.Contains(input.Text, "SMTP envelope sender: <>") {
		t.Fatalf("AI input missing null SMTP envelope sender:\n%s", input.Text)
	}
}

func TestKnownCorrespondentIsSuppliedAsAIEvidence(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = conn.Close()
		<-done
	}()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "alice@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "Alice <alice@example.com>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	input := <-analyzer.inputs
	for _, want := range []string{
		"CORRESPONDENT INFORMATION:",
		"Sender found in known correspondent database: yes",
		"Basis: The visible From address was previously emailed from a relevant local address.",
		"Sender authentication: no trusted aligned DKIM or DMARC result is available.",
	} {
		if !strings.Contains(input.Text, want) {
			t.Errorf("AI input missing %q:\n%s", want, input.Text)
		}
	}
}

func TestMultipleFromHeadersCannotBypassOrTeachSenderTrust(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnAuthenticatedRecipients: true, LearnLegitimateSenders: true,
		UseAllowlist: true, BypassAI: true, Scope: "per_sender", RecipientMatch: "all",
		LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99,
		MaxEntries: 100,
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
	setTestFiltering(server, func(cfg *config.FilteringConfig) {
		cfg.SenderDomainAllowlist = []string{"example.com"}
	})
	if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
		t.Fatal(err)
	}

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "alice@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "Alice <alice@example.com>"),
		headerFrame("From", "Bob <bob@example.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	_ = conn.Close()
	<-done
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("ambiguous sender AI analyses = %d, want 1", got)
	}
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "bob@example.net", []string{"philip@invades.net"}); match.Known {
		t.Fatal("ambiguous sender was learned as a correspondent")
	}
	if got := len(server.sessions.policy.correspondents.(*correspondentStore).snapshot()); got != 1 {
		t.Fatalf("correspondent records after ambiguous sender = %d, want the original record only", got)
	}
}

func TestKnownCorrespondentBypassAuthenticationPolicy(t *testing.T) {
	for _, test := range []struct {
		name            string
		authentication  string
		secondRecipient string
		recipientMatch  string
		requireDKIM     bool
		wantAICalls     int32
	}{
		{name: "trusted aligned DKIM required", authentication: "nl.invades.net; dkim=pass header.d=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 0},
		{name: "untrusted DKIM required", authentication: "attacker.example; dkim=pass header.d=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 1},
		{name: "DMARC is insufficient when DKIM required", authentication: "nl.invades.net; dmarc=pass header.from=example.com", recipientMatch: "all", requireDKIM: true, wantAICalls: 1},
		{name: "no authentication required", authentication: "", recipientMatch: "all", requireDKIM: false, wantAICalls: 0},
		{name: "partial match requiring all", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "all", requireDKIM: false, wantAICalls: 1},
		{name: "partial match requiring any", authentication: "", secondRecipient: "other@invades.net", recipientMatch: "any", requireDKIM: false, wantAICalls: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: test.recipientMatch, BypassAI: true,
				RequireDKIMForBypass: test.requireDKIM,
				MaxEntries:           100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = conn.Close()
				<-done
			}()
			negotiate(t, conn)
			frames := [][]byte{
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
			}
			if test.secondRecipient != "" {
				frames = append(frames, envelopeFrame(commandRecipient, test.secondRecipient))
			}
			frames = append(frames,
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			sendContinueFrames(t, conn, frames...)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestMTAHostnameMacroExpandsTrustedAuthenticationService(t *testing.T) {
	for _, test := range []struct {
		name        string
		mtaHostname string
		wantAICalls int32
	}{
		{name: "matching MTA hostname", mtaHostname: "NL.Invades.Net.", wantAICalls: 0},
		{name: "missing MTA hostname", wantAICalls: 1},
		{name: "invalid MTA hostname", mtaHostname: "not a hostname!", wantAICalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				BypassAI: true, RequireDKIMForBypass: true,
				MaxEntries: 100, TrustedAuthservIDs: []string{config.MTAHostnameAuthservID},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = conn.Close()
				<-done
			}()
			negotiate(t, conn)
			if test.mtaHostname != "" {
				if err := writeFrame(conn, macroFrame(commandConnect, "j", test.mtaHostname)); err != nil {
					t.Fatal(err)
				}
				expectNoFrame(t, conn)
			}
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", "nl.invades.net; dkim=pass header.d=example.com"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			if got := analyzer.calls.Load(); got != test.wantAICalls {
				t.Fatalf("AI analysis calls = %d, want %d", got, test.wantAICalls)
			}
		})
	}
}

func TestBypassedInboundActivityRequiresTrustedDKIM(t *testing.T) {
	for _, test := range []struct {
		name           string
		authentication string
		requireDKIM    bool
		allowedDomain  string
		wantRefresh    bool
	}{
		{name: "unauthenticated bypass is not refreshed", requireDKIM: false},
		{name: "trusted DKIM bypass is refreshed", authentication: "nl.invades.net; dkim=pass header.d=example.com", requireDKIM: true, wantRefresh: true},
		{name: "trusted sender-domain bypass refreshes known correspondent", authentication: "nl.invades.net; dkim=pass header.d=example.com", requireDKIM: true, allowedDomain: "example.com", wantRefresh: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			cfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				BypassAI: true, RequireDKIMForBypass: test.requireDKIM,
				MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))
			if test.allowedDomain != "" {
				setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlist = []string{test.allowedDomain} })
				setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.SenderDomainAllowlistRequireDKIM = true })
			}
			learnedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
			server.sessions.policy.correspondents.(*correspondentStore).now = func() time.Time { return learnedAt }
			if err := server.sessions.policy.correspondents.LearnAuthenticated(context.Background(), "philip@invades.net", []string{"alice@example.com"}); err != nil {
				t.Fatal(err)
			}
			activityAt := learnedAt.Add(time.Hour)
			server.sessions.policy.correspondents.(*correspondentStore).now = func() time.Time { return activityAt }
			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', "127.0.0.1"),
				envelopeFrame(commandMail, "alice@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "Alice <alice@example.com>"),
				headerFrame("Authentication-Results", test.authentication),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			_ = conn.Close()
			<-done
			activity := server.sessions.policy.correspondents.(*correspondentStore).snapshot()["philip@invades.net\x00alice@example.com"].LastActivityAt
			want := learnedAt
			if test.wantRefresh {
				want = activityAt
			}
			if !activity.Equal(want) {
				t.Fatalf("last activity = %s, want %s", activity, want)
			}
			if got := analyzer.calls.Load(); got != 0 {
				t.Fatalf("AI analysis calls = %d, want bypass", got)
			}
		})
	}
}

func TestAIResultLearnsInboundSender(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	cfg := config.CorrespondentsConfig{
		LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
		LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99, LegitimateSenderRequireDKIM: true,
		MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
	}
	setTestCorrespondents(server, cfg, newTestCorrespondentStore(t, cfg, server.log))

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "news@example.com"),
		envelopeFrame(commandRecipient, "philip@invades.net"),
		headerFrame("From", "News <news@example.com>"),
		headerFrame("Authentication-Results", "nl.invades.net; dkim=pass header.d=example.com"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	<-done
	_ = conn.Close()
	if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "news@example.com", []string{"philip@invades.net"}); !match.Known {
		t.Fatal("qualifying AI result did not create a known correspondent")
	}
}

func TestNonEnforceModesDoNotLearnFromAIResultsOrDecayIPReputation(t *testing.T) {
	for _, mode := range []string{"monitor", "tag"} {
		t.Run(mode, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1, Reasons: []string{"test"}}}
			server, conn, done := testServer(t, analyzer)
			setTestMode(server, mode)
			correspondentCfg := config.CorrespondentsConfig{
				LearnLegitimateSenders: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				LegitimateSenderMinMessages: 1, LegitimateSenderMinScore: .99, LegitimateSenderRequireDKIM: true,
				MaxEntries: 100, TrustedAuthservIDs: []string{"nl.invades.net"},
			}
			setTestCorrespondents(server, correspondentCfg, newTestCorrespondentStore(t, correspondentCfg, server.log))
			ipCfg := config.IPReputationConfig{
				BlockDuration: config.Duration(time.Hour), RepeatThreshold: 3, RepeatWindow: config.Duration(24 * time.Hour), LegitimatePerStrike: 1,
				MaxEntries: 100,
			}
			setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
			addr := netip.MustParseAddr("192.0.2.90")
			server.sessions.policy.ipReputation.add(context.Background(), addr, connectionDNSResult{})

			negotiate(t, conn)
			sendContinueFrames(t, conn,
				connectFrame('4', addr.String()),
				envelopeFrame(commandMail, "news@example.com"),
				envelopeFrame(commandRecipient, "philip@invades.net"),
				headerFrame("From", "News <news@example.com>"),
				headerFrame("Authentication-Results", "nl.invades.net; dkim=pass header.d=example.com"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			_ = conn.Close()
			<-done

			if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "news@example.com", []string{"philip@invades.net"}); match.Known {
				t.Fatalf("%s mode learned an inbound correspondent", mode)
			}
			strikes := len(server.sessions.policy.ipReputation.snapshot()[addr].Strikes)
			if strikes != 1 {
				t.Fatalf("%s mode changed IP strike count to %d", mode, strikes)
			}
		})
	}
}

func TestNonEnforceModesDoNotLearnAuthenticatedRecipients(t *testing.T) {
	for _, mode := range []string{"monitor", "tag"} {
		t.Run(mode, func(t *testing.T) {
			server, conn, done := testServer(t, &countingAnalyzer{})
			setTestMode(server, mode)
			setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
			correspondentCfg := config.CorrespondentsConfig{
				LearnAuthenticatedRecipients: true, UseAllowlist: true, Scope: "per_sender", RecipientMatch: "all",
				MaxEntries: 100,
			}
			setTestCorrespondents(server, correspondentCfg, newTestCorrespondentStore(t, correspondentCfg, server.log))

			negotiate(t, conn)
			sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
			if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
				t.Fatal(err)
			}
			expectNoFrame(t, conn)
			sendContinueFrames(t, conn,
				envelopeFrame(commandMail, "philip@invades.net"),
				envelopeFrame(commandRecipient, "alice@example.com"),
				[]byte{commandEndHeaders},
			)
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			expectFrame(t, conn, string([]byte{responseAccept}))
			_ = conn.Close()
			<-done
			if match := testCorrespondentMatch(t, server.sessions.policy.correspondents, context.Background(), "alice@example.com", []string{"philip@invades.net"}); match.Known {
				t.Fatalf("%s mode learned an authenticated recipient", mode)
			}
		})
	}
}

func TestRejectedIPBypassesSecondAIAnalysis(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}}
	server, conn, done := testServer(t, analyzer)
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(15 * time.Minute), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	defer conn.Close()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.25"))
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("first scam")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}

	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestAnalysisTimeoutUsesAITimeoutWithResponseMargin(t *testing.T) {
	s := &analysisService{milterTimeout: 30 * time.Second, ai: config.AIConfig{Timeout: config.Duration(60 * time.Second)}}
	if got, want := s.analysisTimeout(), 65*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutIncludesRetryAttemptsAndWaits(t *testing.T) {
	s := &analysisService{milterTimeout: 30 * time.Second, ai: config.AIConfig{Timeout: config.Duration(60 * time.Second), Retries: 2}}
	if got, want := s.analysisTimeout(), 245*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutIncludesInternalAuthentication(t *testing.T) {
	s := &analysisService{
		milterTimeout: 30 * time.Second, authenticationTimeout: 10 * time.Second,
		ai: config.AIConfig{Timeout: config.Duration(60 * time.Second)},
	}
	if got, want := s.analysisTimeout(), 75*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestAnalysisTimeoutPreservesLongerMilterTimeout(t *testing.T) {
	s := &analysisService{milterTimeout: 90 * time.Second, ai: config.AIConfig{Timeout: config.Duration(60 * time.Second)}}
	if got, want := s.analysisTimeout(), 90*time.Second; got != want {
		t.Fatalf("analysis timeout = %v, want %v", got, want)
	}
}

func TestReplyCodeWireFormat(t *testing.T) {
	got := replyCode("550", "5.7.1", "Message rejected: 100% spam\ntry again")
	want := []byte("y550 5.7.1 Message rejected: 100%% spam try again\x00")
	if string(got) != string(want) {
		t.Fatalf("reply code = %q, want %q", got, want)
	}
}

func TestReplyCodeLimitsSMTPLineAndPreservesUTF8(t *testing.T) {
	got := replyCode("550", "5.7.1", strings.Repeat("é", 600))
	line := got[1 : len(got)-1]
	if len(line) > maxSMTPReplyBytes {
		t.Fatalf("Milter reply is %d bytes, limit is %d", len(line), maxSMTPReplyBytes)
	}
	smtpLine := strings.ReplaceAll(string(line), "%%", "%")
	if len(smtpLine) > maxSMTPReplyBytes {
		t.Fatalf("SMTP reply is %d bytes, limit is %d", len(smtpLine), maxSMTPReplyBytes)
	}
	if !utf8.ValidString(smtpLine) {
		t.Fatal("SMTP reply was truncated inside a UTF-8 sequence")
	}
}

func TestReplyCodePercentEscapingStaysWithinLimitAndComplete(t *testing.T) {
	got := replyCode("550", "5.7.1", "x"+strings.Repeat("%", maxSMTPReplyBytes))
	line := got[1 : len(got)-1]
	if len(line) > maxSMTPReplyBytes {
		t.Fatalf("Milter reply is %d bytes, limit is %d", len(line), maxSMTPReplyBytes)
	}
	percentRun := 0
	for index := len(line) - 1; index >= 0 && line[index] == '%'; index-- {
		percentRun++
	}
	if percentRun%2 != 0 {
		t.Fatalf("reply ends with an incomplete percent escape: %q", line)
	}
}

func TestParseHeaderPreservesEmptyValue(t *testing.T) {
	name, value, ok := parseHeader([]byte("X-Empty\x00\x00"))
	if !ok || name != "X-Empty" || value != "" {
		t.Fatalf("parseHeader = %q, %q, %v", name, value, ok)
	}
}

func TestParseHeaderRejectsTrailingData(t *testing.T) {
	if _, _, ok := parseHeader([]byte("Subject\x00test\x00extra")); ok {
		t.Fatal("accepted header payload with trailing data")
	}
}

func TestWriteFrameHandlesShortWrites(t *testing.T) {
	w := &shortWriter{max: 2}
	if err := writeFrame(w, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	want := "\x00\x00\x00\x05hello"
	if w.b.String() != want {
		t.Fatalf("framed output = %q, want %q", w.b.String(), want)
	}
}
