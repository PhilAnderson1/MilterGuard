package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

type blockingVerifier struct {
	started  chan struct{}
	release  chan struct{}
	canceled chan struct{}
}

func (v *blockingVerifier) Verify(ctx context.Context, _ mailauth.Transaction) (mailauth.Evidence, error) {
	close(v.started)
	select {
	case <-v.release:
		return mailauth.Evidence{}, nil
	case <-ctx.Done():
		if v.canceled != nil {
			close(v.canceled)
		}
		return mailauth.Evidence{}, ctx.Err()
	}
}

type trackedExactMessage struct {
	mu     sync.Mutex
	data   []byte
	closed bool
}

type exactMessageRegistry struct {
	mu            sync.Mutex
	stores        []*trackedExactMessage
	panicOnHeader bool
}

func (r *exactMessageRegistry) factory(string, int64) (mailauth.ExactMessage, error) {
	store := &trackedExactMessage{}
	if r.panicOnHeader {
		return &panicHeaderExactMessage{trackedExactMessage: store}, r.add(store)
	}
	return store, r.add(store)
}

func (r *exactMessageRegistry) add(store *trackedExactMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stores = append(r.stores, store)
	return nil
}

func (r *exactMessageRegistry) requireAllClosed(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.stores) == 0 {
		t.Fatal("no exact-message stores were created")
	}
	for index, store := range r.stores {
		if !store.isClosed() {
			t.Errorf("exact-message store %d was not closed", index)
		}
	}
}

type panicHeaderExactMessage struct{ *trackedExactMessage }

func (m *panicHeaderExactMessage) AddHeader(string, string) error { panic("exact-message test panic") }

func (m *trackedExactMessage) AddHeader(name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append(m.data, []byte(name+": "+value+"\r\n")...)
	return nil
}
func (m *trackedExactMessage) EndHeaders() error { return m.AddBody([]byte("\r\n")) }
func (m *trackedExactMessage) AddBody(payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append(m.data, payload...)
	return nil
}
func (m *trackedExactMessage) ReaderAt() (io.ReaderAt, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copyOfData := append([]byte(nil), m.data...)
	return bytes.NewReader(copyOfData), int64(len(copyOfData)), nil
}
func (m *trackedExactMessage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
func (m *trackedExactMessage) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

type deadlineFailingConn struct {
	net.Conn
	err error
}

func (conn deadlineFailingConn) SetDeadline(time.Time) error { return conn.err }

type blockingAnalyzer struct {
	started       chan struct{}
	release       chan struct{}
	canceled      chan struct{}
	cancelRelease chan struct{}
	finished      chan struct{}
}

func (a *blockingAnalyzer) Analyze(ctx context.Context, _ ai.Input) (ai.Decision, error) {
	close(a.started)
	select {
	case <-a.release:
		return ai.Decision{Classification: "legitimate", Score: 1}, nil
	case <-ctx.Done():
		if a.canceled != nil {
			close(a.canceled)
		}
		if a.cancelRelease != nil {
			<-a.cancelRelease
		}
		if a.finished != nil {
			close(a.finished)
		}
		return ai.Decision{}, ctx.Err()
	}
}

func TestSlowEndOfMessageSendsProgressBeforeFinalResponse(t *testing.T) {
	analyzer := &blockingAnalyzer{started: make(chan struct{}), release: make(chan struct{})}
	server, conn, done := testServer(t, analyzer)
	server.sessions.protocol.progressInterval = 10 * time.Millisecond
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("message body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-analyzer.started:
	case <-time.After(time.Second):
		t.Fatal("analysis did not start")
	}
	expectFrame(t, conn, string([]byte{responseProgress}))
	close(analyzer.release)
	for {
		response, err := readFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if len(response) == 1 && response[0] == responseProgress {
			continue
		}
		if len(response) != 1 || response[0] != responseAccept {
			t.Fatalf("final response = %q, want accept", response)
		}
		break
	}
}

func TestSlowAuthenticationSendsProgressAndPrecedesAnalysis(t *testing.T) {
	verifier := &blockingVerifier{started: make(chan struct{}), release: make(chan struct{})}
	analyzer := &blockingAnalyzer{started: make(chan struct{}), release: make(chan struct{})}
	server, conn, done := testServer(t, analyzer)
	server.sessions.authentication = verifier
	server.sessions.protocol.progressInterval = 10 * time.Millisecond
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-verifier.started:
	case <-time.After(time.Second):
		t.Fatal("authentication verifier did not start")
	}
	expectFrame(t, conn, string([]byte{responseProgress}))
	select {
	case <-analyzer.started:
		t.Fatal("analysis started before authentication completed")
	default:
	}
	close(verifier.release)
	select {
	case <-analyzer.started:
	case <-time.After(time.Second):
		t.Fatal("analysis did not start after authentication")
	}
	close(analyzer.release)
	for {
		response, err := readFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if len(response) == 1 && response[0] == responseProgress {
			continue
		}
		if len(response) != 1 || response[0] != responseAccept {
			t.Fatalf("final response = %q, want accept", response)
		}
		break
	}
}

func TestAuthenticationProgressWriteFailureCancelsVerifier(t *testing.T) {
	verifier := &blockingVerifier{started: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.authentication = verifier
	server.sessions.protocol.progressInterval = 10 * time.Millisecond

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.1"), envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"), headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-verifier.started:
	case <-time.After(time.Second):
		t.Fatal("authentication verifier did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-verifier.canceled:
	case <-time.After(time.Second):
		t.Fatal("authentication verifier was not canceled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after authentication progress failure")
	}
}

func TestExactMessageClosesOnAbortAndDisconnect(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(config.Config{
		Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: .9, AIErrorAction: "accept"},
	}, fixedAnalyzer{}, log)
	var storesMu sync.Mutex
	var stores []*trackedExactMessage
	server.sessions.newExactMessage = func(string, int64) (mailauth.ExactMessage, error) {
		store := &trackedExactMessage{}
		storesMu.Lock()
		stores = append(stores, store)
		storesMu.Unlock()
		return store, nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		server.handle(context.Background(), serverConn)
	}()

	negotiate(t, clientConn)
	sendContinueFrames(t, clientConn, connectFrame('4', "192.0.2.1"), envelopeFrame(commandMail, "sender@example.net"), headerFrame("From", "sender@example.net"))
	if err := writeFrame(clientConn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after disconnect")
	}
	storesMu.Lock()
	defer storesMu.Unlock()
	if len(stores) != 1 {
		t.Fatalf("exact-message stores created = %d, want 1", len(stores))
	}
	for index, store := range stores {
		if !store.isClosed() {
			t.Errorf("exact-message store %d was not closed", index)
		}
	}
}

func TestExactMessageClosesAfterAcceptAndReject(t *testing.T) {
	for _, test := range []struct {
		name     string
		decision ai.Decision
	}{
		{name: "accept", decision: ai.Decision{Classification: "legitimate", Score: 1}},
		{name: "reject", decision: ai.Decision{Classification: "unwanted", Score: 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverConn, clientConn := net.Pipe()
			registry := &exactMessageRegistry{}
			server := NewServer(config.Config{
				Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 1024},
				AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
				Filtering: config.FilteringConfig{RejectScore: .9, AIErrorAction: "accept", RejectMessage: "blocked"},
			}, fixedAnalyzer{decision: test.decision}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			server.sessions.newExactMessage = registry.factory
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer serverConn.Close()
				server.handle(context.Background(), serverConn)
			}()

			negotiate(t, clientConn)
			sendContinueFrames(t, clientConn,
				connectFrame('4', "192.0.2.1"), envelopeFrame(commandMail, "sender@example.net"),
				envelopeFrame(commandRecipient, "recipient@example.com"), headerFrame("From", "sender@example.net"),
				[]byte{commandEndHeaders}, append([]byte{commandBody}, []byte("body")...),
			)
			if err := writeFrame(clientConn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			if _, err := readFrame(clientConn); err != nil {
				t.Fatal(err)
			}
			if err := writeFrame(clientConn, []byte{commandQuit}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("session did not stop")
			}
			_ = clientConn.Close()
			registry.requireAllClosed(t)
		})
	}
}

func TestExactMessageClosesOnPartialFrameTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	registry := &exactMessageRegistry{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(config.Config{
		Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: .9, AIErrorAction: "accept"},
	}, fixedAnalyzer{}, log)
	server.sessions.newExactMessage = registry.factory
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		newSession(server.sessions, serverConn).run(context.Background())
	}()
	// Start a transaction so a per-message exact store exists, then leave the
	// following frame incomplete until the protocol deadline fires.
	negotiate(t, clientConn)
	sendContinueFrames(t, clientConn, connectFrame('4', "192.0.2.1"), envelopeFrame(commandMail, "sender@example.net"))
	if _, err := clientConn.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after partial-frame timeout")
	}
	_ = clientConn.Close()
	registry.requireAllClosed(t)
}

func TestExactMessageClosesWhenSessionPanics(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	registry := &exactMessageRegistry{panicOnHeader: true}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(config.Config{
		Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: .9, AIErrorAction: "accept"},
	}, fixedAnalyzer{}, log)
	server.sessions.newExactMessage = registry.factory
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		server.handle(context.Background(), serverConn)
	}()
	negotiate(t, clientConn)
	sendContinueFrames(t, clientConn, connectFrame('4', "192.0.2.1"), envelopeFrame(commandMail, "sender@example.net"))
	if err := writeFrame(clientConn, headerFrame("From", "sender@example.net")); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(clientConn); err == nil {
		t.Fatal("connection remained open after session panic")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("panicking session did not stop")
	}
	_ = clientConn.Close()
	registry.requireAllClosed(t)
}

func TestCompletedCommandRemainsUsableAcrossReadTimeouts(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server := NewServer(config.Config{
		Mode:      "enforce",
		Milter:    config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond), MaxMessageSize: 1024},
		AI:        config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{RejectScore: 0.9, AIErrorAction: "accept"},
	}, analyzer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := newSession(server.sessions, serverConn)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer serverConn.Close()
		ss.run(context.Background())
	}()

	negotiate(t, clientConn)
	sendContinueFrames(t, clientConn,
		connectFrame('4', "192.0.2.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("message body")...),
	)
	if err := writeFrame(clientConn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, clientConn, string([]byte{responseAccept}))
	time.Sleep(75 * time.Millisecond)
	if err := writeFrame(clientConn, []byte{commandHelo}); err != nil {
		t.Fatalf("write command after completed processing: %v", err)
	}
	expectFrame(t, clientConn, string([]byte{responseContinue}))
	if err := writeFrame(clientConn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestProgressWriteFailureCancelsAnalysis(t *testing.T) {
	analyzer := &blockingAnalyzer{
		started: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{}),
		cancelRelease: make(chan struct{}), finished: make(chan struct{}),
	}
	server, conn, done := testServer(t, analyzer)
	server.sessions.protocol.progressInterval = 10 * time.Millisecond

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.1"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.com"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("message body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-analyzer.started:
	case <-time.After(time.Second):
		t.Fatal("analysis did not start")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-analyzer.canceled:
	case <-time.After(time.Second):
		t.Fatal("analysis was not canceled after the progress response failed")
	}
	select {
	case <-done:
		t.Fatal("session exited before its analysis worker finished")
	case <-time.After(25 * time.Millisecond):
	}
	close(analyzer.cancelRelease)
	select {
	case <-analyzer.finished:
	case <-time.After(time.Second):
		t.Fatal("analysis worker did not finish after cancellation cleanup")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session did not stop after the progress response failed")
	}
}

func TestDeadlineFailureClosesSession(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	deadlineErr := errors.New("deadline unavailable")
	var logOutput bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug}))
	server := &Server{log: log, sessions: &sessionDependencies{
		protocol: protocolOptions{timeout: time.Minute, maxMessageSize: 1024}, log: log,
	}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handle(context.Background(), deadlineFailingConn{Conn: serverConn, err: deadlineErr})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("session continued after deadline failure")
	}
	for _, wanted := range []string{`msg="cannot set Milter connection deadline"`, `stage="protocol read"`, "deadline unavailable"} {
		if !strings.Contains(logOutput.String(), wanted) {
			t.Errorf("deadline failure log does not contain %q: %s", wanted, logOutput.String())
		}
	}
}

func TestMalformedOptionNegotiationClosesConnection(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	if err := writeFrame(conn, []byte{commandOptionNegotiation, 0, 0, 0, 6}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(conn); err == nil {
		t.Fatal("expected malformed negotiation to close the connection")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after malformed negotiation")
	}
}

func TestProtocolRejectsInvalidSequences(t *testing.T) {
	tests := []struct {
		name    string
		setup   [][]byte
		invalid []byte
	}{
		{name: "header before mail", invalid: []byte{commandHeader}},
		{name: "body before end headers", setup: [][]byte{{commandMail}}, invalid: []byte{commandBody}},
		{name: "end body before end headers", setup: [][]byte{{commandMail}}, invalid: []byte{commandEndBody}},
		{name: "helo during message", setup: [][]byte{{commandMail}}, invalid: []byte{commandHelo}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, conn, done := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
			sendContinueFrames(t, conn, test.setup...)
			if err := writeFrame(conn, test.invalid); err != nil {
				t.Fatal(err)
			}
			if _, err := readFrame(conn); err == nil {
				t.Fatal("expected invalid sequence to close the connection")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler did not exit after invalid sequence")
			}
		})
	}
}

func TestProtocolRejectsHeloAndMailWithoutConnect(t *testing.T) {
	for _, command := range []byte{commandHelo, commandMail} {
		t.Run(commandName(command), func(t *testing.T) {
			_, conn, done := testServer(t, fixedAnalyzer{})
			defer conn.Close()
			negotiate(t, conn)
			if err := writeFrame(conn, []byte{command}); err != nil {
				t.Fatal(err)
			}
			if _, err := readFrame(conn); err == nil {
				t.Fatal("command without CONNECT did not close the connection")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler did not exit after command without CONNECT")
			}
		})
	}
}

func TestAbortDoesNotDesynchronizeNextTransaction(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{decision: ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}})
	defer conn.Close()
	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "c")
	if err := writeFrame(conn, []byte{commandAbort}); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	for _, frame := range [][]byte{{commandHelo}, {commandMail}, append([]byte{commandHeader}, []byte("Subject\x00test\x00")...), {commandEndHeaders}, append([]byte{commandBody}, []byte("test body")...)} {
		if err := writeFrame(conn, frame); err != nil {
			t.Fatal(err)
		}
		expectFrame(t, conn, "c")
	}
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if err := writeFrame(conn, []byte{commandQuit}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestUnsupportedCommandClosesConnection(t *testing.T) {
	_, conn, done := testServer(t, fixedAnalyzer{})
	defer conn.Close()
	if err := writeFrame(conn, []byte{'Z'}); err != nil {
		t.Fatal(err)
	}
	if _, err := readFrame(conn); err == nil || !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("expected connection close, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit for unsupported command")
	}
}

func TestIdleConnectionRemainsOpenAcrossReadTimeouts(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(config.Config{
		Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond), MaxMessageSize: 1024, MaxConnections: 1},
		AI: config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1},
	}, fixedAnalyzer{}, log)
	done := make(chan struct{})
	go func() { defer close(done); defer serverConn.Close(); server.handle(context.Background(), serverConn) }()
	time.Sleep(75 * time.Millisecond)
	negotiate(t, clientConn)
	sendContinueFrames(t, clientConn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(clientConn, []byte{commandHelo}); err != nil {
		t.Fatalf("write command after idle period: %v", err)
	}
	reply, err := readFrame(clientConn)
	if err != nil {
		t.Fatalf("read reply after idle period: %v", err)
	}
	if len(reply) != 1 || reply[0] != 'c' {
		t.Fatalf("unexpected reply: %q", reply)
	}
	if err := writeFrame(clientConn, []byte{commandQuit}); err != nil {
		t.Fatalf("write quit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not exit after quit")
	}
}

func TestContextCancellationClosesIdleConnectionImmediately(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	var logOutput bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logOutput, nil))
	server := NewServer(config.Config{
		Mode: "enforce", Milter: config.MilterConfig{Timeout: config.Duration(time.Hour), MaxMessageSize: 1024, MaxConnections: 1},
		AI: config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1},
	}, fixedAnalyzer{}, log)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); server.handle(ctx, serverConn) }()
	negotiate(t, clientConn)
	started := time.Now()
	cancel()
	select {
	case <-done:
		if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
			t.Fatalf("cancelled idle connection took %s to close", elapsed)
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection remained blocked after context cancellation")
	}
	if logOutput.Len() != 0 {
		t.Fatalf("normal shutdown produced a connection warning: %s", logOutput.String())
	}
}

func TestHandleClosesAfterPartialFrameTimeout(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := &Server{log: log, sessions: &sessionDependencies{
		protocol: protocolOptions{timeout: 20 * time.Millisecond, maxMessageSize: 1024}, log: log,
	}}
	done := make(chan struct{})
	go func() { defer close(done); defer serverConn.Close(); server.handle(context.Background(), serverConn) }()
	if _, err := clientConn.Write([]byte{0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler retained a connection after a partial-frame timeout")
	}
}
