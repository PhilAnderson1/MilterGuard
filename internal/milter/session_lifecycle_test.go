package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

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
	server.progressInterval = 10 * time.Millisecond
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
	ss := newSession(server, serverConn)
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
	server.progressInterval = 10 * time.Millisecond

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
	server := &Server{
		cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(time.Minute)}},
		log: slog.New(slog.NewTextHandler(&logOutput, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
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
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(time.Hour)}}, log: slog.New(slog.NewTextHandler(&logOutput, nil))}
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
	server := &Server{cfg: config.Config{Milter: config.MilterConfig{Timeout: config.Duration(20 * time.Millisecond)}}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
