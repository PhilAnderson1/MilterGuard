package milter

import (
	"context"
	"encoding/binary"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fixedAnalyzer struct {
	decision ai.Decision
	usage    ai.Usage
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

func (a fixedAnalyzer) Analyze(context.Context, ai.Input) (ai.Analysis, error) {
	return ai.Analysis{Decision: a.decision, Usage: a.usage}, nil
}

func (a *countingAnalyzer) Analyze(context.Context, ai.Input) (ai.Analysis, error) {
	a.calls.Add(1)
	return ai.Analysis{Decision: a.decision}, nil
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
	server.maintenance.archive = archive
	return root
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
	wantActions := actions & (resultHeaderActions | actionDeleteRecipient)
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
