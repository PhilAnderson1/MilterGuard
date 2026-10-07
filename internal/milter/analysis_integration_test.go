package milter

import (
	"context"
	"errors"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recordingAnalyzer struct {
	inputs chan ai.Input
}

type failingAnalyzer struct{}

type usageFailingAnalyzer struct{ usage ai.Usage }

func (a *recordingAnalyzer) Analyze(_ context.Context, input ai.Input) (ai.Analysis, error) {
	a.inputs <- input
	return ai.Analysis{Decision: ai.Decision{Classification: "legitimate", Score: 0, Reasons: []string{"test"}}}, nil
}

func (failingAnalyzer) Analyze(context.Context, ai.Input) (ai.Analysis, error) {
	return ai.Analysis{}, errors.New("endpoint unavailable")
}

func (a usageFailingAnalyzer) Analyze(context.Context, ai.Input) (ai.Analysis, error) {
	return ai.Analysis{Usage: a.usage}, errors.New("endpoint unavailable")
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

func TestCompletedScanRecordsActivityAndTokenCost(t *testing.T) {
	cfg := config.Config{
		Mode:   "enforce",
		Milter: config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 1024},
		AI: config.AIConfig{
			Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
			InputCostPerMillionTokens: 1, OutputCostPerMillionTokens: 2,
		},
		Activity:    config.ActivityConfig{Expiry: config.Duration(24 * time.Hour)},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		Filtering: config.FilteringConfig{
			RejectScore: .9, LegitimateLowConfidenceScore: .8, AIErrorAction: "accept", RejectMessage: "blocked",
		},
	}
	server, conn, done := testServerWithConfig(t, cfg, fixedAnalyzer{
		decision: ai.Decision{Classification: "legitimate", Score: 1},
		usage:    ai.Usage{InputTokens: 1000, OutputTokens: 500},
	})
	defer func() { _ = conn.Close(); <-done; _ = server.Close() }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "198.51.100.9"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))

	reporter, ok := server.maintenance.activity.(stores.ActivityReporter)
	if !ok {
		t.Fatal("activity maintenance repository does not support reporting")
	}
	var summary stores.ActivitySummary
	var err error
	deadline := time.Now().Add(time.Second)
	for {
		summary, err = reporter.ActivitySummary(context.Background(), stores.ActivityQuery{Before: time.Now().Add(time.Second)})
		if err != nil || summary.ScanTotal == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if summary.ScanTotal != 1 || summary.ScanAccepted != 1 || summary.ScanRejections != 0 || summary.AIEvaluationsFailed != 0 || summary.TokenCost != .002 {
		t.Fatalf("activity summary = %+v", summary)
	}
}

func TestFailedFailOpenScanRecordsAcceptedActivityAndKnownCost(t *testing.T) {
	cfg := config.Config{
		Mode:   "enforce",
		Milter: config.MilterConfig{Timeout: config.Duration(time.Second), MaxMessageSize: 1024},
		AI: config.AIConfig{
			Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
			InputCostPerMillionTokens: 1, OutputCostPerMillionTokens: 2,
		},
		Activity:    config.ActivityConfig{Expiry: config.Duration(24 * time.Hour)},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		Filtering: config.FilteringConfig{
			RejectScore: .9, LegitimateLowConfidenceScore: .8, AIErrorAction: "accept", RejectMessage: "blocked",
		},
	}
	server, conn, done := testServerWithConfig(t, cfg, usageFailingAnalyzer{
		usage: ai.Usage{InputTokens: 1000, OutputTokens: 500},
	})
	defer func() { _ = conn.Close(); <-done; _ = server.Close() }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "198.51.100.9"),
		envelopeFrame(commandMail, "sender@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "sender@example.net"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))

	reporter, ok := server.maintenance.activity.(stores.ActivityReporter)
	if !ok {
		t.Fatal("activity maintenance repository does not support reporting")
	}
	var summary stores.ActivitySummary
	deadline := time.Now().Add(time.Second)
	for {
		var err error
		summary, err = reporter.ActivitySummary(context.Background(), stores.ActivityQuery{Before: time.Now().Add(time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		if summary.ScanTotal == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if summary.ScanTotal != 1 || summary.ScanAccepted != 1 || summary.AIEvaluationsFailed != 1 || summary.TokenCost != .002 {
		t.Fatalf("activity summary = %+v", summary)
	}
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
