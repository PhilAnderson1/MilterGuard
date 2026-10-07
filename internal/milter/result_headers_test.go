package milter

import (
	"context"
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

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
	setTestMode(server, "accept")
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

func TestAcceptModeAddsConfiguredHeadersForEveryAIClassification(t *testing.T) {
	for _, test := range []struct {
		decision       ai.Decision
		wantScore      string
		wantConfidence string
		wantAction     string
	}{
		{ai.Decision{Classification: "legitimate", Score: 0.8, Reasons: []string{"test"}}, "0.8", "high", "accepted"},
		{ai.Decision{Classification: "unwanted", Score: 1, Reasons: []string{"test"}}, "1", "high", "accepted-accept-mode"},
	} {
		t.Run(string(test.decision.Classification), func(t *testing.T) {
			server, conn, done := testServer(t, fixedAnalyzer{decision: test.decision})
			setTestMode(server, "accept")
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
			expectFrame(t, conn, string(addHeaderResponse(classificationHeader, string(test.decision.Classification))))
			expectFrame(t, conn, string(addHeaderResponse(scoreHeader, test.wantScore)))
			expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, test.wantConfidence)))
			expectFrame(t, conn, string(addHeaderResponse(actionHeader, test.wantAction)))
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
