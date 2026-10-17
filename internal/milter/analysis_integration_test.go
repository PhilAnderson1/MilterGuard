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
	"net/netip"
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

func TestIncompleteBodyRejectSkipsAIAndRespectsMode(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		selected action
	}{{"enforce", actionReject}, {"accept", actionAccept}} {
		t.Run(tc.mode, func(t *testing.T) {
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
				Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 8,
				IncompleteBodyAction: "reject", VisionMode: "off",
			}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			msg := message.New(1024)
			msg.AddHeader("Content-Type", "text/plain")
			msg.AddBody([]byte(strings.Repeat("evidence ", 20)))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, tc.mode, .9, "accept", false)
			if result.proposed != actionReject || result.selected != tc.selected || analyzer.calls.Load() != 0 {
				t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
			}
		})
	}
}

func TestHTMLCPUProtectionSkipsAIAndRespectsMode(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		selected action
	}{{"enforce", actionReject}, {"accept", actionAccept}} {
		t.Run(tc.mode, func(t *testing.T) {
			const rejectMessage = "HTML CPU limit exceeded"
			analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
			readings := []time.Duration{time.Second, 2*time.Second + time.Millisecond, 2*time.Second + time.Millisecond, 2*time.Second + time.Millisecond}
			reading := 0
			service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
				Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
				MaxHTMLParseCPUMilliseconds: 1000, HTMLParseCPULimitAction: "dos-reject", HTMLDoSRejectMessage: rejectMessage, VisionMode: "off",
			}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			service.threadCPUTime = func() (time.Duration, bool) {
				value := readings[min(reading, len(readings)-1)]
				reading++
				return value, true
			}
			msg := message.New(1024)
			msg.AddHeader("Content-Type", "text/html")
			msg.AddBody([]byte("<p>ordinary message</p>"))
			result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, tc.mode, .9, "accept", false)
			if result.proposed != actionReject || result.selected != tc.selected ||
				result.classification != ai.ClassificationUnwanted || !result.htmlCPUExceeded ||
				result.htmlCPUTime != time.Second+time.Millisecond || result.rejectMessage != rejectMessage ||
				analyzer.calls.Load() != 0 {
				t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
			}
		})
	}
}

func TestHTMLCPULimitFallbackContinuesAIWithBoundedExtraction(t *testing.T) {
	analyzer := &recordingAnalyzer{inputs: make(chan ai.Input, 1)}
	readings := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second}
	reading := 0
	service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
		Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 4096,
		MaxHTMLParseCPUMilliseconds: 250, HTMLParseCPULimitAction: "fallback", VisionMode: "off",
	}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	service.threadCPUTime = func() (time.Duration, bool) {
		value := readings[min(reading, len(readings)-1)]
		reading++
		return value, true
	}
	msg := message.New(4096)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte(`<p style="display:none">hidden</p><p>ordinary message</p>`))
	result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
	if result.selected != actionAccept || !result.htmlCPUExceeded || result.htmlCPUAction != "fallback" {
		t.Fatalf("result=%+v", result)
	}
	input := <-analyzer.inputs
	if !strings.Contains(input.Text, "HTML/CSS visibility analysis unavailable") || strings.Contains(input.Text, `<invisible`) {
		t.Fatalf("fallback AI input = %q", input.Text)
	}
}

func TestHTMLCPULimitRejectStopsLexicalFallback(t *testing.T) {
	readings := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second}
	reading := 0
	service := &analysisService{ai: config.AIConfig{
		MaxBodyChars: 4096, MaxHTMLParseCPUMilliseconds: 250,
		HTMLParseCPULimitAction: "dos-reject", VisionMode: "off",
	}}
	service.threadCPUTime = func() (time.Duration, bool) {
		value := readings[min(reading, len(readings)-1)]
		reading++
		return value, true
	}
	msg := message.New(4096)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte(`<p style="display:none">hidden</p><p>ordinary message</p>`))

	prepared, _, measured, exceeded := service.buildAnalysis(context.Background(), msg, message.AnalysisContext{})
	if !measured || !exceeded || !prepared.BodyExtractionIncomplete || !prepared.HTMLCPULimitExceeded {
		t.Fatalf("prepared=%+v measured=%t exceeded=%t", prepared, measured, exceeded)
	}
	if strings.Contains(prepared.Prompt, "ordinary message") {
		t.Fatalf("CPU-rejected analysis retained lexical fallback: %q", prepared.Prompt)
	}
}

func TestHTMLCPULimitFallbackRetainsCompletedMultipartAnalysis(t *testing.T) {
	newService := func() *analysisService {
		return &analysisService{ai: config.AIConfig{
			MaxBodyChars: 4096, MaxHTMLParseCPUMilliseconds: 250,
			HTMLParseCPULimitAction: "fallback", VisionMode: "off",
		}}
	}
	msg := message.New(8192)
	msg.AddHeader("Content-Type", `multipart/mixed; boundary="late-limit"`)
	msg.AddBody([]byte("--late-limit\r\nContent-Type: text/plain\r\n\r\nplain evidence\r\n" +
		"--late-limit\r\nContent-Type: text/html\r\n\r\n<p>HTML evidence</p>\r\n" +
		"--late-limit--\r\n"))

	// First count the deterministic clock samples for a completed extraction.
	baselineCalls := 0
	baseline := newService()
	baseline.threadCPUTime = func() (time.Duration, bool) {
		baselineCalls++
		return time.Second, true
	}
	_, _, measured, exceeded := baseline.buildAnalysis(context.Background(), msg, message.AnalysisContext{})
	if !measured || exceeded || baselineCalls < 2 {
		t.Fatalf("baseline clock: measured=%v exceeded=%v calls=%d", measured, exceeded, baselineCalls)
	}

	// Cross the limit only at the final, post-extraction clock sample. The
	// already completed analysis must be retained rather than rebuilt.
	calls := 0
	service := newService()
	service.threadCPUTime = func() (time.Duration, bool) {
		calls++
		if calls == baselineCalls {
			return time.Second + 251*time.Millisecond, true
		}
		return time.Second, true
	}
	prepared, duration, measured, exceeded := service.buildAnalysis(context.Background(), msg, message.AnalysisContext{})
	if !measured || !exceeded || duration != 251*time.Millisecond || calls != baselineCalls {
		t.Fatalf("late limit: measured=%v exceeded=%v duration=%v calls=%d want calls=%d",
			measured, exceeded, duration, calls, baselineCalls)
	}
	if prepared.BodyExtractionIncomplete || !prepared.HasHTML ||
		!strings.Contains(prepared.Prompt, "plain evidence") || !strings.Contains(prepared.Prompt, "HTML evidence") {
		t.Fatalf("completed multipart analysis was not retained: %+v", prepared)
	}
}

func TestHTMLCPULimitRejectIsNotDoSActivity(t *testing.T) {
	repository := &recordingActivity{}
	service := &activityService{repository: repository}
	service.recordScan(context.Background(), evaluationResult{
		selected: actionReject, htmlCPUExceeded: true, htmlCPUAction: "reject",
	}, nil)
	if len(repository.events) != 1 || repository.events[0].EventType != stores.ActivityEventHTMLLimit {
		t.Fatalf("activity events = %+v", repository.events)
	}
}

func TestHTMLCPULimitRejectSkipsAIWithoutDoSMessage(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: ai.ClassificationLegitimate, Score: 1}}
	readings := []time.Duration{time.Second, 2 * time.Second, 2 * time.Second}
	reading := 0
	service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
		Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
		MaxHTMLParseCPUMilliseconds: 250, HTMLParseCPULimitAction: "reject",
		HTMLDoSRejectMessage: "must not be used", VisionMode: "off",
	}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	service.threadCPUTime = func() (time.Duration, bool) {
		value := readings[min(reading, len(readings)-1)]
		reading++
		return value, true
	}
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte("<p>ordinary message</p>"))
	result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
	if result.selected != actionReject || result.htmlCPUAction != "reject" || !result.htmlCPUExceeded ||
		result.classification != "" || result.rejectMessage != "" || analyzer.calls.Load() != 0 {
		t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
	}
}

func TestHTMLCPULimitRejectDoesNotAddIPReputationStrike(t *testing.T) {
	repository := &recordingIPReputationRepository{}
	policy := &messagePolicyService{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), rejectionHistory: &recordingRejectionHistory{},
		ipReputation: &ipReputationStore{repository: repository, enabledFeature: true},
	}
	policy.applyPostDecisionUpdates(context.Background(), messageContext{
		message: message.New(1024), peerIP: netip.MustParseAddr("192.0.2.10"),
	}, evaluationResult{
		selected: actionReject, htmlCPUExceeded: true, htmlCPUAction: "reject",
	}, inboundEvidence{}, .9)
	if got := repository.rejections.Load(); got != 0 {
		t.Fatalf("IP reputation strikes = %d, want 0", got)
	}
}

func TestContentCPUProtectionRejectsOverBudgetPlainText(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	reading := 0
	service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
		Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
		MaxHTMLParseCPUMilliseconds: 1, VisionMode: "off",
	}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	service.threadCPUTime = func() (time.Duration, bool) {
		reading++
		return time.Duration(reading) * time.Second, true
	}
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/plain")
	msg.AddBody([]byte("ordinary message"))
	result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
	if result.selected != actionReject || !result.htmlCPUExceeded || analyzer.calls.Load() != 0 {
		t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
	}
}

func TestHTMLCPUProtectionCanBeDisabled(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
		Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
		MaxHTMLParseCPUMilliseconds: 0, VisionMode: "off",
	}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	service.threadCPUTime = func() (time.Duration, bool) {
		panic("disabled CPU protection read the thread clock")
	}
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte("<p>ordinary message</p>"))
	result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
	if result.selected != actionAccept || result.htmlCPUExceeded || analyzer.calls.Load() != 1 {
		t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
	}
}

func TestContentPreparationObservesCancellationWithCPUProtectionDisabled(t *testing.T) {
	service := &analysisService{ai: config.AIConfig{
		MaxBodyChars: 1024, MaxHTMLParseCPUMilliseconds: 0, VisionMode: "off",
	}}
	service.threadCPUTime = func() (time.Duration, bool) {
		panic("disabled CPU protection read the thread clock")
	}
	msg := message.New(16 << 10)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte(`<p>` + strings.Repeat("ordinary message ", 512) + `</p>`))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prepared, _, measured, exceeded := service.buildAnalysis(ctx, msg, message.AnalysisContext{})
	if measured || exceeded {
		t.Fatalf("CPU result measured=%t exceeded=%t, want context cancellation only", measured, exceeded)
	}
	if !prepared.HTMLCPULimitExceeded {
		t.Fatal("content preparation did not observe context cancellation")
	}
}

func TestCancelledAnalysisDoesNotCallAnalyzer(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	service := &analysisService{analyzer: analyzer, ai: config.AIConfig{
		Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024,
		MaxHTMLParseCPUMilliseconds: 250, VisionMode: "off",
	}, slots: make(chan struct{}, 1), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	msg := message.New(1024)
	msg.AddHeader("Content-Type", "text/html")
	msg.AddBody([]byte("<p>ordinary message</p>"))

	result := service.evaluate(ctx, msg, message.AnalysisContext{}, "enforce", .9, "accept", false)
	if !errors.Is(result.err, context.Canceled) || analyzer.calls.Load() != 0 {
		t.Fatalf("result=%+v analyzer calls=%d", result, analyzer.calls.Load())
	}
}

func TestHTMLCPUProtectionRecordsDistinctActivity(t *testing.T) {
	repository := &recordingActivity{}
	service := &activityService{repository: repository}
	service.recordScan(context.Background(), evaluationResult{
		selected: actionReject, htmlCPUExceeded: true, htmlCPUAction: "dos-reject",
	}, nil)
	if len(repository.events) != 1 || repository.events[0].EventType != stores.ActivityEventHTMLDoS ||
		repository.events[0].Outcome != stores.ActivityOutcomeRejected {
		t.Fatalf("activity events = %+v", repository.events)
	}
}

func TestHTMLCPUProtectionAppearsInRejectionHistory(t *testing.T) {
	history := &recordingRejectionHistory{}
	policy := &messagePolicyService{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), rejectionHistory: history,
	}
	msg := message.New(1024)
	msg.AddHeader("Subject", "resource exhaustion")
	policy.applyPostDecisionUpdates(context.Background(), messageContext{
		message: msg, authenticated: true, envelopeRecipients: []string{"recipient@example.com"},
	}, evaluationResult{
		selected: actionReject, classification: ai.ClassificationUnwanted,
		reasons: []string{"Message content processing exceeded the configured CPU-time limit"}, htmlCPUExceeded: true, htmlCPUAction: "dos-reject",
	}, inboundEvidence{}, .9)
	if len(history.inputs) != 1 || len(history.inputs[0].Reasons) != 1 ||
		history.inputs[0].Reasons[0] != "Message content processing exceeded the configured CPU-time limit" {
		t.Fatalf("rejection history inputs = %+v", history.inputs)
	}
}

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

func TestAuthenticationTransactionMarksMalformedFromInvalid(t *testing.T) {
	verifier := &recordingVerifier{observations: make(chan authenticationObservation, 1)}
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
		envelopeFrame(commandMail, "bounce@example.net"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame("From", "malformed sender identity"),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("body")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}

	transaction := (<-verifier.observations).transaction
	if !transaction.VisibleFromInvalid || transaction.VisibleFromDomain != "" {
		t.Fatalf("authentication transaction = %#v", transaction)
	}
	<-analyzer.inputs
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
