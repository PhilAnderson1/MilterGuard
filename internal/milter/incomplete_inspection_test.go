package milter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type inspectionLearningSpy struct {
	stores.CorrespondentPolicyRepository
	calls int
}

func (s *inspectionLearningSpy) RecordInboundClassification(context.Context, stores.InboundClassification) error {
	s.calls++
	return nil
}

func TestIncompleteInspectionRejectIsNotAIVerdict(t *testing.T) {
	for _, policy := range []string{"scan", "reject"} {
		for _, mode := range []string{"accept", "enforce"} {
			t.Run(policy+"/"+mode, func(t *testing.T) {
				analyzer := &countingAnalyzer{decision: ai.Decision{Classification: ai.ClassificationLegitimate, Score: .9}}
				service := &analysisService{analyzer: analyzer, ai: config.AIConfig{Timeout: config.Duration(time.Second), MaxBodyChars: 8, IncompleteBodyAction: policy, VisionMode: "off"}, slots: make(chan struct{}, 1)}
				msg := message.New(1024)
				msg.AddBody([]byte("longer than eight characters"))
				result := service.evaluate(context.Background(), msg, message.AnalysisContext{}, mode, .8, "accept", false)
				if policy == "scan" {
					if result.incompleteInspection || analyzer.calls.Load() != 1 || result.classification != ai.ClassificationLegitimate || result.score != .9 || result.selected != actionAccept {
						t.Fatalf("scan changed: %+v", result)
					}
					return
				}
				if !result.incompleteInspection || result.classification != "" || result.score != 0 || analyzer.calls.Load() != 0 || result.rejectMessage != incompleteInspectionRejectMessage || result.proposed != actionReject {
					t.Fatalf("policy result: %+v", result)
				}
				if result.selected != selectActionForMode(actionReject, mode) {
					t.Fatalf("wrong action: %+v", result)
				}
			})
		}
	}
}

func TestIncompleteInspectionPreservesHistoryWithoutReputationOrLearning(t *testing.T) {
	for _, resourceFallback := range []bool{false, true} {
		history := &recordingRejectionHistory{}
		ips := &recordingIPReputationRepository{}
		correspondents := &inspectionLearningSpy{}
		policy := &messagePolicyService{log: slog.New(slog.NewTextHandler(io.Discard, nil)), rejectionHistory: history, correspondents: correspondents, ipReputation: &ipReputationStore{repository: ips, enabledFeature: true}}
		result := evaluationResult{incompleteInspection: true, selected: actionReject, reasons: []string{"message body extraction was incomplete"}, htmlMemoryExceeded: resourceFallback, htmlCPUAction: "fallback"}
		policy.applyPostDecisionUpdates(context.Background(), messageContext{message: message.New(1024), visibleSender: "sender@example.org", envelopeRecipients: []string{"recipient@example.net"}, peerIP: netip.MustParseAddr("192.0.2.10")}, result, inboundEvidence{}, .8)
		if len(history.inputs) != 1 || history.inputs[0].Reasons[0] != result.reasons[0] {
			t.Fatalf("history=%+v", history.inputs)
		}
		if ips.rejections.Load() != 0 || correspondents.calls != 0 {
			t.Fatalf("reputation=%d learning=%d", ips.rejections.Load(), correspondents.calls)
		}
	}
}

func TestIncompleteInspectionHeadersAndSMTPReply(t *testing.T) {
	for _, mode := range []string{"accept", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			analyzer := &countingAnalyzer{}
			server, conn, done := testServer(t, analyzer)
			setTestMode(server, mode)
			setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
			server.sessions.analysis.ai.IncompleteBodyAction = "reject"
			server.sessions.analysis.ai.MaxBodyChars = 8
			defer func() { _ = conn.Close(); <-done }()
			negotiateWithActions(t, conn, resultHeaderActions)
			sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"), envelopeFrame(commandMail, "sender@example.org"), envelopeFrame(commandRecipient, "recipient@example.net"), headerFrame("From", "sender@example.org"), headerFrame(scoreHeader, "1"), headerFrame(policyHeader, "forged"), []byte{commandEndHeaders}, append([]byte{commandBody}, []byte("longer than eight characters")...))
			if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
				t.Fatal(err)
			}
			if mode == "enforce" {
				expectFrame(t, conn, "y550 5.7.1 "+incompleteInspectionRejectMessage+"\x00")
			} else {
				expectFrame(t, conn, string(deleteHeaderResponse(scoreHeader)))
				expectFrame(t, conn, string(deleteHeaderResponse(policyHeader)))
				expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "not-scanned")))
				expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
				expectFrame(t, conn, string(addHeaderResponse(actionHeader, acceptModeAction)))
				expectFrame(t, conn, string(addHeaderResponse(policyHeader, incompleteInspectionPolicy)))
				expectFrame(t, conn, string([]byte{responseAccept}))
			}
			if analyzer.calls.Load() != 0 {
				t.Fatal("AI called")
			}
		})
	}
}

func TestIncompleteInspectionLogsAndActivityArePolicyDecisions(t *testing.T) {
	var output bytes.Buffer
	service := &analysisService{log: slog.New(slog.NewJSONHandler(&output, nil))}
	result := evaluationResult{incompleteInspection: true, selected: actionReject, proposed: actionReject}
	service.logOutcome(context.Background(), message.New(1024), result, "enforce", false, true, nil)
	var entry map[string]any
	if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["policy"] != incompleteInspectionPolicy || !strings.Contains(entry["msg"].(string), "policy decision") {
		t.Fatalf("log=%v", entry)
	}
	for _, key := range []string{"classification", "score", "model"} {
		if _, ok := entry[key]; ok {
			t.Errorf("unexpected %s in policy log", key)
		}
	}
	for _, selected := range []action{actionAccept, actionReject} {
		repository := &recordingActivity{}
		result.selected = selected
		(&activityService{repository: repository}).recordScan(context.Background(), result, nil)
		if len(repository.events) != 1 || repository.events[0].EventType != stores.ActivityEventIncompleteInspection || repository.events[0].Outcome != activityOutcome(selected, nil) {
			t.Fatalf("events=%+v", repository.events)
		}
	}
}
