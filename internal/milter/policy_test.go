package milter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

func TestApplyPolicy(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		decision ai.Decision
		proposed action
		selected action
	}{
		{
			name:     "enforce rejects unwanted",
			mode:     "enforce",
			decision: ai.Decision{Classification: "unwanted", Score: 0.9},
			proposed: actionReject,
			selected: actionReject,
		},
		{
			name:     "monitor records rejection but accepts",
			mode:     "monitor",
			decision: ai.Decision{Classification: "unwanted", Score: 1},
			proposed: actionReject,
			selected: actionAccept,
		},
		{
			name:     "tag records rejection but accepts",
			mode:     "tag",
			decision: ai.Decision{Classification: "unwanted", Score: 1},
			proposed: actionReject,
			selected: actionAccept,
		},
		{
			name:     "high legitimate score is accepted",
			mode:     "enforce",
			decision: ai.Decision{Classification: "legitimate", Score: 1},
			proposed: actionAccept,
			selected: actionAccept,
		},
		{
			name:     "sub-threshold unwanted is accepted",
			mode:     "enforce",
			decision: ai.Decision{Classification: "unwanted", Score: 0.89},
			proposed: actionAccept,
			selected: actionAccept,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &analysisService{}
			proposed, selected := service.applyPolicy(test.decision, test.mode, 0.9)
			if proposed != test.proposed || selected != test.selected {
				t.Fatalf("actions = (%s, %s), want (%s, %s)", proposed, selected, test.proposed, test.selected)
			}
		})
	}
}

func TestEncodeAction(t *testing.T) {
	tests := []struct {
		action action
		want   string
	}{
		{actionAccept, "a"},
		{actionReject, "y550 5.7.1 blocked\x00"},
		{actionTempfail, "t"},
	}
	for _, test := range tests {
		if got := string(responseForAction(test.action, "blocked")); got != test.want {
			t.Errorf("responseForAction(%s) = %q, want %q", test.action, got, test.want)
		}
	}
}

func TestLogOutcomeRecordsResponseDelivery(t *testing.T) {
	var output bytes.Buffer
	service := &analysisService{
		ai:  config.AIConfig{Model: "test-model"},
		log: slog.New(slog.NewJSONHandler(&output, nil)),
	}
	msg := message.New(1024)
	msg.AddHeader("Message-ID", "<test@example.invalid>")
	result := evaluationResult{
		proposed: actionReject, selected: actionReject,
		classification: "unwanted", score: 1, reasons: []string{"test"},
		latency: time.Millisecond,
	}
	service.logOutcome(context.Background(), msg, result, "enforce", false, false, errors.New("write failed"))
	logLine := output.String()
	for _, wanted := range []string{`"actual_action":"reject"`, `"response_sent":false`, `"response_error":"write failed"`} {
		if !strings.Contains(logLine, wanted) {
			t.Errorf("log output does not contain %s: %s", wanted, logLine)
		}
	}
}

func TestFinishBypassedMessageSubjectLogging(t *testing.T) {
	tests := []struct {
		name           string
		includeSubject bool
		wantSubject    bool
	}{
		{name: "enabled", includeSubject: true, wantSubject: true},
		{name: "disabled", includeSubject: false, wantSubject: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, nil))
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			ss := newSession(&sessionDependencies{
				mode: "enforce", protocol: protocolOptions{maxMessageSize: 1024},
				filtering: config.FilteringConfig{RejectMessage: "blocked"},
				logging:   config.LoggingConfig{IncludeSubject: test.includeSubject},
				analysis:  &analysisService{},
				policy:    &messagePolicyService{},
				log:       logger,
			}, serverConn)
			ss.message.AddHeader("Message-ID", "<bypass@example.invalid>")
			ss.message.AddHeader("Subject", "Bypassed subject")

			done := make(chan bool, 1)
			go func() {
				done <- ss.finishBypassedMessage(context.Background(), "test_bypass", false, false)
			}()
			response, err := readFrame(clientConn)
			if err != nil {
				t.Fatalf("read bypass response: %v", err)
			}
			if len(response) != 1 || response[0] != responseAccept {
				t.Fatalf("bypass response = %q, want accept", response)
			}
			if !<-done {
				t.Fatal("finishBypassedMessage reported failure")
			}

			hasSubject := strings.Contains(output.String(), `"subject":"Bypassed subject"`)
			if hasSubject != test.wantSubject {
				t.Fatalf("subject present = %t, want %t; log: %s", hasSubject, test.wantSubject, output.String())
			}
		})
	}
}

func TestLogOutcomeIdentifiesPermanentEndpointFailures(t *testing.T) {
	tests := []struct {
		name       string
		kind       ai.ErrorKind
		statusCode int
		message    string
		kindName   string
	}{
		{name: "credentials", kind: ai.ErrorCredentials, statusCode: 401, message: "AI endpoint credentials rejected", kindName: "credentials"},
		{name: "credit", kind: ai.ErrorPaymentRequired, statusCode: 402, message: "AI endpoint credit unavailable", kindName: "insufficient_credit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			service := &analysisService{
				log: slog.New(slog.NewJSONHandler(&output, nil)),
			}
			msg := message.New(1024)
			msg.AddHeader("Message-ID", "<test@example.invalid>")
			service.logOutcome(context.Background(), msg, evaluationResult{
				selected: actionAccept,
				err: &ai.EndpointError{
					Kind: test.kind, StatusCode: test.statusCode,
					Err: errors.New("endpoint failure"),
				},
			}, "enforce", false, true, nil)
			logLine := output.String()
			for _, wanted := range []string{
				`"msg":"` + test.message + `"`,
				`"endpoint_error_kind":"` + test.kindName + `"`,
				`"endpoint_status_code":` + fmt.Sprint(test.statusCode),
			} {
				if !strings.Contains(logLine, wanted) {
					t.Errorf("log output does not contain %s: %s", wanted, logLine)
				}
			}
		})
	}
}
