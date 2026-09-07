package milter

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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
			server := &Server{cfg: config.Config{Mode: test.mode, Filtering: config.FilteringConfig{RejectScore: 0.9}}}
			proposed, selected := server.applyPolicy(test.decision)
			if proposed != test.proposed || selected != test.selected {
				t.Fatalf("actions = (%s, %s), want (%s, %s)", proposed, selected, test.proposed, test.selected)
			}
		})
	}
}

func TestEncodeAction(t *testing.T) {
	server := &Server{cfg: config.Config{Filtering: config.FilteringConfig{RejectMessage: "blocked"}}}
	tests := []struct {
		action action
		want   string
	}{
		{actionAccept, "a"},
		{actionReject, "y550 5.7.1 blocked\x00"},
		{actionTempfail, "t"},
	}
	for _, test := range tests {
		if got := string(server.encodeAction(test.action)); got != test.want {
			t.Errorf("encodeAction(%s) = %q, want %q", test.action, got, test.want)
		}
	}
}

func TestLogOutcomeRecordsResponseDelivery(t *testing.T) {
	var output bytes.Buffer
	server := &Server{
		cfg: config.Config{Mode: "enforce", AI: config.AIConfig{Model: "test-model"}},
		log: slog.New(slog.NewJSONHandler(&output, nil)),
	}
	msg := message.New(1024)
	msg.AddHeader("Message-ID", "<test@example.invalid>")
	result := evaluationResult{
		proposed: actionReject, selected: actionReject,
		classification: "unwanted", score: 1, reasons: []string{"test"},
		latency: time.Millisecond,
	}
	server.logOutcome(context.Background(), msg, result, false, errors.New("write failed"))
	logLine := output.String()
	for _, wanted := range []string{`"actual_action":"reject"`, `"response_sent":false`, `"response_error":"write failed"`} {
		if !strings.Contains(logLine, wanted) {
			t.Errorf("log output does not contain %s: %s", wanted, logLine)
		}
	}
}
