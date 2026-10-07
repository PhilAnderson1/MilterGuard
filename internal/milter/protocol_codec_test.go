package milter

import (
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

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
