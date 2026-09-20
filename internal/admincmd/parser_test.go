package admincmd

import (
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

func TestCommandAuthorizationAndCanonicalization(t *testing.T) {
	p := New(Dependencies{})
	user := Actor{DefaultRecipient: "Phil <phil@example.com>"}
	admin := Actor{Administrator: true, DefaultRecipient: "phil@example.com"}
	for _, line := range []string{"WHITELIST DELETE news@example.net *", "REJECTIONS *", "WHITELIST LIST *", "IP LIST"} {
		if _, err := p.Parse(line, user); err == nil {
			t.Errorf("ordinary user could issue %q", line)
		}
	}
	tests := map[string]string{
		"REJECTIONS":                          "REJECTIONS week",
		"REJECTIONS * year":                   "REJECTIONS * year",
		"WHITELIST LIST * month":              "WHITELIST LIST * month",
		"IP LIST LOOKUP all":                  "IP LIST LOOKUP all",
		"IP ADD ::ffff:192.0.2.10":            "IP ADD 192.0.2.10",
		"WHITELIST DELETE news@example.net *": "WHITELIST DELETE news@example.net *",
	}
	for line, want := range tests {
		command, err := p.Parse(line, admin)
		if err != nil || command.Canonical() != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", line, command.Canonical(), err, want)
		}
	}
	for _, line := range []string{"REJECTION", "REJECTION 0", "IP ADD invalid", "IP LIST fortnight", "WHITELIST LIST * month extra"} {
		if _, err := p.Parse(line, admin); err == nil {
			t.Errorf("invalid command %q accepted", line)
		}
	}
}

func TestTerminalWhitelistAddExplainsMissingRecipient(t *testing.T) {
	p := New(Dependencies{})
	_, err := p.Parse("WHITELIST ADD a@b.com", Actor{Administrator: true, DefaultRecipient: "*"})
	if err == nil || err.Error() != "WHITELIST ADD requires an explicit local recipient" {
		t.Fatalf("error = %v", err)
	}
}

func TestPeriodCutoffs(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		p    period
		want time.Time
	}{
		{periodDay, now.Add(-24 * time.Hour)}, {periodWeek, now.Add(-7 * 24 * time.Hour)},
		{periodMonth, now.AddDate(0, -1, 0)}, {periodYear, now.AddDate(-1, 0, 0)}, {periodAll, time.Time{}},
	}
	for _, test := range tests {
		if got := test.p.cutoff(now); !got.Equal(test.want) {
			t.Errorf("%s cutoff=%v, want %v", test.p, got, test.want)
		}
	}
}

func TestFormattingBoundsAndAudience(t *testing.T) {
	entries := []stores.Correspondent{{Correspondent: "news@example.net", LocalAddress: "phil@example.com", WhitelistType: stores.CorrespondentKindRepeatedLegitimateInbound}}
	if got := formatAllowlist(entries, false, false); strings.Contains(got, "Recipient:") {
		t.Fatalf("ordinary output exposes recipient: %s", got)
	}
	if got := formatAllowlist(entries, true, false); !strings.Contains(got, "Recipient: phil@example.com") {
		t.Fatalf("admin output omits recipient: %s", got)
	}
	many := make([]stores.Correspondent, MaxListRows+1)
	for i := range many {
		many[i] = stores.Correspondent{Correspondent: "sender@example.net", WhitelistType: stores.CorrespondentKindManual}
	}
	if got := formatAllowlist(many, false, false); !strings.Contains(got, listTruncatedNotice) {
		t.Fatal("row truncation was not reported")
	}
	if !strings.Contains(Help(true), "REJECTIONS * year") || strings.Contains(Help(false), "REJECTIONS * year") {
		t.Fatal("administrator help audience is incorrect")
	}
}
