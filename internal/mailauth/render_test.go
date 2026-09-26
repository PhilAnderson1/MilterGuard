package mailauth

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderAuthenticationResultsRoundTrip(t *testing.T) {
	evidence := Evidence{
		VisibleDomain: "shop.example.com",
		Results: []Result{
			{Method: MethodSPF, Outcome: OutcomePass, Domain: "bounce.example.com", SPFIdentity: "mailfrom"},
			{Method: MethodDKIM, Outcome: OutcomePass, Domain: "mail.example.com", Selector: "selector1", Algorithm: "RSA-SHA256"},
			{Method: MethodDKIM, Outcome: OutcomePolicy, Domain: "bulk.example.net", Selector: "limited", Algorithm: "rsa-sha256", BodyLengthLimited: true, BodyLength: 12},
			{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDomain: "example.com", PolicyDisposition: "reject", SubdomainPolicy: "quarantine", PolicyApplied: true},
		},
	}
	value, err := RenderAuthenticationResults("MX.EXAMPLE.", evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mx.example;\r\n\tspf=pass smtp.mailfrom=bounce.example.com",
		"dkim=pass header.d=mail.example.com header.s=selector1",
		"header.a=rsa-sha256",
		"dkim=policy header.d=bulk.example.net header.s=limited",
		"dmarc=fail header.from=shop.example.com policy.dmarc=quarantine",
	} {
		if !strings.Contains(value, want) {
			t.Errorf("rendered value lacks %q:\n%q", want, value)
		}
	}

	parsed := Parse(Input{AuthenticationResults: []string{value}, TrustedAuthservIDs: []string{"mx.example"}})
	if len(parsed) != 4 {
		t.Fatalf("parsed rendered results = %#v", parsed)
	}
	if parsed[0].Method != MethodSPF || parsed[0].Domain != "bounce.example.com" ||
		parsed[1].Method != MethodDKIM || parsed[1].Outcome != OutcomePass || parsed[1].Domain != "mail.example.com" ||
		parsed[2].Method != MethodDKIM || parsed[2].Outcome != OutcomePolicy || parsed[2].Domain != "bulk.example.net" ||
		parsed[3].Method != MethodDMARC || parsed[3].Domain != "shop.example.com" {
		t.Fatalf("parsed rendered results = %#v", parsed)
	}
	assertSafeFolding(t, value)
}

func TestRenderAuthenticationResultsNone(t *testing.T) {
	value, err := RenderAuthenticationResults("mx.example", Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	if value != "mx.example; none" {
		t.Fatalf("rendered value = %q", value)
	}
	if parsed := Parse(Input{AuthenticationResults: []string{value}, TrustedAuthservIDs: []string{"mx.example"}}); len(parsed) != 0 {
		t.Fatalf("parsed none result = %#v", parsed)
	}
}

func TestRenderAuthenticationResultsRejectsInvalidAuthservID(t *testing.T) {
	for _, authservID := range []string{"", "mx example", "mx.example\r\nBcc: victim@example.net", "hé.example"} {
		if _, err := RenderAuthenticationResults(authservID, Evidence{}); !errors.Is(err, ErrInvalidAuthservID) {
			t.Errorf("RenderAuthenticationResults(%q) error = %v", authservID, err)
		}
	}
}

func TestRenderAuthenticationResultsOmitsUnsafePropertiesAndReasons(t *testing.T) {
	evidence := Evidence{VisibleDomain: "example.com\r\nBcc: victim@example.net", Results: []Result{
		{Method: MethodSPF, Outcome: OutcomePass, Domain: "example.com", SPFIdentity: "helo\r\nX: y", Reason: "attacker; dkim=pass"},
		{Method: MethodDKIM, Outcome: OutcomeFail, Domain: "example.com", Selector: "bad\r\nX: y", Algorithm: "rsa-sha256\r\nX: y", Reason: "attacker-controlled\r\nBcc: victim@example.net"},
		{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDisposition: "reject\r\nX: y", PolicyApplied: true},
	}}
	value, err := RenderAuthenticationResults("mx.example", evidence)
	if err != nil {
		t.Fatal(err)
	}
	unfolded := strings.ReplaceAll(value, "\r\n\t", " ")
	if strings.ContainsAny(unfolded, "\r\n") || strings.Contains(unfolded, "attacker") || strings.Contains(unfolded, "Bcc:") || strings.Contains(unfolded, "X:") {
		t.Fatalf("unsafe value entered result header: %q", value)
	}
	if strings.Contains(value, "smtp.") || strings.Contains(value, "header.s=") || strings.Contains(value, "header.a=") || strings.Contains(value, "header.from=") || strings.Contains(value, "policy.dmarc=") {
		t.Fatalf("unsafe properties were not omitted: %q", value)
	}
	assertSafeFolding(t, value)
}

func TestRenderAuthenticationResultsSelectsRegisteredOutcomes(t *testing.T) {
	evidence := Evidence{Results: []Result{
		{Method: MethodSPF, Outcome: OutcomePolicy},
		{Method: MethodDKIM, Outcome: OutcomeSoftfail},
		{Method: MethodDMARC, Outcome: OutcomeNeutral},
		{Method: Method("arc"), Outcome: OutcomePass},
	}}
	value, err := RenderAuthenticationResults("mx.example", evidence)
	if err != nil {
		t.Fatal(err)
	}
	if value != "mx.example; none" {
		t.Fatalf("rendered value = %q", value)
	}
}

func TestRenderAuthenticationResultsDMARCPolicy(t *testing.T) {
	tests := []struct {
		name       string
		visible    string
		result     Result
		wantPolicy string
		omitPolicy bool
	}{
		{name: "published policy", visible: "example.com", result: Result{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDomain: "example.com", PolicyDisposition: "reject", PolicyApplied: true}, wantPolicy: "reject"},
		{name: "subdomain policy", visible: "sub.example.com", result: Result{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDomain: "example.com", PolicyDisposition: "reject", SubdomainPolicy: "quarantine", PolicyApplied: true}, wantPolicy: "quarantine"},
		{name: "sampled out", visible: "example.com", result: Result{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDomain: "example.com", PolicyDisposition: "reject", PolicyApplied: false}, wantPolicy: "none"},
		{name: "missing policy", visible: "example.com", result: Result{Method: MethodDMARC, Outcome: OutcomeFail, PolicyDomain: "example.com", PolicyApplied: false}, omitPolicy: true},
		{name: "passing result has no disposition", visible: "example.com", result: Result{Method: MethodDMARC, Outcome: OutcomePass, PolicyDomain: "example.com", PolicyDisposition: "reject", PolicyApplied: true}, omitPolicy: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value, err := RenderAuthenticationResults("mx.example", Evidence{VisibleDomain: test.visible, Results: []Result{test.result}})
			if err != nil {
				t.Fatal(err)
			}
			if test.omitPolicy {
				if strings.Contains(value, "policy.dmarc=") {
					t.Fatalf("unexpected applied policy: %q", value)
				}
			} else if !strings.Contains(value, "policy.dmarc="+test.wantPolicy) {
				t.Fatalf("rendered value = %q", value)
			}
		})
	}
}

func TestRenderAuthenticationResultsCapsDKIMResults(t *testing.T) {
	results := make([]Result, maxRenderedDKIMResults+5)
	for index := range results {
		results[index] = Result{Method: MethodDKIM, Outcome: OutcomeFail, Domain: "example.com"}
	}
	value, err := RenderAuthenticationResults("mx.example", Evidence{Results: results})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(value, "dkim=fail"); got != maxRenderedDKIMResults {
		t.Fatalf("rendered DKIM results = %d", got)
	}
}

func assertSafeFolding(t *testing.T, value string) {
	t.Helper()
	withoutFolds := strings.ReplaceAll(value, "\r\n\t", "")
	if strings.ContainsAny(withoutFolds, "\r\n") || strings.ContainsRune(value, '\x00') {
		t.Fatalf("invalid header folding: %q", value)
	}
	for _, line := range strings.Split("Authentication-Results: "+value, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("header line has %d bytes: %q", len(line), line)
		}
	}
}
