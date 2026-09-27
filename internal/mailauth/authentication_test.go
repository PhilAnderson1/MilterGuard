package mailauth

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAuthenticationResults(t *testing.T) {
	input := Input{
		AuthenticationResults: []string{
			`attacker.example; dkim=pass header.d=evil.example`,
			`NL.INVADES.NET.; dkim=pass header.d=mail.example.com header.i=@example.com; spf=pass smtp.mailfrom=<bounce@example.com>; dmarc=pass header.from=example.com`,
		},
		TrustedAuthservIDs: []string{"nl.invades.net"},
	}
	want := []Result{
		{Method: MethodDKIM, Outcome: "pass", Domain: "mail.example.com"},
		{Method: MethodSPF, Outcome: "pass", Domain: "example.com"},
		{Method: MethodDMARC, Outcome: "pass", Domain: "example.com"},
	}
	if got := Parse(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

func TestParseQuotedSemicolonDoesNotCreateMethod(t *testing.T) {
	input := Input{
		AuthenticationResults: []string{
			`mx.example; dkim=fail reason="bad; dmarc=pass header.from=example.com" header.d=example.com; dmarc=fail header.from=example.com`,
		},
		TrustedAuthservIDs: []string{"mx.example"},
	}
	want := []Result{
		{Method: MethodDKIM, Outcome: "fail", Domain: "example.com"},
		{Method: MethodDMARC, Outcome: "fail", Domain: "example.com"},
	}
	if got := Parse(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

func TestParseReceivedSPFFallback(t *testing.T) {
	base := Input{
		ReceivedSPF: []string{
			`pass (receiver=mx.example) receiver=forged.example; envelope-from="attacker@evil.example"`,
			`pass receiver="mx.example"; envelope-from=<sender@example.com>`,
		},
		TrustedAuthservIDs: []string{"mx.example"},
	}
	want := []Result{{Method: MethodSPF, Outcome: "pass", Domain: "example.com"}}
	if got := Parse(base); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}

	base.AuthenticationResults = []string{`mx.example; spf=neutral smtp.mailfrom=other.example`}
	want = []Result{{Method: MethodSPF, Outcome: "neutral", Domain: "other.example"}}
	if got := Parse(base); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() with Authentication-Results SPF = %#v, want %#v", got, want)
	}
}

func TestParseNormalizesOpenDMARCSPFTempfail(t *testing.T) {
	tests := []Input{
		{
			AuthenticationResults: []string{`mx.example; spf=tempfail smtp.mailfrom=sender@example.com`},
			TrustedAuthservIDs:    []string{"mx.example"},
		},
		{
			ReceivedSPF:        []string{`tempfail receiver=mx.example; envelope-from=sender@example.com`},
			TrustedAuthservIDs: []string{"mx.example"},
		},
	}
	for _, input := range tests {
		got := Parse(input)
		want := []Result{{Method: MethodSPF, Outcome: OutcomeTemperror, Domain: "example.com"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Parse() = %#v, want %#v", got, want)
		}
	}

	input := Input{
		AuthenticationResults: []string{`mx.example; dkim=tempfail header.d=example.com`},
		TrustedAuthservIDs:    []string{"mx.example"},
	}
	want := []Result{{Method: MethodDKIM, Outcome: "tempfail", Domain: "example.com"}}
	if got := Parse(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() changed non-SPF extension result: %#v, want %#v", got, want)
	}
}

func TestDomainNormalizationAndAlignment(t *testing.T) {
	if got := NormalizeDomain(" Mail.Example.COM. "); got != "mail.example.com" {
		t.Fatalf("NormalizeDomain() = %q", got)
	}
	for _, invalid := range []string{"", ".example.com", "-mail.example.com", "mail example.com"} {
		if got := NormalizeDomain(invalid); got != "" {
			t.Errorf("NormalizeDomain(%q) = %q, want empty", invalid, got)
		}
	}
	if !DomainAligned("mailer.example.co.uk", "news.example.co.uk") {
		t.Fatal("expected relaxed organizational-domain alignment")
	}
	if DomainAligned("example.net", "example.com") {
		t.Fatal("unexpected alignment")
	}
}

func TestParseRemovesDuplicateResults(t *testing.T) {
	input := Input{
		AuthenticationResults: []string{
			`mx.example; dkim=pass header.d=example.com`,
			`mx.example; dkim=pass header.d=example.com`,
		},
		TrustedAuthservIDs: []string{"mx.example"},
	}
	if got := Parse(input); len(got) != 1 {
		t.Fatalf("Parse() returned %d duplicate results: %#v", len(got), got)
	}
}

func TestHeaderVerifierProducesSharedAlignmentEvidence(t *testing.T) {
	verifier := HeaderVerifier{}
	evidence, err := verifier.Verify(t.Context(), Transaction{
		AuthenticationResults: []string{`mx.example; dkim=pass header.d=mail.example.com; spf=pass smtp.mailfrom=other.example; dmarc=pass header.from=example.com`},
		TrustedAuthservIDs:    []string{"mx.example"}, VisibleFromDomain: "news.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.DKIMAligned || !evidence.DMARCAligned || !evidence.AnyAligned() {
		t.Fatalf("alignment evidence = %#v", evidence)
	}
	if len(evidence.Results) != 3 || !evidence.Results[0].Aligned || evidence.Results[1].Aligned || !evidence.Results[2].Aligned {
		t.Fatalf("per-result alignment = %#v", evidence.Results)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`mx.example; dkim=pass header.d=example.com`, `pass receiver=mx.example; envelope-from=a@example.com`)
	f.Add(`mx.example; dkim=fail reason="bad; dmarc=pass"`, `neutral (comment) receiver="mx.example"`)
	f.Fuzz(func(t *testing.T, authenticationResults, receivedSPF string) {
		input := Input{
			AuthenticationResults: []string{authenticationResults},
			ReceivedSPF:           []string{receivedSPF},
			TrustedAuthservIDs:    []string{"mx.example"},
		}
		first := Parse(input)
		if second := Parse(input); !reflect.DeepEqual(first, second) {
			t.Fatalf("non-deterministic results: %#v != %#v", first, second)
		}
		for _, result := range first {
			if string(result.Outcome) != strings.ToLower(string(result.Outcome)) {
				t.Fatalf("outcome is not normalized: %q", result.Outcome)
			}
			if result.Domain != "" && NormalizeDomain(result.Domain) != result.Domain {
				t.Fatalf("domain is not normalized: %q", result.Domain)
			}
		}
		if got := Parse(Input{AuthenticationResults: []string{authenticationResults}, ReceivedSPF: []string{receivedSPF}}); len(got) != 0 {
			t.Fatalf("untrusted input returned results: %#v", got)
		}
	})
}

func FuzzReceivedSPF(f *testing.F) {
	f.Add(`pass receiver=mx.example; envelope-from=<sender@example.com>`)
	f.Add(`pass (receiver=mx.example) receiver=attacker.example`)
	f.Add(`pass client-ip=192.0.2.1; receiver="mx.example"`)
	f.Fuzz(func(t *testing.T, header string) {
		input := Input{ReceivedSPF: []string{header}, TrustedAuthservIDs: []string{"mx.example"}}
		first := Parse(input)
		if second := Parse(input); !reflect.DeepEqual(first, second) {
			t.Fatalf("non-deterministic results: %#v != %#v", first, second)
		}
	})
}

func FuzzNormalizeDomainAndAlignment(f *testing.F) {
	f.Add("mail.example.com", "example.com")
	f.Add("selector._domainkey.example.com", "example.com")
	f.Add("-invalid.example", "example.com")
	f.Fuzz(func(t *testing.T, authenticatedDomain, fromDomain string) {
		normalized := NormalizeDomain(authenticatedDomain)
		if normalized != "" && NormalizeDomain(normalized) != normalized {
			t.Fatalf("normalization is not idempotent: %q -> %q", authenticatedDomain, normalized)
		}
		first := DomainAligned(authenticatedDomain, fromDomain)
		if second := DomainAligned(authenticatedDomain, fromDomain); first != second {
			t.Fatal("alignment is non-deterministic")
		}
	})
}
