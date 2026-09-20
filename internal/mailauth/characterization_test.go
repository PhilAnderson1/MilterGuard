package mailauth

import (
	"reflect"
	"testing"
)

func TestParseTrustSelection(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		trusted []string
		want    bool
	}{
		{name: "case insensitive with trailing dot", header: `MX.Example.; dkim=pass header.d=example.com`, trusted: []string{"mx.example"}, want: true},
		{name: "trusted value has trailing dot", header: `mx.example; dkim=pass header.d=example.com`, trusted: []string{"MX.EXAMPLE."}, want: true},
		{name: "untrusted", header: `attacker.example; dkim=pass header.d=example.com`, trusted: []string{"mx.example"}},
		{name: "missing authserv", header: `; dkim=pass header.d=example.com`, trusted: []string{"mx.example"}},
		{name: "missing delimiter", header: `mx.example dkim=pass header.d=example.com`, trusted: []string{"mx.example"}},
		{name: "empty trust set", header: `mx.example; dkim=pass header.d=example.com`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(Input{AuthenticationResults: []string{test.header}, TrustedAuthservIDs: test.trusted})
			if (len(got) > 0) != test.want {
				t.Fatalf("Parse() = %#v, want accepted=%v", got, test.want)
			}
		})
	}
}

func TestParseMethodAndPropertyVariations(t *testing.T) {
	tests := []struct {
		name   string
		clause string
		want   Result
	}{
		{name: "DKIM case and whitespace", clause: ` DKIM = PASS header.d=Mail.Example.COM.`, want: Result{Method: MethodDKIM, Outcome: "pass", Domain: "mail.example.com"}},
		{name: "SPF mailbox", clause: `spf=pass smtp.mailfrom=sender@example.com`, want: Result{Method: MethodSPF, Outcome: "pass", Domain: "example.com"}},
		{name: "SPF angle mailbox", clause: `spf=pass smtp.mailfrom=<sender@example.com>`, want: Result{Method: MethodSPF, Outcome: "pass", Domain: "example.com"}},
		{name: "SPF bare domain", clause: `spf=pass smtp.mailfrom=example.com`, want: Result{Method: MethodSPF, Outcome: "pass", Domain: "example.com"}},
		{name: "DMARC", clause: `dmarc=quarantine header.from=example.com`, want: Result{Method: MethodDMARC, Outcome: "quarantine", Domain: "example.com"}},
		{name: "missing property", clause: `dkim=pass`, want: Result{Method: MethodDKIM, Outcome: "pass"}},
		{name: "malformed property", clause: `dmarc=fail header.from=-example.com`, want: Result{Method: MethodDMARC, Outcome: "fail"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Parse(Input{AuthenticationResults: []string{"mx.example;" + test.clause}, TrustedAuthservIDs: []string{"mx.example"}})
			if !reflect.DeepEqual(got, []Result{test.want}) {
				t.Fatalf("Parse() = %#v, want %#v", got, []Result{test.want})
			}
		})
	}
}

func TestParseRejectsMethodLikeText(t *testing.T) {
	input := Input{
		AuthenticationResults: []string{
			`mx.example; x-dkim=pass header.d=example.com; reason="dmarc=pass header.from=example.com"; (spf=pass smtp.mailfrom=example.com); dkim=fail header.d=example.com`,
		},
		TrustedAuthservIDs: []string{"mx.example"},
	}
	want := []Result{{Method: MethodDKIM, Outcome: "fail", Domain: "example.com"}}
	if got := Parse(input); !reflect.DeepEqual(got, want) {
		t.Fatalf("Parse() = %#v, want %#v", got, want)
	}
}

func TestParseEscapedQuoteAndSemicolon(t *testing.T) {
	input := Input{
		AuthenticationResults: []string{
			`mx.example; dkim=fail reason="escaped \" quote; dmarc=pass header.from=example.com" header.d=example.com; dmarc=fail header.from=example.com`,
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

func TestDomainEdgeCases(t *testing.T) {
	if !DomainAligned("example.invalid", "example.invalid") {
		t.Fatal("expected exact fallback alignment")
	}
	if got := NormalizeDomain("selector._domainkey.example.com"); got != "selector._domainkey.example.com" {
		t.Fatalf("underscore normalization = %q", got)
	}
	if DomainAligned("com", "other.com") {
		t.Fatal("public suffix unexpectedly aligned")
	}
}
