package mailauth

import "testing"

func TestAuthenticationPropertyBoundaries(t *testing.T) {
	tests := []struct {
		name, clause, domain string
	}{
		{"DKIM identity decoy", `dkim=pass header.i=header.d=victim.example@attacker.example header.d=attacker.example`, "attacker.example"},
		{"DKIM quoted reason", `dkim=pass reason="header.d=victim.example" header.d=attacker.example`, "attacker.example"},
		{"DKIM quoted identity", `dkim=pass header.i="header.d=victim.example@attacker.example" header.d=attacker.example`, "attacker.example"},
		{"DKIM absent real property", `dkim=pass header.i=header.d=victim.example@attacker.example`, ""},
		{"DMARC embedded property", `dmarc=pass reason=header.from=victim.example header.from=attacker.example`, "attacker.example"},
		{"DMARC quoted property", `dmarc=pass reason="header.from=victim.example" header.from=attacker.example`, "attacker.example"},
		{"SPF embedded property", `spf=pass reason=smtp.mailfrom=victim.example smtp.mailfrom=sender@attacker.example`, "attacker.example"},
		{"SPF angle decoy", `spf=pass x.identity=<smtp.mailfrom=victim.example> smtp.helo=attacker.example`, "attacker.example"},
		{"quoted domain", `dkim=pass header.d="attacker.example"`, "attacker.example"},
		{"folded and spaced property", "DKIM = PASS\r\n\tHEADER . D = attacker.example", "attacker.example"},
		{"similar key", `dkim=pass x-header.d=victim.example header.d=attacker.example`, "attacker.example"},
		{"duplicate DKIM domain", `dkim=pass header.d=victim.example header.d=attacker.example`, ""},
		{"duplicate identical domain", `dkim=pass header.d=victim.example HEADER.D=victim.example`, ""},
		{"duplicate DMARC domain", `dmarc=pass header.from=victim.example header.from=attacker.example`, ""},
		{"duplicate SPF identity with HELO", `spf=pass smtp.mailfrom=victim.example smtp.mailfrom=attacker.example smtp.helo=victim.example`, ""},
		{"domain token is not a prefix", `dkim=pass header.d=victim.example@attacker.example`, ""},
		{"quoted value requires separator", `dkim=pass reason="ok"header.d=victim.example`, ""},
		{"angle value requires separator", `dkim=pass x.identity=<ok>header.d=victim.example`, ""},
		{"malformed trailing assignment", `dkim=pass header.d=victim.example header.d=`, ""},
		{"embedded quote", `dkim=pass x.identity=a" header.d=victim.example "`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Parse(Input{TrustedAuthservIDs: []string{"mx.example"}, AuthenticationResults: []string{"mx.example; " + tt.clause}})
			if len(results) != 1 || results[0].Domain != tt.domain {
				t.Fatalf("Parse() = %+v, want one result with domain %q", results, tt.domain)
			}
			if evidence := NewEvidence(results, "victim.example"); evidence.AnyAligned() {
				t.Fatalf("attacker-controlled property authenticated victim: %+v", evidence)
			}
		})
	}
}

func TestAmbiguousSPFPropertiesDoNotEnableReceivedSPFFallback(t *testing.T) {
	results := Parse(Input{
		TrustedAuthservIDs:    []string{"mx.example"},
		AuthenticationResults: []string{`mx.example; spf=pass smtp.mailfrom=victim.example smtp.mailfrom=attacker.example`},
		ReceivedSPF:           []string{`pass receiver=mx.example; envelope-from=sender@victim.example`},
	})
	if len(results) != 1 || results[0].Domain != "" || NewEvidence(results, "victim.example").AnyAligned() {
		t.Fatalf("ambiguous SPF clause activated fallback: %+v", results)
	}
}

func TestAuthenticationPropertiesAreScopedToEachMethod(t *testing.T) {
	results := Parse(Input{
		TrustedAuthservIDs:    []string{"mx.example"},
		AuthenticationResults: []string{`mx.example; dkim=pass header.d=attacker.example; dkim=pass header.d=victim.example; dmarc=pass header.from=victim.example`},
	})
	evidence := NewEvidence(results, "victim.example")
	if len(results) != 3 || !evidence.DKIMAligned || !evidence.DMARCAligned {
		t.Fatalf("independent method clauses lost valid evidence: %+v", evidence)
	}
}
