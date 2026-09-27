package moxverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func TestSPFMechanismAndLimitMatrix(t *testing.T) {
	resolver := dns.MockResolver{
		TXT: map[string][]string{
			"include.test.":              {"v=spf1 include:included.test -all"},
			"included.test.":             {"v=spf1 ip4:192.0.2.1 -all"},
			"redirect.test.":             {"v=spf1 redirect=redirect-target.test"},
			"redirect-target.test.":      {"v=spf1 ip4:192.0.2.1 -all"},
			"a.test.":                    {"v=spf1 a -all"},
			"mx.test.":                   {"v=spf1 mx -all"},
			"exists.test.":               {"v=spf1 exists:present.exists.test -all"},
			"macro.test.":                {"v=spf1 exists:%{l}.macro-target.test -all"},
			"loop.test.":                 {"v=spf1 include:loop.test -all"},
			"void.test.":                 {"v=spf1 exists:void1.test exists:void2.test exists:void3.test -all"},
			"ipv6.test.":                 {"v=spf1 ip6:2001:db8::/64 -all"},
			"xn--bcher-kva.example.":     {"v=spf1 ip4:192.0.2.1 -all"},
			"neutral.test.":              {"v=spf1 ?all"},
			"softfail.test.":             {"v=spf1 ~all"},
			"fail.test.":                 {"v=spf1 -all"},
			"malformed.test.":            {"v=spf1 ip4:not-an-address"},
			"include-temperror.test.":    {"v=spf1 include:temporary.test -all"},
			"receiver-macro.test.":       {"v=spf1 exists:%{r}.receiver-target.test -all"},
			"local-ip-macro.test.":       {"v=spf1 exists:%{i}.local-ip-target.test -all"},
			"helo-domain-macro.test.":    {"v=spf1 exists:%{h}.helo-target.test -all"},
			"sender-domain-macro.test.":  {"v=spf1 exists:%{d}.sender-target.test -all"},
			"sender-reverse-macro.test.": {"v=spf1 exists:%{ir}.reverse-target.test -all"},
		},
		A: map[string][]string{
			"a.test.":                                      {"192.0.2.1"},
			"mail.mx.test.":                                {"192.0.2.1"},
			"present.exists.test.":                         {"203.0.113.10"},
			"alice.macro-target.test.":                     {"203.0.113.10"},
			"192.0.2.1.local-ip-target.test.":              {"203.0.113.10"},
			"mail.example.test.helo-target.test.":          {"203.0.113.10"},
			"sender-domain-macro.test.sender-target.test.": {"203.0.113.10"},
			"1.2.0.192.reverse-target.test.":               {"203.0.113.10"},
		},
		AAAA: map[string][]string{"ipv6.test.": {"2001:db8::1"}},
		MX:   map[string][]*net.MX{"mx.test.": {{Host: "mail.mx.test.", Pref: 10}}},
		Fail: []string{"txt temporary.test."},
	}
	verifier := newTestVerifier(t, resolver)
	tests := []struct {
		name       string
		sender     string
		remoteIP   string
		outcome    mailauth.Outcome
		category   mailauth.ErrorCategory
		wantDomain string
	}{
		{name: "include", sender: "alice@include.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "include.test"},
		{name: "redirect", sender: "alice@redirect.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "redirect.test"},
		{name: "a", sender: "alice@a.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "a.test"},
		{name: "mx", sender: "alice@mx.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "mx.test"},
		{name: "exists", sender: "alice@exists.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "exists.test"},
		{name: "localpart macro", sender: "alice@macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "macro.test"},
		{name: "invalid receiver macro context", sender: "alice@receiver-macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax, wantDomain: "receiver-macro.test"},
		{name: "remote IP macro", sender: "alice@local-ip-macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "local-ip-macro.test"},
		{name: "HELO macro", sender: "alice@helo-domain-macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "helo-domain-macro.test"},
		{name: "sender domain macro", sender: "alice@sender-domain-macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "sender-domain-macro.test"},
		{name: "reversed IP macro", sender: "alice@sender-reverse-macro.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "sender-reverse-macro.test"},
		{name: "IPv6", sender: "alice@ipv6.test", remoteIP: "2001:db8::1", outcome: mailauth.OutcomePass, wantDomain: "ipv6.test"},
		{name: "IDNA", sender: "alice@bücher.example", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePass, wantDomain: "xn--bcher-kva.example"},
		{name: "neutral", sender: "alice@neutral.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomeNeutral, wantDomain: "neutral.test"},
		{name: "softfail", sender: "alice@softfail.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomeSoftfail, wantDomain: "softfail.test"},
		{name: "fail", sender: "alice@fail.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomeFail, wantDomain: "fail.test"},
		{name: "none", sender: "alice@absent.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomeNone, wantDomain: "absent.test"},
		{name: "malformed", sender: "alice@malformed.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax, wantDomain: "malformed.test"},
		{name: "include temperror", sender: "alice@include-temperror.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomeTemperror, category: mailauth.ErrorDNS, wantDomain: "include-temperror.test"},
		{name: "lookup loop", sender: "alice@loop.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePermerror, category: mailauth.ErrorLimit, wantDomain: "loop.test"},
		{name: "void lookup limit", sender: "alice@void.test", remoteIP: "192.0.2.1", outcome: mailauth.OutcomePermerror, category: mailauth.ErrorLimit, wantDomain: "void.test"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction := testTransaction(nil)
			transaction.EnvelopeSender = test.sender
			transaction.RemoteIP = netip.MustParseAddr(test.remoteIP)
			result, _, _ := verifier.verifySPF(t.Context(), transaction)
			if result.Outcome != test.outcome || result.ErrorCategory != test.category || result.Domain != test.wantDomain {
				t.Fatalf("SPF result = %#v, want outcome=%s category=%s domain=%s", result, test.outcome, test.category, test.wantDomain)
			}
		})
	}
}

func TestDKIMCanonicalizationAndBodyFixtureMatrix(t *testing.T) {
	record := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	resolver := dns.MockResolver{TXT: map[string][]string{"probe._domainkey.example.test.": {record}}}
	verifier := newTestVerifier(t, resolver)

	t.Run("canonicalizations and repeated folded headers", func(t *testing.T) {
		evidence, err := verifier.Verify(t.Context(), testTransaction(readFixture(t, "signed-canonicalizations.eml")))
		if err != nil {
			t.Fatal(err)
		}
		want := [][2]string{{"simple", "simple"}, {"simple", "relaxed"}, {"relaxed", "simple"}, {"relaxed", "relaxed"}}
		for index, canonicalization := range want {
			result := resultFor(t, evidence, mailauth.MethodDKIM, index)
			if result.Outcome != mailauth.OutcomePass || result.HeaderCanonicalization != canonicalization[0] || result.BodyCanonicalization != canonicalization[1] {
				t.Fatalf("DKIM result %d = %#v, want %v", index, result, canonicalization)
			}
		}
	})

	for _, fixture := range []string{"signed-empty.eml", "signed-binary.eml"} {
		t.Run(fixture, func(t *testing.T) {
			evidence, err := verifier.Verify(t.Context(), testTransaction(readFixture(t, fixture)))
			if err != nil {
				t.Fatal(err)
			}
			if result := resultFor(t, evidence, mailauth.MethodDKIM, 0); result.Outcome != mailauth.OutcomePass {
				t.Fatalf("DKIM result = %#v", result)
			}
		})
	}
}

func TestDKIMMultiplePassAndFailResults(t *testing.T) {
	signed := readFixture(t, "signed-empty.eml")
	headerEnd := bytes.Index(signed, []byte("\r\nFrom:"))
	if headerEnd < 0 {
		t.Fatal("signed fixture lacks expected DKIM/From boundary")
	}
	mutated := append([]byte(nil), signed[:headerEnd+2]...)
	signature := bytes.Index(mutated, []byte("b="))
	if signature < 0 || signature+2 >= len(mutated) {
		t.Fatal("signed fixture lacks signature value")
	}
	if mutated[signature+2] == 'A' {
		mutated[signature+2] = 'B'
	} else {
		mutated[signature+2] = 'A'
	}
	message := append(mutated, signed...)
	record := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"probe._domainkey.example.test.": {record},
	}})
	evidence, err := verifier.Verify(t.Context(), testTransaction(message))
	if err != nil {
		t.Fatal(err)
	}
	failed := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	passed := resultFor(t, evidence, mailauth.MethodDKIM, 1)
	if failed.Outcome != mailauth.OutcomeFail || failed.ErrorCategory != mailauth.ErrorCrypto || passed.Outcome != mailauth.OutcomePass {
		t.Fatalf("multiple DKIM results = %#v, %#v", failed, passed)
	}
	if !evidence.DKIMAligned {
		t.Fatalf("passing aligned signature was lost: %#v", evidence)
	}
}

func TestDKIMEd25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: Alice <alice@example.test>\r\nSubject: ed25519\r\n\r\nbody\r\n")
	headers, err := dkim.Sign(t.Context(), slog.New(slog.DiscardHandler), smtp.Localpart("δοκιμή"),
		dns.Domain{ASCII: "example.test"}, []dkim.Selector{{
			Hash: "sha256", Headers: []string{"From", "Subject"}, PrivateKey: privateKey,
			Domain: dns.Domain{ASCII: "ed"},
		}}, true, bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	signed := append([]byte(headers), message...)
	record := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(publicKey)
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"ed._domainkey.example.test.": {record},
	}})
	transaction := testTransaction(signed)
	transaction.SMTPUTF8 = true
	evidence, err := verifier.Verify(t.Context(), transaction)
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	if result.Outcome != mailauth.OutcomePass || result.Algorithm != "ed25519-sha256" || !strings.HasPrefix(result.Identity, "δοκιμή@") {
		t.Fatalf("Ed25519 DKIM result = %#v", result)
	}
}

func TestDKIMOversignedHeaderRejectsInjection(t *testing.T) {
	privateKey, err := rsa.GenerateKey(cryptorand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("From: Alice <alice@example.test>\r\nSubject: sealed\r\nX-Test: original\r\n\r\nbody\r\n")
	headers, err := dkim.Sign(t.Context(), slog.New(slog.DiscardHandler), smtp.Localpart("alice"),
		dns.Domain{ASCII: "example.test"}, []dkim.Selector{{
			Hash: "sha256", Headers: []string{"From", "Subject", "X-Test"}, SealHeaders: true,
			PrivateKey: privateKey, Domain: dns.Domain{ASCII: "sealed"},
		}}, false, bytes.NewReader(message))
	if err != nil {
		t.Fatal(err)
	}
	modified := bytes.Replace(message, []byte("\r\n\r\n"), []byte("\r\nX-Test: injected\r\n\r\n"), 1)
	signed := append([]byte(headers), modified...)
	publicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"sealed._domainkey.example.test.": {record},
	}})
	evidence, err := verifier.Verify(t.Context(), testTransaction(signed))
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	if result.Outcome != mailauth.OutcomeFail || result.ErrorCategory != mailauth.ErrorCrypto || result.Aligned {
		t.Fatalf("oversigned-header injection result = %#v", result)
	}
}

func TestDKIMErrorMatrix(t *testing.T) {
	signed := readFixture(t, "signed-empty.eml")
	record := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	malformedMessage := func(tags string) []byte {
		return append([]byte("DKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=probe; h=from:subject; bh=AAAA; b=AAAA; "+tags+"\r\n"),
			[]byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\n")...)
	}
	tests := []struct {
		name     string
		message  []byte
		resolver dns.MockResolver
		outcome  mailauth.Outcome
		category mailauth.ErrorCategory
	}{
		{name: "missing key", message: signed, resolver: dns.MockResolver{}, outcome: mailauth.OutcomePermerror, category: mailauth.ErrorLookup},
		{name: "temporary DNS", message: signed, resolver: dns.MockResolver{Fail: []string{"txt probe._domainkey.example.test."}}, outcome: mailauth.OutcomeTemperror, category: mailauth.ErrorDNS},
		{name: "multiple keys", message: signed, resolver: dns.MockResolver{TXT: map[string][]string{"probe._domainkey.example.test.": {record, record}}}, outcome: mailauth.OutcomeTemperror, category: mailauth.ErrorSyntax},
		{name: "modified body", message: append(append([]byte(nil), signed...), []byte("tampered\r\n")...), resolver: dns.MockResolver{TXT: map[string][]string{"probe._domainkey.example.test.": {record}}}, outcome: mailauth.OutcomeFail, category: mailauth.ErrorCrypto},
		{name: "unsupported algorithm", message: append([]byte("DKIM-Signature: v=1; a=rsa-sha999; d=example.test; s=probe; h=from:subject; bh=AAAA; b=AAAA\r\n"), []byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\n")...), resolver: dns.MockResolver{}, outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax},
		{name: "negative body length", message: malformedMessage("l=-1;"), resolver: dns.MockResolver{}, outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax},
		{name: "overflow body length", message: malformedMessage("l=9223372036854775808;"), resolver: dns.MockResolver{}, outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax},
		{name: "duplicate body length", message: malformedMessage("l=1; l=2;"), resolver: dns.MockResolver{}, outcome: mailauth.OutcomePermerror, category: mailauth.ErrorSyntax},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := newTestVerifier(t, test.resolver)
			evidence, err := verifier.Verify(t.Context(), testTransaction(test.message))
			if err != nil {
				t.Fatal(err)
			}
			result := resultFor(t, evidence, mailauth.MethodDKIM, 0)
			if result.Outcome != test.outcome || result.ErrorCategory != test.category || result.Aligned {
				t.Fatalf("DKIM result = %#v, want outcome=%s category=%s", result, test.outcome, test.category)
			}
		})
	}
}

func TestDMARCPolicyLookupAndErrorMatrix(t *testing.T) {
	message := []byte("From: Alice <alice@sub.example.com>\r\nSubject: test\r\n\r\n")
	tests := []struct {
		name             string
		resolver         dns.MockResolver
		visibleDomain    string
		wantOutcome      mailauth.Outcome
		wantCategory     mailauth.ErrorCategory
		wantPolicyDomain string
		wantPolicy       string
		wantSubpolicy    string
	}{
		{
			name: "organizational fallback and subdomain policy",
			resolver: dns.MockResolver{TXT: map[string][]string{
				"example.com.":        {"v=spf1 ip4:192.0.2.1 -all"},
				"_dmarc.example.com.": {"v=DMARC1; p=reject; sp=none"},
			}}, visibleDomain: "sub.example.com", wantOutcome: mailauth.OutcomePass,
			wantPolicyDomain: "example.com", wantPolicy: "reject", wantSubpolicy: "none",
		},
		{name: "no policy", resolver: dns.MockResolver{}, visibleDomain: "sub.example.com", wantOutcome: mailauth.OutcomeNone, wantPolicyDomain: "example.com"},
		{name: "temporary policy lookup", resolver: dns.MockResolver{Fail: []string{"txt _dmarc.sub.example.com."}}, visibleDomain: "sub.example.com", wantOutcome: mailauth.OutcomeTemperror, wantCategory: mailauth.ErrorDNS, wantPolicyDomain: "sub.example.com"},
		{name: "malformed policy", resolver: dns.MockResolver{TXT: map[string][]string{"_dmarc.sub.example.com.": {"v=DMARC1; p=reject; bogus"}}}, visibleDomain: "sub.example.com", wantOutcome: mailauth.OutcomePermerror, wantCategory: mailauth.ErrorSyntax, wantPolicyDomain: "sub.example.com"},
		{name: "multiple policies", resolver: dns.MockResolver{TXT: map[string][]string{"_dmarc.example.com.": {"v=DMARC1; p=none", "v=DMARC1; p=reject"}}}, visibleDomain: "example.com", wantOutcome: mailauth.OutcomeNone, wantCategory: mailauth.ErrorSyntax, wantPolicyDomain: "example.com"},
		{name: "ambiguous From identity", resolver: dns.MockResolver{}, visibleDomain: "", wantOutcome: mailauth.OutcomeNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := newTestVerifier(t, test.resolver)
			transaction := testTransaction(message)
			transaction.EnvelopeSender = "alice@example.com"
			transaction.VisibleFromDomain = test.visibleDomain
			evidence, err := verifier.Verify(t.Context(), transaction)
			if err != nil {
				t.Fatal(err)
			}
			result := resultFor(t, evidence, mailauth.MethodDMARC, 0)
			if result.Outcome != test.wantOutcome || result.ErrorCategory != test.wantCategory ||
				result.PolicyDomain != test.wantPolicyDomain || result.PolicyDisposition != test.wantPolicy || result.SubdomainPolicy != test.wantSubpolicy {
				t.Fatalf("DMARC result = %#v", result)
			}
		})
	}
}

func TestDMARCDKIMAlignmentModes(t *testing.T) {
	message := readFixture(t, "signed-empty.eml")
	dkimRecord := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	for _, test := range []struct {
		name        string
		alignment   string
		wantOutcome mailauth.Outcome
	}{
		{name: "relaxed", alignment: "r", wantOutcome: mailauth.OutcomePass},
		{name: "strict", alignment: "s", wantOutcome: mailauth.OutcomeFail},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := dns.MockResolver{TXT: map[string][]string{
				"probe._domainkey.example.test.": {dkimRecord},
				"_dmarc.sub.example.test.":       {"v=DMARC1; p=reject; adkim=" + test.alignment},
			}}
			verifier := newTestVerifier(t, resolver)
			transaction := testTransaction(message)
			transaction.EnvelopeSender = "alice@other.test"
			transaction.VisibleFromDomain = "sub.example.test"
			evidence, err := verifier.Verify(t.Context(), transaction)
			if err != nil {
				t.Fatal(err)
			}
			result := resultFor(t, evidence, mailauth.MethodDMARC, 0)
			if result.Outcome != test.wantOutcome || result.DKIMAlignmentMode != test.alignment {
				t.Fatalf("DMARC result = %#v", result)
			}
		})
	}
}

func TestVerifierCallerCancellation(t *testing.T) {
	verifier, err := New(Options{Timeout: time.Second, MaxConcurrent: 1, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evidence, err := verifier.Verify(ctx, testTransaction([]byte("From: a@example.test\r\nSubject: x\r\n\r\n")))
	if err == nil || len(evidence.Results) != 0 || evidence.AnyAligned() {
		t.Fatalf("canceled verification = %#v, %v", evidence, err)
	}
}
