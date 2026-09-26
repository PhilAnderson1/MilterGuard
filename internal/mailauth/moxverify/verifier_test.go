package moxverify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
)

func TestNewOwnsDedicatedStrictResolver(t *testing.T) {
	for _, options := range []Options{
		{MaxConcurrent: 1},
		{Timeout: time.Second},
		{Timeout: -time.Second, MaxConcurrent: 1},
	} {
		if _, err := New(options); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("New(%+v) error = %v, want invalid options", options, err)
		}
	}

	verifier := newTestVerifier(t, dns.MockResolver{})
	strict, ok := verifier.resolver.(dns.MockResolver)
	if !ok || strict.TXT != nil {
		t.Fatal("test verifier resolver injection failed")
	}

	production, err := New(Options{Timeout: time.Second, MaxConcurrent: 2, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	resolver, ok := production.resolver.(dns.StrictResolver)
	if !ok {
		t.Fatalf("resolver type = %T, want dns.StrictResolver", production.resolver)
	}
	if resolver.Resolver == nil || resolver.Resolver == adns.DefaultResolver {
		t.Fatal("authentication resolver aliases adns.DefaultResolver")
	}
	if !resolver.Resolver.PreferGo || !resolver.Resolver.StrictErrors {
		t.Fatalf("dedicated resolver options = %+v", resolver.Resolver)
	}
}

func TestVerifySPFDKIMNoneAndDMARCPass(t *testing.T) {
	message := []byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\nbody\r\n")
	resolver := dns.MockResolver{TXT: map[string][]string{
		"example.test.":        {"v=spf1 ip4:192.0.2.1 -all"},
		"_dmarc.example.test.": {"v=DMARC1; p=reject"},
	}, AllAuthentic: true}
	verifier := newTestVerifier(t, resolver)

	evidence, err := verifier.Verify(t.Context(), testTransaction(message))
	if err != nil {
		t.Fatal(err)
	}
	spfResult := resultFor(t, evidence, mailauth.MethodSPF, 0)
	if spfResult.Outcome != mailauth.OutcomePass || spfResult.Domain != "example.test" || spfResult.SPFIdentity != "mailfrom" || !spfResult.DNSAuthentic {
		t.Fatalf("SPF result = %#v", spfResult)
	}
	dkimResult := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	if dkimResult.Outcome != mailauth.OutcomeNone {
		t.Fatalf("DKIM result = %#v", dkimResult)
	}
	dmarcResult := resultFor(t, evidence, mailauth.MethodDMARC, 0)
	if dmarcResult.Outcome != mailauth.OutcomePass || !dmarcResult.AlignedSPFPass || dmarcResult.AlignedDKIMPass ||
		dmarcResult.PolicyDomain != "example.test" || dmarcResult.PolicyDisposition != "reject" ||
		dmarcResult.PolicyPercentage != 100 || !dmarcResult.PolicyApplied || !dmarcResult.DNSAuthentic {
		t.Fatalf("DMARC result = %#v", dmarcResult)
	}
	if !evidence.DMARCAligned {
		t.Fatalf("DMARC evidence is not aligned: %#v", evidence)
	}
}

func TestVerifyExactDKIMFixture(t *testing.T) {
	message := readFixture(t, "signed-canonicalizations.eml")
	record := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"probe._domainkey.example.test.": {record},
	}})
	transaction := testTransaction(message)
	transaction.EnvelopeSender = "sender@other.test"

	evidence, err := verifier.Verify(t.Context(), transaction)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 4; index++ {
		result := resultFor(t, evidence, mailauth.MethodDKIM, index)
		if result.Outcome != mailauth.OutcomePass || result.Domain != "example.test" || result.Selector != "probe" ||
			result.Algorithm != "rsa-sha256" || result.BodyLengthLimited || result.ErrorCategory != mailauth.ErrorNone {
			t.Fatalf("DKIM result %d = %#v", index, result)
		}
	}
	if !evidence.DKIMAligned {
		t.Fatalf("DKIM evidence is not aligned: %#v", evidence)
	}
}

func TestVerifyBodyLengthSignatureIsPolicyResult(t *testing.T) {
	message := readFixture(t, "signed-body-length.eml")
	verifier := newTestVerifier(t, dns.MockResolver{})
	evidence, err := verifier.Verify(t.Context(), testTransaction(message))
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	if result.Outcome != mailauth.OutcomePolicy || result.ErrorCategory != mailauth.ErrorPolicy ||
		!result.BodyLengthLimited || result.BodyLength != 12 || result.Aligned {
		t.Fatalf("body-length DKIM result = %#v", result)
	}
	if evidence.DKIMAligned {
		t.Fatalf("body-length signature authenticated the sender: %#v", evidence)
	}
}

func TestVerifyBoundsRetainedDKIMResults(t *testing.T) {
	signed := readFixture(t, "signed-empty.eml")
	headerEnd := bytes.Index(signed, []byte("\r\nFrom:"))
	if headerEnd < 0 {
		t.Fatal("signed fixture lacks expected DKIM/From boundary")
	}
	dkimHeader := signed[:headerEnd+2]
	unsigned := signed[headerEnd+2:]
	var message bytes.Buffer
	for range maxDKIMSignatures + 8 {
		message.Write(dkimHeader)
	}
	message.Write(unsigned)
	contents := message.Bytes()
	record := strings.TrimSpace(string(readFixture(t, "dkim-record.txt")))
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"probe._domainkey.example.test.": {record},
	}})
	evidence, err := verifier.Verify(t.Context(), testTransaction(contents))
	if err != nil {
		t.Fatal(err)
	}
	dkimCount := 0
	for _, result := range evidence.Results {
		if result.Method == mailauth.MethodDKIM {
			dkimCount++
		}
	}
	if dkimCount != maxDKIMSignatures+1 {
		t.Fatalf("retained DKIM results = %d, want %d", dkimCount, maxDKIMSignatures+1)
	}
	for _, occurrence := range []int{0, maxDKIMSignatures - 1} {
		if result := resultFor(t, evidence, mailauth.MethodDKIM, occurrence); result.Outcome != mailauth.OutcomePass {
			t.Fatalf("retained DKIM result %d = %#v, want pass", occurrence, result)
		}
	}
	summary := resultFor(t, evidence, mailauth.MethodDKIM, maxDKIMSignatures)
	if summary.Outcome != mailauth.OutcomePolicy || summary.ErrorCategory != mailauth.ErrorLimit {
		t.Fatalf("DKIM limit summary = %#v", summary)
	}
}

func TestVerifyTemporarySPFDNSFailure(t *testing.T) {
	message := []byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\n")
	resolver := dns.MockResolver{Fail: []string{"txt example.test."}}
	verifier := newTestVerifier(t, resolver)
	evidence, err := verifier.Verify(t.Context(), testTransaction(message))
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodSPF, 0)
	if result.Outcome != mailauth.OutcomeTemperror || result.ErrorCategory != mailauth.ErrorDNS || result.Aligned {
		t.Fatalf("SPF temporary failure = %#v", result)
	}
}

func TestVerifyNullReversePathUsesHELOIdentity(t *testing.T) {
	message := []byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\n")
	tests := []struct {
		name     string
		helo     string
		resolver dns.MockResolver
		outcome  mailauth.Outcome
		domain   string
	}{
		{
			name: "domain", helo: "bounce.example.test",
			resolver: dns.MockResolver{TXT: map[string][]string{"bounce.example.test.": {"v=spf1 ip4:192.0.2.1 -all"}}},
			outcome:  mailauth.OutcomePass, domain: "bounce.example.test",
		},
		{name: "IPv4 literal", helo: "[192.0.2.44]", resolver: dns.MockResolver{}, outcome: mailauth.OutcomeNone},
		{name: "IPv6 literal", helo: "[IPv6:2001:db8::44]", resolver: dns.MockResolver{}, outcome: mailauth.OutcomeNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier := newTestVerifier(t, test.resolver)
			transaction := testTransaction(message)
			transaction.EnvelopeSender = "<>"
			transaction.HELO = test.helo
			transaction.VisibleFromDomain = ""
			evidence, err := verifier.Verify(t.Context(), transaction)
			if err != nil {
				t.Fatal(err)
			}
			result := resultFor(t, evidence, mailauth.MethodSPF, 0)
			if result.Outcome != test.outcome || result.Domain != test.domain {
				t.Fatalf("SPF result = %#v", result)
			}
			if test.domain != "" && result.SPFIdentity != "helo" {
				t.Fatalf("SPF identity = %q, want helo", result.SPFIdentity)
			}
		})
	}
}

func TestVerifyMalformedEnvelopeSenderIsPermerror(t *testing.T) {
	message := []byte("From: Alice <alice@example.test>\r\nSubject: test\r\n\r\n")
	verifier := newTestVerifier(t, dns.MockResolver{})
	transaction := testTransaction(message)
	transaction.EnvelopeSender = "<<alice@example.test>>"
	evidence, err := verifier.Verify(t.Context(), transaction)
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodSPF, 0)
	if result.Outcome != mailauth.OutcomePermerror || result.ErrorCategory != mailauth.ErrorSyntax || result.Reason != "invalid envelope sender" {
		t.Fatalf("malformed envelope result = %#v", result)
	}
}

func TestVerifyDMARCAlignmentModesAndPercentage(t *testing.T) {
	message := []byte("From: Alice <alice@sub.example.test>\r\nSubject: test\r\n\r\n")
	for _, test := range []struct {
		name        string
		policy      string
		wantOutcome mailauth.Outcome
		wantApplied bool
	}{
		{name: "relaxed alignment sampled out", policy: "v=DMARC1; p=reject; aspf=r; pct=0", wantOutcome: mailauth.OutcomePass},
		{name: "strict alignment fails", policy: "v=DMARC1; p=reject; aspf=s; pct=100", wantOutcome: mailauth.OutcomeFail, wantApplied: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := dns.MockResolver{TXT: map[string][]string{
				"example.test.":            {"v=spf1 ip4:192.0.2.1 -all"},
				"_dmarc.sub.example.test.": {test.policy},
			}}
			verifier := newTestVerifier(t, resolver)
			transaction := testTransaction(message)
			transaction.VisibleFromDomain = "sub.example.test"
			evidence, err := verifier.Verify(t.Context(), transaction)
			if err != nil {
				t.Fatal(err)
			}
			result := resultFor(t, evidence, mailauth.MethodDMARC, 0)
			if result.Outcome != test.wantOutcome || result.PolicyApplied != test.wantApplied {
				t.Fatalf("DMARC result = %#v", result)
			}
		})
	}
}

func TestVerifyTemporaryDKIMDNSFailure(t *testing.T) {
	message := readFixture(t, "signed-empty.eml")
	resolver := dns.MockResolver{Fail: []string{"txt probe._domainkey.example.test."}}
	verifier := newTestVerifier(t, resolver)
	evidence, err := verifier.Verify(t.Context(), testTransaction(message))
	if err != nil {
		t.Fatal(err)
	}
	result := resultFor(t, evidence, mailauth.MethodDKIM, 0)
	if result.Outcome != mailauth.OutcomeTemperror || result.ErrorCategory != mailauth.ErrorDNS || result.Aligned {
		t.Fatalf("DKIM temporary failure = %#v", result)
	}
}

func TestVerifyMissingExactMessageCannotProduceDKIMOrDMARCPass(t *testing.T) {
	transaction := testTransaction(nil)
	transaction.Message = nil
	transaction.MessageSize = 0
	verifier := newTestVerifier(t, dns.MockResolver{TXT: map[string][]string{
		"example.test.": {"v=spf1 ip4:192.0.2.1 -all"},
	}})

	evidence, err := verifier.Verify(t.Context(), transaction)
	if !errors.Is(err, ErrMessageUnavailable) {
		t.Fatalf("Verify error = %v, want exact message unavailable", err)
	}
	if resultFor(t, evidence, mailauth.MethodSPF, 0).Outcome != mailauth.OutcomePass {
		t.Fatalf("SPF result was not retained: %#v", evidence)
	}
	for _, method := range []mailauth.Method{mailauth.MethodDKIM, mailauth.MethodDMARC} {
		result := resultFor(t, evidence, method, 0)
		if result.Outcome != mailauth.OutcomeTemperror || result.ErrorCategory != mailauth.ErrorInternal || result.Aligned {
			t.Fatalf("%s unavailable result = %#v", method, result)
		}
	}
	if evidence.AnyAligned() {
		t.Fatalf("unavailable exact message produced aligned evidence: %#v", evidence)
	}
}

func TestVerifyExactMessageReadFailureCannotProduceDKIMOrDMARCPass(t *testing.T) {
	transaction := testTransaction([]byte("placeholder"))
	transaction.Message = failingReaderAt{err: errors.New("local spool read failed")}
	transaction.MessageSize = 11
	verifier := newTestVerifier(t, dns.MockResolver{})

	evidence, err := verifier.Verify(t.Context(), transaction)
	if !errors.Is(err, ErrMessageUnavailable) {
		t.Fatalf("Verify error = %v, want exact message unavailable", err)
	}
	for _, method := range []mailauth.Method{mailauth.MethodDKIM, mailauth.MethodDMARC} {
		result := resultFor(t, evidence, method, 0)
		if result.Outcome != mailauth.OutcomeTemperror || result.ErrorCategory != mailauth.ErrorInternal || result.Aligned {
			t.Fatalf("%s read-failure result = %#v", method, result)
		}
	}
	if evidence.AnyAligned() {
		t.Fatalf("exact-message read failure produced aligned evidence: %#v", evidence)
	}
}

func TestVerifyTimeoutDiscardsPartialPassEvidence(t *testing.T) {
	verifier := &Verifier{
		timeout: 15 * time.Millisecond, slots: make(chan struct{}, 1), log: slog.New(slog.DiscardHandler),
	}
	verifier.run = func(ctx context.Context, _ mailauth.Transaction) (mailauth.Evidence, error) {
		<-ctx.Done()
		return mailauth.NewEvidence([]mailauth.Result{{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "example.test"}}, "example.test"), ctx.Err()
	}
	evidence, err := verifier.Verify(t.Context(), mailauth.Transaction{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify error = %v, want deadline exceeded", err)
	}
	if len(evidence.Results) != 0 || evidence.AnyAligned() {
		t.Fatalf("timeout retained partial pass evidence: %#v", evidence)
	}
}

func TestVerifyBoundsConcurrentQueue(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	verifier := &Verifier{
		timeout: 20 * time.Millisecond, slots: make(chan struct{}, 1), log: slog.New(slog.DiscardHandler),
	}
	verifier.run = func(ctx context.Context, _ mailauth.Transaction) (mailauth.Evidence, error) {
		close(started)
		<-release
		<-ctx.Done()
		return mailauth.Evidence{}, ctx.Err()
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := verifier.Verify(context.Background(), mailauth.Transaction{})
		firstDone <- err
	}()
	<-started

	_, err := verifier.Verify(t.Context(), mailauth.Transaction{})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "queue") {
		t.Fatalf("queued Verify error = %v, want queue deadline", err)
	}
	close(release)
	if err := <-firstDone; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first Verify error = %v, want verification deadline", err)
	}
}

func TestTranslateDKIMPreservesBoundedSignatureMetadata(t *testing.T) {
	localpart := smtp.Localpart(strings.Repeat("é", 200))
	source := dkim.Result{
		Status: dkim.StatusPolicy,
		Sig: &dkim.Sig{
			Domain: dns.Domain{ASCII: "mail.example.test"}, Selector: dns.Domain{ASCII: "selector"},
			Identity:      &dkim.Identity{Localpart: &localpart, Domain: dns.Domain{ASCII: "example.test"}},
			AlgorithmSign: "RSA", AlgorithmHash: "SHA256", Canonicalization: "Relaxed/Simple", Length: 0,
		},
		Err: dkim.ErrPolicy,
	}
	result := translateDKIM(source)
	if result.Domain != "mail.example.test" || result.Selector != "selector" || result.Algorithm != "rsa-sha256" ||
		result.HeaderCanonicalization != "relaxed" || result.BodyCanonicalization != "simple" ||
		!result.BodyLengthLimited || result.BodyLength != 0 || result.ErrorCategory != mailauth.ErrorPolicy {
		t.Fatalf("translated DKIM result = %#v", result)
	}
	if len(result.Identity) > 320 || !utf8.ValidString(result.Identity) {
		t.Fatalf("identity was not safely bounded: %q", result.Identity)
	}
}

func TestTranslateDMARCPreservesPolicy(t *testing.T) {
	source := dmarc.Result{
		Status: dmarc.StatusFail, Domain: dns.Domain{ASCII: "example.test"}, RecordAuthentic: true,
		AlignedSPFPass: false, AlignedDKIMPass: false,
		Record: &dmarc.Record{Policy: dmarc.PolicyReject, SubdomainPolicy: dmarc.PolicyQuarantine,
			ADKIM: dmarc.AlignStrict, ASPF: dmarc.AlignRelaxed, Percentage: 25},
	}
	result := translateDMARC(source, "mail.example.test")
	if result.Domain != "example.test" || result.PolicyDomain != "example.test" || result.PolicyDisposition != "reject" ||
		result.SubdomainPolicy != "quarantine" || result.DKIMAlignmentMode != "s" || result.SPFAlignmentMode != "r" ||
		result.PolicyPercentage != 25 || !result.DNSAuthentic {
		t.Fatalf("translated DMARC result = %#v", result)
	}
}

func newTestVerifier(t *testing.T, resolver dns.Resolver) *Verifier {
	t.Helper()
	verifier, err := New(Options{Timeout: time.Second, MaxConcurrent: 2, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	verifier.resolver = resolver
	return verifier
}

func testTransaction(message []byte) mailauth.Transaction {
	return mailauth.Transaction{
		RemoteIP: netip.MustParseAddr("192.0.2.1"), HELO: "mail.example.test",
		EnvelopeSender: "alice@example.test", ReceiverHostname: "mx.receiver.test",
		ReceiverIP: netip.MustParseAddr("192.0.2.25"), VisibleFromDomain: "example.test",
		Message: bytes.NewReader(message), MessageSize: int64(len(message)),
	}
}

func resultFor(t *testing.T, evidence mailauth.Evidence, method mailauth.Method, occurrence int) mailauth.Result {
	t.Helper()
	for _, result := range evidence.Results {
		if result.Method != method {
			continue
		}
		if occurrence == 0 {
			return result
		}
		occurrence--
	}
	t.Fatalf("result %s[%d] not found in %#v", method, occurrence, evidence.Results)
	return mailauth.Result{}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "..", "prototype", "exactdkim", name))
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

type failingReaderAt struct{ err error }

func (r failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, r.err }
