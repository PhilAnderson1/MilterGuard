package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

func TestCompareShadowAuthentication(t *testing.T) {
	trusted := mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodSPF, Outcome: mailauth.OutcomePass, Domain: "bounce.example.com"},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "mail.example.com"},
		{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomePass, Domain: "example.com"},
	}, "example.com")
	internal := mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodSPF, Outcome: mailauth.OutcomePass, Domain: "bounce.example.com"},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePermerror, Domain: "mail.example.com", ErrorCategory: mailauth.ErrorPolicy},
		{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomePass, Domain: "example.com"},
	}, "example.com")

	comparison := compareShadowAuthentication(trusted, internal)
	if comparison.matched || comparison.comparedMethods != 3 || !slicesEqual(comparison.differences, []string{"dkim"}) {
		t.Fatalf("comparison = %#v", comparison)
	}
	dkim := comparison.methods[mailauth.MethodDKIM]
	if dkim.outcomeMatch || dkim.alignmentMatch || dkim.internal.outcome != mailauth.OutcomePermerror || !slicesEqual(dkim.internal.errorCategories, []string{"policy"}) {
		t.Fatalf("DKIM comparison = %#v", dkim)
	}
}

func TestCompareShadowAuthenticationDoesNotInventMissingReference(t *testing.T) {
	trusted := mailauth.NewEvidence(nil, "example.com")
	internal := mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodSPF, Outcome: mailauth.OutcomePass, Domain: "example.com"},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomeNone},
		{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomeNone},
	}, "example.com")
	comparison := compareShadowAuthentication(trusted, internal)
	if !comparison.matched || comparison.comparedMethods != 0 || len(comparison.differences) != 0 {
		t.Fatalf("comparison without reference = %#v", comparison)
	}
}

func TestShadowAuthenticationCannotChangeAuthoritativeEvidence(t *testing.T) {
	trustedEvidence := mailauth.NewEvidence([]mailauth.Result{{
		Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "example.com",
	}}, "example.com")
	internalEvidence := mailauth.NewEvidence([]mailauth.Result{{
		Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomeFail, Domain: "example.com",
	}}, "example.com")
	authoritative := &fixedAuthenticationVerifier{evidence: trustedEvidence}
	shadow := &fixedAuthenticationVerifier{evidence: internalEvidence, err: errors.New("shadow-only failure")}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	msg := message.New(1024)
	msg.AddHeader("Message-ID", "<shadow-test@example.com>")
	ss := &session{
		deps: &sessionDependencies{
			authentication: authoritative, shadowAuthentication: shadow,
			policy:   &messagePolicyService{correspondentCfg: config.CorrespondentsConfig{TrustedAuthservIDs: []string{"mx.example"}}},
			protocol: protocolOptions{progressInterval: time.Hour}, log: log,
		},
		message: msg, visibleSenderDomain: "example.com",
	}

	got, err := ss.verifyAuthenticationWithProgress(t.Context())
	if err != nil {
		t.Fatalf("authoritative verification returned shadow error: %v", err)
	}
	if !got.DKIMAligned || len(got.Results) != 1 || got.Results[0].Outcome != mailauth.OutcomePass {
		t.Fatalf("authoritative evidence changed by shadow = %#v", got)
	}
	if authoritative.calls.Load() != 1 || shadow.calls.Load() != 1 {
		t.Fatalf("verifier calls authoritative=%d shadow=%d", authoritative.calls.Load(), shadow.calls.Load())
	}
	for _, want := range []string{`"msg":"authentication shadow comparison"`, `"matched":false`, `"differences":["dkim"]`, `"shadow_error":"verification"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("shadow log does not contain %q: %s", want, logs.String())
		}
	}
}

type panicShadowVerifier struct{}

func (panicShadowVerifier) Verify(context.Context, mailauth.Transaction) (mailauth.Evidence, error) {
	panic("shadow test panic")
}

func TestShadowAuthenticationPanicIsContained(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	ss := &session{
		deps: &sessionDependencies{
			authentication: &fixedAuthenticationVerifier{}, shadowAuthentication: panicShadowVerifier{},
			policy: &messagePolicyService{}, protocol: protocolOptions{progressInterval: time.Hour}, log: log,
		},
		message: message.New(1024),
	}
	if _, err := ss.verifyAuthenticationWithProgress(t.Context()); err != nil {
		t.Fatalf("shadow panic escaped into authoritative path: %v", err)
	}
	if !strings.Contains(logs.String(), `"shadow_error":"panic"`) || !strings.Contains(logs.String(), "shadow authentication verification") {
		t.Fatalf("shadow panic not safely logged: %s", logs.String())
	}
}

func TestAuthenticatedSubmissionSkipsAuthenticationShadow(t *testing.T) {
	shadow := &fixedAuthenticationVerifier{}
	ss := &session{
		deps: &sessionDependencies{
			authentication: &fixedAuthenticationVerifier{}, shadowAuthentication: shadow,
			policy: &messagePolicyService{}, protocol: protocolOptions{progressInterval: time.Hour},
			log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		message: message.New(1024), authentication: authenticationState{Authenticated: true},
	}
	if _, err := ss.verifyAuthenticationWithProgress(t.Context()); err != nil {
		t.Fatal(err)
	}
	if shadow.calls.Load() != 0 {
		t.Fatalf("authenticated submission shadow calls = %d", shadow.calls.Load())
	}
}

func slicesEqual[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
