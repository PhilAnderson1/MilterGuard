package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

func TestReceivedMetadataUsesFirstPublicPeerAndTopReceiver(t *testing.T) {
	remote, helo, receiver := receivedMetadata([]string{
		"from local.example (local.example [127.0.0.1]) by mx.example with ESMTP",
		"from sender.example (ptr.example [8.8.8.8]) by local.example with ESMTP",
	})
	if remote != netip.MustParseAddr("8.8.8.8") || helo != "sender.example" || receiver != "mx.example" {
		t.Fatalf("metadata = %v %q %q", remote, helo, receiver)
	}
}

func TestReferenceAuthservIDs(t *testing.T) {
	got := referenceAuthservIDs([]string{
		"mx.example; dkim=pass header.d=example.org",
		"mx.example; spf=pass smtp.mailfrom=example.org",
		"filter.example; dmarc=pass header.from=example.org",
	}, []string{"pass receiver=spf.example; envelope-from=a@example.org"})
	want := []string{"mx.example", "filter.example", "spf.example"}
	if !slices.Equal(got, want) {
		t.Fatalf("authserv IDs = %q, want %q", got, want)
	}
}

func TestSummarizeMethodPrefersPassAndPreservesAlignment(t *testing.T) {
	evidence := mailauth.NewEvidence([]mailauth.Result{
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomeFail, Domain: "bad.example"},
		{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePass, Domain: "example.org"},
	}, "example.org")
	got := summarizeMethod(evidence, mailauth.MethodDKIM)
	if got.Outcome != "pass" || !got.Aligned || !slices.Equal(got.PassDomains, []string{"example.org"}) {
		t.Fatalf("summary = %#v", got)
	}
}
