package mailaddr

import (
	"strings"
	"testing"
)

func TestMailboxFallsBackToUnambiguousAngleAddress(t *testing.T) {
	if got, ok := Mailbox(`Malformed [display <Sender@Example.com>`); !ok || got != "Sender@Example.com" {
		t.Fatalf("fallback mailbox = %q, %v", got, ok)
	}
	for _, value := range []string{
		`Malformed <first@example.com> <second@example.com>`,
		`Malformed <not-an-address>`,
		`Malformed <Name <sender@example.com>`,
	} {
		if got, ok := Mailbox(value); ok {
			t.Errorf("ambiguous or invalid mailbox %q accepted as %q", value, got)
		}
	}
}

func TestNormalizePreservesPersistentIdentitySemantics(t *testing.T) {
	if got := Normalize(`Malformed [display <Sender@Example.COM>`); got != "sender@example.com" {
		t.Fatalf("Normalize() = %q", got)
	}
	for _, value := range []string{"", "missing-at.example", "a@under_score.example", "a@-bad.example"} {
		if got := Normalize(value); got != "" {
			t.Errorf("Normalize(%q) = %q, want empty", value, got)
		}
	}
}

func TestNormalizeEnforcesMailboxLengthLimit(t *testing.T) {
	local := strings.Repeat("a", 64)
	domainAtLimit := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	atLimit := local + "@" + domainAtLimit
	if len(atLimit) != 254 {
		t.Fatalf("test mailbox length = %d, want 254", len(atLimit))
	}
	if got := Normalize(atLimit); got != atLimit {
		t.Fatalf("254-byte mailbox normalized to %q", got)
	}

	domainOverLimit := domainAtLimit + "d"
	overLimit := local + "@" + domainOverLimit
	if len(overLimit) != 255 {
		t.Fatalf("test mailbox length = %d, want 255", len(overLimit))
	}
	if got := Normalize(overLimit); got != "" {
		t.Fatalf("255-byte mailbox accepted as %q", got)
	}
}

func TestNormalizeEnforcesRawInputLengthLimit(t *testing.T) {
	const mailbox = "a@b.co"
	makeAddress := func(length int) string {
		suffix := " <" + mailbox + ">"
		return strings.Repeat("x", length-len(suffix)) + suffix
	}
	if value := makeAddress(320); len(value) != 320 || Normalize(value) != mailbox {
		t.Fatalf("320-byte raw address was not accepted")
	}
	if value := makeAddress(321); len(value) != 321 || Normalize(value) != "" {
		t.Fatalf("321-byte raw address was accepted")
	}
}

func TestNormalizeCanonicalizesSingleTrailingDomainDot(t *testing.T) {
	for _, value := range []string{"User@Example.COM.", "User Name <User@Example.COM.>"} {
		if got := Normalize(value); got != "user@example.com" {
			t.Errorf("trailing-dot mailbox %q normalized to %q", value, got)
		}
	}
	if got := Normalize("user@example.com.."); got != "" {
		t.Fatalf("repeated trailing dots accepted as %q", got)
	}
}
