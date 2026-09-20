package mailaddr

import "testing"

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
