package stores

import (
	"testing"
)

func TestRecipientScopeValidation(t *testing.T) {
	for _, test := range []struct {
		name  string
		scope RecipientScope
		valid bool
	}{
		{name: "one recipient", scope: RecipientScope{Address: "user@example.com"}, valid: true},
		{name: "all recipients", scope: RecipientScope{All: true}, valid: true},
		{name: "neither"},
		{name: "both", scope: RecipientScope{All: true, Address: "user@example.com"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.scope.Validate(); (got == nil) != test.valid {
				t.Fatalf("Validate() error = %v, valid=%v", got, test.valid)
			}
		})
	}
}

func TestPersistedEnumerationValues(t *testing.T) {
	values := map[string]string{
		"authenticated": string(CorrespondentKindAuthenticatedOutbound),
		"learned":       string(CorrespondentKindRepeatedLegitimateInbound),
		"manual":        string(CorrespondentKindManual),
		"short":         string(IPBlockLevelShort),
		"repeat":        string(IPBlockLevelRepeat),
		"global_scope":  string(CorrespondentScopeGlobal),
		"sender_scope":  string(CorrespondentScopePerSender),
		"legitimate":    string(InboundVerdictLegitimate),
		"unwanted":      string(InboundVerdictUnwanted),
	}
	want := map[string]string{
		"authenticated": "authenticated_outbound",
		"learned":       "repeated_legitimate_inbound",
		"manual":        "manual",
		"short":         "short",
		"repeat":        "repeat",
		"global_scope":  "global",
		"sender_scope":  "per_sender",
		"legitimate":    "legitimate",
		"unwanted":      "unwanted",
	}
	for name, value := range values {
		if value != want[name] {
			t.Errorf("%s value = %q, want %q", name, value, want[name])
		}
	}

	numericValues := map[string]uint8{
		"activity_scan":                       uint8(ActivityEventScan),
		"activity_ip_rejection":               uint8(ActivityEventIPRejection),
		"activity_correspondent_accept":       uint8(ActivityEventCorrespondentAccept),
		"activity_trusted_domain_accept":      uint8(ActivityEventTrustedDomainAccept),
		"activity_attachment_rejection":       uint8(ActivityEventAttachmentRejection),
		"activity_protected_domain_rejection": uint8(ActivityEventProtectedSenderDomainRejection),
		"activity_accepted":                   uint8(ActivityOutcomeAccepted),
		"activity_rejected":                   uint8(ActivityOutcomeRejected),
		"activity_tempfailed":                 uint8(ActivityOutcomeTempfailed),
		"activity_response_failed":            uint8(ActivityOutcomeResponseFailed),
		"service_mode_accept":                 uint8(ServiceModeAccept),
		"service_mode_enforce":                uint8(ServiceModeEnforce),
	}
	numericWant := map[string]uint8{
		"activity_scan":                       1,
		"activity_ip_rejection":               2,
		"activity_correspondent_accept":       3,
		"activity_trusted_domain_accept":      4,
		"activity_attachment_rejection":       5,
		"activity_protected_domain_rejection": 6,
		"activity_accepted":                   1,
		"activity_rejected":                   2,
		"activity_tempfailed":                 3,
		"activity_response_failed":            4,
		"service_mode_accept":                 1,
		"service_mode_enforce":                2,
	}
	for name, value := range numericValues {
		if value != numericWant[name] {
			t.Errorf("%s value = %d, want %d", name, value, numericWant[name])
		}
	}
}
