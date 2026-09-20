package stores

import (
	"testing"
	"time"
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

func TestSliceBearingValuesCloneCallerOwnedData(t *testing.T) {
	rejectionInput := NewRejection{Recipients: []string{"one@example.com"}, Reasons: []string{"reason"}}
	clonedInput := rejectionInput.Clone()
	clonedInput.Recipients[0], clonedInput.Reasons[0] = "changed@example.com", "changed"
	if rejectionInput.Recipients[0] != "one@example.com" || rejectionInput.Reasons[0] != "reason" {
		t.Fatal("NewRejection.Clone retained caller-owned slice storage")
	}

	rejection := Rejection{Recipients: []string{"one@example.com"}}
	clonedRejection := rejection.Clone()
	clonedRejection.Recipients[0] = "changed@example.com"
	if rejection.Recipients[0] != "one@example.com" {
		t.Fatal("Rejection.Clone retained caller-owned slice storage")
	}

	reputation := IPReputationRecord{Strikes: []time.Time{time.Unix(1, 0)}}
	clonedReputation := reputation.Clone()
	clonedReputation.Strikes[0] = time.Unix(2, 0)
	if reputation.Strikes[0].Unix() != 1 {
		t.Fatal("IPReputationRecord.Clone retained caller-owned slice storage")
	}

	classification := InboundClassification{Recipients: []string{"one@example.com"}}
	clonedClassification := classification.Clone()
	clonedClassification.Recipients[0] = "changed@example.com"
	if classification.Recipients[0] != "one@example.com" {
		t.Fatal("InboundClassification.Clone retained caller-owned slice storage")
	}
}

func TestPersistedEnumerationValues(t *testing.T) {
	values := map[string]string{
		"authenticated": string(CorrespondentKindAuthenticatedOutbound),
		"learned":       string(CorrespondentKindRepeatedLegitimateInbound),
		"manual":        string(CorrespondentKindManual),
		"short":         string(IPBlockLevelShort),
		"repeat":        string(IPBlockLevelRepeat),
	}
	want := map[string]string{
		"authenticated": "authenticated_outbound",
		"learned":       "repeated_legitimate_inbound",
		"manual":        "manual",
		"short":         "short",
		"repeat":        "repeat",
	}
	for name, value := range values {
		if value != want[name] {
			t.Errorf("%s value = %q, want %q", name, value, want[name])
		}
	}
}
