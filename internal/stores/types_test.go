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
