package htmlextract

import "testing"

func TestDeclarationPreparationInvariants(t *testing.T) {
	tests := []struct {
		name              string
		declaration       declaration
		prepared          bool
		validityReady     bool
		tokensReady       bool
		dependenciesReady bool
	}{
		{
			name:          "static value",
			declaration:   declaration{prop: display, value: "none"},
			prepared:      true,
			validityReady: true,
		},
		{
			name:          "contextual value",
			declaration:   declaration{prop: fontSize, value: "2em"},
			validityReady: true,
		},
		{
			name:              "variable reference",
			declaration:       declaration{prop: display, value: "var(--show)"},
			tokensReady:       true,
			dependenciesReady: true,
		},
		{
			name:        "custom property",
			declaration: declaration{prop: -1, custom: "--show", value: "block"},
			tokensReady: true,
		},
		{
			name:          "unsupported static value",
			declaration:   declaration{prop: display, value: "future-display", unsupported: true},
			prepared:      true,
			validityReady: true,
		},
		{
			name:        "shorthand",
			declaration: declaration{prop: background, value: "red", shorthand: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := prepareDeclaration(test.declaration, testCPUGuard(cpuGuard{}))
			if got.prepared != nil != test.prepared || got.validityReady != test.validityReady ||
				got.tokensReady != test.tokensReady || got.dependenciesReady != test.dependenciesReady {
				t.Fatalf("preparation state = prepared:%t validity:%t tokens:%t dependencies:%t",
					got.prepared != nil, got.validityReady, got.tokensReady, got.dependenciesReady)
			}
			if got.prepared != nil && (got.valueTokens != nil || got.tokensReady || !got.validityReady) {
				t.Fatalf("prepared declaration retained duplicate token state: %+v", got)
			}
			if got.dependenciesReady && (!got.hasVars || !got.tokensReady || got.valueStatus != valueResolved) {
				t.Fatalf("dependency state is not backed by resolved variable tokens: %+v", got)
			}
		})
	}
}
