package stores

import "testing"

func TestDecideInboundLearning(t *testing.T) {
	policy := InboundLearningPolicy{
		LearnLegitimateSenders: true,
		LegitimateMinScore:     0.9,
		RequireAuthentication:  true,
	}
	tests := []struct {
		name    string
		policy  InboundLearningPolicy
		input   InboundClassification
		want    InboundLearningAction
		wantErr bool
	}{
		{
			name:   "qualifying legitimate result advances candidate",
			policy: policy,
			input:  InboundClassification{Verdict: InboundVerdictLegitimate, Score: 0.9, AuthenticationSatisfied: true},
			want:   InboundLearningAdvance,
		},
		{
			name:   "legitimate result below score refreshes existing relationship",
			policy: policy,
			input:  InboundClassification{Verdict: InboundVerdictLegitimate, Score: 0.89, AuthenticationSatisfied: true},
			want:   InboundLearningRefresh,
		},
		{
			name:   "legitimate result without required authentication refreshes existing relationship",
			policy: policy,
			input:  InboundClassification{Verdict: InboundVerdictLegitimate, Score: 1},
			want:   InboundLearningRefresh,
		},
		{
			name:   "disabled learning refreshes existing relationship",
			policy: InboundLearningPolicy{LegitimateMinScore: 0.9},
			input:  InboundClassification{Verdict: InboundVerdictLegitimate, Score: 1, AuthenticationSatisfied: true},
			want:   InboundLearningRefresh,
		},
		{
			name:   "unwanted result at threshold removes candidate",
			policy: policy,
			input:  InboundClassification{Verdict: InboundVerdictUnwanted, Score: 0.8, UnwantedMinScore: 0.8},
			want:   InboundLearningRemove,
		},
		{
			name:   "unwanted result below threshold is ignored",
			policy: policy,
			input:  InboundClassification{Verdict: InboundVerdictUnwanted, Score: 0.79, UnwantedMinScore: 0.8},
			want:   InboundLearningIgnore,
		},
		{
			name:    "invalid verdict fails",
			policy:  policy,
			input:   InboundClassification{Verdict: InboundVerdict("unknown")},
			want:    InboundLearningIgnore,
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecideInboundLearning(test.policy, test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("DecideInboundLearning() error = %v, want error %v", err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("DecideInboundLearning() = %v, want %v", got, test.want)
			}
		})
	}
}
