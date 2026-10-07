package stores

import "fmt"

// InboundLearningPolicy contains the classification thresholds that determine
// how an inbound result should affect learned correspondents.
type InboundLearningPolicy struct {
	LearnLegitimateSenders bool
	LegitimateMinScore     float64
	RequireAuthentication  bool
}

// InboundLearningAction describes the persistence operation selected by the
// correspondent-learning policy.
type InboundLearningAction uint8

const (
	InboundLearningIgnore InboundLearningAction = iota
	InboundLearningRefresh
	InboundLearningAdvance
	InboundLearningRemove
)

// DecideInboundLearning converts an AI classification and authentication
// result into a storage-independent correspondent-learning action.
func DecideInboundLearning(policy InboundLearningPolicy, input InboundClassification) (InboundLearningAction, error) {
	switch input.Verdict {
	case InboundVerdictUnwanted:
		if input.Score >= input.UnwantedMinScore {
			return InboundLearningRemove, nil
		}
		return InboundLearningIgnore, nil
	case InboundVerdictLegitimate:
		if policy.LearnLegitimateSenders &&
			input.Score >= policy.LegitimateMinScore &&
			(!policy.RequireAuthentication || input.AuthenticationSatisfied) {
			return InboundLearningAdvance, nil
		}
		return InboundLearningRefresh, nil
	default:
		return InboundLearningIgnore, fmt.Errorf("invalid inbound correspondent verdict %q", input.Verdict)
	}
}
