package sqlite

import (
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type CorrespondentOptions struct {
	LearnAuthenticatedRecipients          bool
	LearnLegitimateSenders                bool
	UseAllowlist                          bool
	Scope                                 stores.CorrespondentScope
	MaxEntries                            int
	StaleAfter                            time.Duration
	LegitimateSenderMinScore              float64
	LegitimateSenderMinMessages           int
	LegitimateSenderRequireAuthentication bool
	Now                                   func() time.Time
}

type RejectionOptions struct {
	Expiry     time.Duration
	MaxEntries int
	Now        func() time.Time
}

type IPReputationOptions struct {
	BlockDuration          time.Duration
	RepeatThreshold        int
	RepeatWindow           time.Duration
	RepeatBlockDuration    time.Duration
	RepeatRefreshOnAttempt bool
	LegitimatePerStrike    int
	MaxEntries             int
	Now                    func() time.Time
}

type DomainOptions struct {
	MaxEntries  int
	ExpiryGrace time.Duration
	Now         func() time.Time
}

type ActivityOptions struct {
	Expiry time.Duration
	Now    func() time.Time
}

type SenderBlocklistOptions struct {
	Expiry     time.Duration
	MaxEntries int
	Now        func() time.Time
}

func clock(value func() time.Time) func() time.Time {
	if value != nil {
		return value
	}
	return time.Now
}
