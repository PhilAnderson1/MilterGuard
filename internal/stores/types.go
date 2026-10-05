package stores

import (
	"net/netip"
	"time"
)

type CorrespondentKind string

const (
	CorrespondentKindAuthenticatedOutbound     CorrespondentKind = "authenticated_outbound"
	CorrespondentKindRepeatedLegitimateInbound CorrespondentKind = "repeated_legitimate_inbound"
	CorrespondentKindManual                    CorrespondentKind = "manual"
)

type IPBlockLevel string

const (
	IPBlockLevelShort  IPBlockLevel = "short"
	IPBlockLevelRepeat IPBlockLevel = "repeat"
)

type Correspondent struct {
	ID                   uint64
	LocalAddress         string
	Correspondent        string
	LearnedAt            time.Time
	LastActivityAt       time.Time
	WhitelistType        CorrespondentKind
	LegitimateEmailCount int
}

type CorrespondentMatch struct {
	Known                bool
	AllRecipientsMatched bool
}

type Rejection struct {
	ID         uint64
	Sender     string
	Subject    string
	Recipients []string
	RejectedAt time.Time
	Reason     string
}

type IPBlock struct {
	Address     netip.Addr
	Hostname    string
	Level       IPBlockLevel
	ExpiresAt   time.Time
	StrikeCount int
}

type DomainRegistration struct {
	Domain       string
	RegisteredAt time.Time
	ExpiresAt    time.Time
}

type ActivityEventType uint8

const (
	ActivityEventScan ActivityEventType = iota + 1
	ActivityEventIPRejection
	ActivityEventWhitelistAccept
	ActivityEventTrustedDomainAccept
	ActivityEventAttachmentRejection
	ActivityEventProtectedSenderDomainRejection
)

type ActivityOutcome uint8

const (
	ActivityOutcomeAccepted ActivityOutcome = iota + 1
	ActivityOutcomeRejected
	ActivityOutcomeTempfailed
	ActivityOutcomeResponseFailed
)

type ServiceMode uint8

const (
	ServiceModeAccept ServiceMode = iota + 1
	ServiceModeEnforce
)

type ActivityEvent struct {
	OccurredAt     time.Time
	EventType      ActivityEventType
	Outcome        ActivityOutcome
	AnalysisFailed bool
	TokenCost      float64
}

type ActivitySummary struct {
	ScanTotal                       int64
	ScanRejections                  int64
	ScanAccepted                    int64
	AIEvaluationsFailed             int64
	IPRejections                    int64
	WhitelistAccepts                int64
	TrustedDomainAccepts            int64
	AttachmentRejections            int64
	ProtectedSenderDomainRejections int64
	TokenCost                       float64
}

type ServiceStatus struct {
	StartedAt time.Time
	Mode      ServiceMode
}

type CorrespondentPage struct {
	Entries   []Correspondent
	Truncated bool
}

type RejectionPage struct {
	Entries   []Rejection
	Truncated bool
}

type IPBlockPage struct {
	Entries   []IPBlock
	Truncated bool
}
