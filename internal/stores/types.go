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

type CorrespondentScope string

const (
	CorrespondentScopeGlobal    CorrespondentScope = "global"
	CorrespondentScopePerSender CorrespondentScope = "per_sender"
)

type InboundVerdict string

const (
	InboundVerdictLegitimate InboundVerdict = "legitimate"
	InboundVerdictUnwanted   InboundVerdict = "unwanted"
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
	CorrespondentType    CorrespondentKind
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
	ActivityEventScan                           ActivityEventType = 1
	ActivityEventIPRejection                    ActivityEventType = 2
	ActivityEventCorrespondentAccept            ActivityEventType = 3
	ActivityEventTrustedDomainAccept            ActivityEventType = 4
	ActivityEventAttachmentRejection            ActivityEventType = 5
	ActivityEventProtectedSenderDomainRejection ActivityEventType = 6
)

type ActivityOutcome uint8

const (
	ActivityOutcomeAccepted       ActivityOutcome = 1
	ActivityOutcomeRejected       ActivityOutcome = 2
	ActivityOutcomeTempfailed     ActivityOutcome = 3
	ActivityOutcomeResponseFailed ActivityOutcome = 4
)

type ServiceMode uint8

const (
	ServiceModeAccept  ServiceMode = 1
	ServiceModeEnforce ServiceMode = 2
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
	CorrespondentAccepts            int64
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
