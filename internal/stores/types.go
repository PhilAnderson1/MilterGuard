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
	MatchedRecipients    int
	TotalRecipients      int
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
	ID           uint64
	Domain       string
	RegisteredAt time.Time
	ExpiresAt    time.Time
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
