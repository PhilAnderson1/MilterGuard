// Package stores defines SQL-independent repository contracts and values for
// MilterGuard's persistent state.
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

// Clone returns a snapshot whose Recipients slice is owned by the caller.
func (r Rejection) Clone() Rejection {
	r.Recipients = append([]string(nil), r.Recipients...)
	return r
}

type IPBlock struct {
	Address     netip.Addr
	Hostname    string
	Level       IPBlockLevel
	ExpiresAt   time.Time
	StrikeCount int
}

type IPReputationRecord struct {
	ID              uint64
	Address         netip.Addr
	Strikes         []time.Time
	BlockLevel      IPBlockLevel
	BlockedUntil    time.Time
	LegitimateCount int
	LastActivityAt  time.Time
}

// Clone returns a snapshot whose Strikes slice is owned by the caller.
func (r IPReputationRecord) Clone() IPReputationRecord {
	r.Strikes = append([]time.Time(nil), r.Strikes...)
	return r
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
