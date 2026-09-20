package stores

import (
	"fmt"
	"strings"
	"time"
)

type RecipientScope struct {
	All     bool
	Address string
}

func (s RecipientScope) Validate() error {
	if s.All && strings.TrimSpace(s.Address) != "" {
		return fmt.Errorf("recipient scope cannot contain both all recipients and an address")
	}
	if !s.All && strings.TrimSpace(s.Address) == "" {
		return fmt.Errorf("recipient scope requires an address")
	}
	return nil
}

type CorrespondentListQuery struct {
	Recipients  RecipientScope
	ActiveSince time.Time
	Limit       int
}

type RejectionListQuery struct {
	Recipients    RecipientScope
	RejectedSince time.Time
	Limit         int
}

type IPBlockListQuery struct {
	ActiveSince time.Time
	Limit       int
}

type NewRejection struct {
	VisibleSender  string
	EnvelopeSender string
	Subject        string
	Recipients     []string
	Reasons        []string
	RejectedAt     time.Time
}

// Clone returns an input value whose slices do not share backing storage with
// the original. Repositories must likewise not retain caller-owned slices.
func (r NewRejection) Clone() NewRejection {
	r.Recipients = append([]string(nil), r.Recipients...)
	r.Reasons = append([]string(nil), r.Reasons...)
	return r
}

type InboundClassification struct {
	Correspondent      string
	Recipients         []string
	RecipientsComplete bool
	Classification     string
	Score              float64
	UnwantedMinScore   float64
	DKIMAligned        bool
}

// Clone returns an input value whose Recipients slice is independently owned.
func (c InboundClassification) Clone() InboundClassification {
	c.Recipients = append([]string(nil), c.Recipients...)
	return c
}
