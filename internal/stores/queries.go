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

type InboundClassification struct {
	Correspondent      string
	Recipients         []string
	RecipientsComplete bool
	Classification     string
	Score              float64
	UnwantedMinScore   float64
	DKIMAligned        bool
}
