package stores

import (
	"context"
	"net/netip"
)

// CorrespondentPolicyRepository exposes adaptive correspondent operations used
// while filtering live mail.
type CorrespondentPolicyRepository interface {
	LearnAuthenticated(context.Context, string, []string) error
	TouchInbound(context.Context, string, []string) error
	RecordInboundClassification(context.Context, InboundClassification) error
	Match(context.Context, string, []string) (CorrespondentMatch, error)
}

// CorrespondentAdminRepository exposes bounded listing and manual allowlist
// operations used by administration commands.
type CorrespondentAdminRepository interface {
	ListCorrespondents(context.Context, CorrespondentListQuery) (CorrespondentPage, error)
	AddManual(context.Context, string, string) (bool, error)
	DeleteCorrespondent(context.Context, string, RecipientScope) (int, error)
}

// RejectionRepository records rejection events and provides recipient-scoped
// history and detail queries.
type RejectionRepository interface {
	AddRejection(context.Context, NewRejection) (uint64, error)
	ListRejections(context.Context, RejectionListQuery) (RejectionPage, error)
	RejectionByID(context.Context, uint64, RecipientScope) (Rejection, bool, error)
}

// IPReputationPolicyRepository exposes automatic sending-IP reputation
// operations used while filtering live mail.
type IPReputationPolicyRepository interface {
	RecordRejection(context.Context, netip.Addr) (IPBlock, error)
	RecordLegitimate(context.Context, netip.Addr) error
	// ActiveBlock may atomically extend an active repeat block when sliding
	// expiry is enabled by the repository's policy options.
	ActiveBlock(context.Context, netip.Addr) (IPBlock, bool, error)
}

// IPReputationAdminRepository exposes manual block and listing operations used
// by administration commands.
type IPReputationAdminRepository interface {
	AddManualBlock(context.Context, netip.Addr) (IPBlock, error)
	Delete(context.Context, netip.Addr) (bool, error)
	ListActiveBlocks(context.Context, IPBlockListQuery) (IPBlockPage, error)
}

type IPReputationRepository interface {
	IPReputationPolicyRepository
	IPReputationAdminRepository
}

// DomainRegistrationRepository stores cached RDAP registration evidence.
// DomainRegistration may return an expired cached record; callers must check
// ExpiresAt before using it as current evidence.
type DomainRegistrationRepository interface {
	DomainRegistration(context.Context, string) (DomainRegistration, bool, error)
	PutDomainRegistration(context.Context, DomainRegistration) error
}

// MaintainedRepository supports periodic expiry/capacity cleanup and debug
// record counts.
type MaintainedRepository interface {
	Cleanup(context.Context) (int64, error)
	Count(context.Context) (int, error)
}

type CorrespondentRepository interface {
	CorrespondentPolicyRepository
	CorrespondentAdminRepository
	MaintainedRepository
}

type RejectionHistoryRepository interface {
	RejectionRepository
	MaintainedRepository
}

type PersistentIPReputationRepository interface {
	IPReputationRepository
	MaintainedRepository
}

type DomainRegistrationCache interface {
	DomainRegistrationRepository
	MaintainedRepository
}

// ActivityRepository records aggregateable filtering outcomes and the
// singleton status of the currently serving process.
type ActivityRepository interface {
	AddActivity(context.Context, ActivityEvent) error
	ActivitySummary(context.Context, ActivityQuery) (ActivitySummary, error)
	CleanupActivity(context.Context) (int64, error)
	CountActivity(context.Context) (int, error)
	ServiceStatus(context.Context) (ServiceStatus, bool, error)
	SetServiceStatus(context.Context, ServiceStatus) error
	ClearServiceStatus(context.Context) error
}
