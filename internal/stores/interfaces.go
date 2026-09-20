package stores

import (
	"context"
	"net/netip"
)

type CorrespondentPolicyRepository interface {
	LearnAuthenticated(context.Context, string, []string) error
	TouchInbound(context.Context, string, []string) error
	RecordInboundClassification(context.Context, InboundClassification) error
	Match(context.Context, string, []string) (CorrespondentMatch, error)
}

type CorrespondentAdminRepository interface {
	ListCorrespondents(context.Context, CorrespondentListQuery) (CorrespondentPage, error)
	AddManual(context.Context, string, string) (bool, error)
	DeleteManual(context.Context, string, RecipientScope) (int, error)
}

type RejectionRepository interface {
	AddRejection(context.Context, NewRejection) (uint64, error)
	ListRejections(context.Context, RejectionListQuery) (RejectionPage, error)
	RejectionByID(context.Context, uint64, RecipientScope) (Rejection, bool, error)
}

type IPReputationRepository interface {
	RecordRejection(context.Context, netip.Addr) (IPBlock, error)
	RecordLegitimate(context.Context, netip.Addr) error
	// ActiveBlock may atomically extend an active repeat block when sliding
	// expiry is enabled by the repository's policy options.
	ActiveBlock(context.Context, netip.Addr) (IPBlock, bool, error)
	AddManualBlock(context.Context, netip.Addr) (IPBlock, error)
	Delete(context.Context, netip.Addr) (bool, error)
	ListActiveBlocks(context.Context, IPBlockListQuery) (IPBlockPage, error)
}

type DomainRegistrationRepository interface {
	DomainRegistration(context.Context, string) (DomainRegistration, bool, error)
	PutDomainRegistration(context.Context, DomainRegistration) error
}

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
