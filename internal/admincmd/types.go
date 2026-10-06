package admincmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	MaxListRows           = 1000
	MaxRejectionBodyRunes = 50000
	MaxResponseBytes      = 1 << 20
)

type Actor struct {
	Administrator    bool
	CommandMode      bool
	DefaultRecipient string
	NewestLast       bool
}

type Attachment struct {
	Filename   string
	MediaType  string
	Contents   []byte
	SourcePath string
}

type Response struct {
	Text        string
	Attachments []Attachment
}

type DeferredResponse func() Response

type ArchivedMessage struct {
	Contents []byte
	Path     string
}

type RejectionMessageSource interface {
	ReadWithRecordID(uint64, time.Time, int64) (ArchivedMessage, error)
}

type IPHostnameResolver interface {
	ResolveActiveIPHostnames(context.Context, []stores.IPBlock) []stores.IPBlock
}

type Dependencies struct {
	Correspondents  stores.CorrespondentAdminRepository
	Rejections      stores.RejectionRepository
	IPReputation    stores.IPReputationAdminRepository
	Activity        stores.ActivityRepository
	MessageSource   RejectionMessageSource
	IPResolver      IPHostnameResolver
	MaxMessageSize  int64
	DatabaseTimeout time.Duration
	ActivityExpiry  time.Duration
	Now             func() time.Time
	Logger          *slog.Logger
}

type Processor struct {
	correspondents  stores.CorrespondentAdminRepository
	rejections      stores.RejectionRepository
	ipReputation    stores.IPReputationAdminRepository
	activity        stores.ActivityRepository
	messageSource   RejectionMessageSource
	ipResolver      IPHostnameResolver
	maxMessageSize  int64
	databaseTimeout time.Duration
	activityExpiry  time.Duration
	now             func() time.Time
	log             *slog.Logger
}

// New constructs a transport-independent command processor from repository,
// archive, and optional hostname-resolution dependencies.
func New(deps Dependencies) *Processor {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.DatabaseTimeout <= 0 {
		deps.DatabaseTimeout = 15 * time.Second
	}
	return &Processor{
		correspondents: deps.Correspondents, rejections: deps.Rejections,
		ipReputation: deps.IPReputation, messageSource: deps.MessageSource,
		activity:       deps.Activity,
		ipResolver:     deps.IPResolver,
		maxMessageSize: deps.MaxMessageSize, databaseTimeout: deps.DatabaseTimeout, activityExpiry: deps.ActivityExpiry,
		now: deps.Now, log: deps.Logger,
	}
}
