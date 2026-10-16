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
	Correspondents              stores.CorrespondentAdminRepository
	Rejections                  stores.RejectionRepository
	IPReputation                stores.IPReputationAdminRepository
	SenderBlocklist             stores.SenderBlocklistAdminRepository
	Activity                    stores.ActivityReporter
	ServiceStatus               stores.ServiceStatusStore
	CommandHistory              stores.CommandHistoryRepository
	MessageSource               RejectionMessageSource
	IPResolver                  IPHostnameResolver
	MaxMessageSize              int64
	MaxHTMLParseCPUMilliseconds int
	MaxHTMLParseMemoryBytes     int64
	DatabaseTimeout             time.Duration
	ActivityExpiry              time.Duration
	Now                         func() time.Time
	ThreadCPUTime               func() (time.Duration, bool)
	Logger                      *slog.Logger
}

type Processor struct {
	correspondents              stores.CorrespondentAdminRepository
	rejections                  stores.RejectionRepository
	ipReputation                stores.IPReputationAdminRepository
	senderBlocklist             stores.SenderBlocklistAdminRepository
	activity                    stores.ActivityReporter
	serviceStatus               stores.ServiceStatusStore
	commandHistory              stores.CommandHistoryRepository
	messageSource               RejectionMessageSource
	ipResolver                  IPHostnameResolver
	maxMessageSize              int64
	maxHTMLParseCPUMilliseconds int
	maxHTMLParseMemoryBytes     int64
	databaseTimeout             time.Duration
	activityExpiry              time.Duration
	now                         func() time.Time
	threadCPUTime               func() (time.Duration, bool)
	log                         *slog.Logger
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
		senderBlocklist: deps.SenderBlocklist,
		activity:        deps.Activity,
		serviceStatus:   deps.ServiceStatus,
		commandHistory:  deps.CommandHistory,
		ipResolver:      deps.IPResolver,
		maxMessageSize:  deps.MaxMessageSize, maxHTMLParseCPUMilliseconds: deps.MaxHTMLParseCPUMilliseconds,
		maxHTMLParseMemoryBytes: deps.MaxHTMLParseMemoryBytes,
		databaseTimeout:         deps.DatabaseTimeout, activityExpiry: deps.ActivityExpiry,
		now: deps.Now, threadCPUTime: deps.ThreadCPUTime, log: deps.Logger,
	}
}
