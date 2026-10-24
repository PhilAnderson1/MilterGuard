package admincmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrArchiveTooLarge means the archive was not read because it exceeds the
// caller's byte limit. Archive implementations must check file size before
// allocating its contents and bound the read in case the file grows.
var ErrArchiveTooLarge = errors.New("saved message exceeds read limit")

// ReplyAttachmentBudget is shared by sequential command renderers for one
// email reply. It budgets encoded bytes, including conservative MIME overhead.
// It must not be used concurrently. Terminal command rendering needs no budget.
type ReplyAttachmentBudget struct {
	remaining int64
	included  map[uint64]bool
	omitted   []uint64
}

type replyAttachmentBudgetKey struct{}

func NewReplyAttachmentBudget(encodedBytes int64) *ReplyAttachmentBudget {
	return &ReplyAttachmentBudget{remaining: max(0, encodedBytes), included: make(map[uint64]bool)}
}

func WithReplyAttachmentBudget(ctx context.Context, budget *ReplyAttachmentBudget) context.Context {
	return context.WithValue(ctx, replyAttachmentBudgetKey{}, budget)
}

// Each archived attachment has a short generated filename and media type.
// 1024 bytes covers its MIME headers and boundary; each 57 input bytes produce
// at most 78 bytes of line-wrapped base64, including CRLF.
func (b *ReplyAttachmentBudget) readLimit() int64 {
	return max(0, (b.remaining-1024)/78) * 57
}

func (b *ReplyAttachmentBudget) include(id uint64, bytes int64) {
	b.remaining -= 1024 + max(1, (bytes+56)/57)*78
	b.included[id] = true
}

func (b *ReplyAttachmentBudget) omit(id uint64) {
	for _, existing := range b.omitted {
		if existing == id {
			return
		}
	}
	b.omitted = append(b.omitted, id)
}

// OmissionNotice is placed before command output so text truncation cannot
// silently conceal omitted attachments.
func (b *ReplyAttachmentBudget) OmissionNotice() string {
	if len(b.omitted) == 0 {
		return ""
	}
	var text strings.Builder
	text.WriteString("Saved messages too large to attach within this reply's size limit (rejection IDs): ")
	for i, id := range b.omitted {
		if i > 0 {
			text.WriteString(", ")
		}
		fmt.Fprint(&text, id)
	}
	text.WriteString(". Request these individually; if one still does not fit, retrieve it using command mode.\n\n")
	return text.String()
}
