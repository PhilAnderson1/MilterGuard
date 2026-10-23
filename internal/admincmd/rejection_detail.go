package admincmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// rejectionDetail retrieves and attaches the archived original on demand while
// attempting to regenerate its cleaned body with the current message parser.
func (p *Processor) rejectionDetail(ctx context.Context, entry stores.Rejection) Response {
	if ctx.Err() != nil {
		return Response{Text: formatRejectionDetail(entry, "Saved message rendering was interrupted.")}
	}
	processedBody := "Saved message is not available."
	var attachments []Attachment
	if p.messageSource != nil {
		archivedMessage, err := p.messageSource.ReadWithRecordID(entry.ID, entry.RejectedAt, p.maxMessageSize)
		switch {
		case err == nil:
			attachments = append(attachments, Attachment{Filename: fmt.Sprintf("rejection-%d.eml", entry.ID), MediaType: "application/octet-stream", Contents: archivedMessage.Contents, SourcePath: archivedMessage.Path})
			processedBody = "Saved message is attached, but its body could not be processed."
			archived, parseErr := message.ParseArchived(archivedMessage.Contents, p.maxMessageSize)
			if parseErr == nil {
				processedBody = p.archivedVisibleBody(ctx, archived, entry.ID)
				if strings.TrimSpace(processedBody) == "" {
					processedBody = "No readable message text was found."
				}
				if archived.SavedArchiveTruncated {
					processedBody = "NOTICE: Saved message was truncated during archiving; some headers or body content may be missing.\n\n" + processedBody
				}
			} else if p.log != nil {
				p.log.Warn("cannot process saved rejected message", "rejection_id", entry.ID, "error", parseErr)
			}
		case errors.Is(err, fs.ErrNotExist):
		default:
			if p.log != nil {
				p.log.Warn("cannot read saved rejected message", "rejection_id", entry.ID, "error", err)
			}
		}
	}
	return Response{Text: formatRejectionDetail(entry, processedBody), Attachments: attachments}
}

func (p *Processor) archivedVisibleBody(ctx context.Context, archived *message.Message, rejectionID uint64) string {
	parserPanic := func() {
		if p.log != nil {
			p.log.Error("HTML parser panic; using fallback extraction", "rejection_id", rejectionID)
		}
	}
	body, _ := message.WithProcessingLimits(ctx, message.ProcessingLimits{
		AllowFallbackAfterLimit: true,
		MemoryBytes:             p.maxHTMLParseMemoryBytes,
		MaxCPUMilliseconds:      p.maxHTMLParseCPUMilliseconds,
		OnHTMLParserPanic:       parserPanic,
	}, func(control message.HTMLProcessingControl) string {
		return archived.VisibleBodyWithHTMLControl(MaxRejectionBodyRunes, control)
	})
	return body
}
