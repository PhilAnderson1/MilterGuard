package admincmd

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

// rejectionDetail reads the archived original on demand and regenerates its
// cleaned body with the current message parser before attaching the `.eml`.
func (p *Processor) rejectionDetail(entry stores.Rejection) Response {
	processedBody := "Saved message is not available."
	var attachments []Attachment
	if p.messageSource != nil {
		contents, err := p.messageSource.ReadWithRecordID(entry.ID, entry.RejectedAt, p.maxMessageSize)
		switch {
		case err == nil:
			sourcePath := filepath.Join(p.archiveRoot, entry.RejectedAt.UTC().Format("2006"), entry.RejectedAt.UTC().Format("01"), entry.RejectedAt.UTC().Format("02"), strconv.FormatUint(entry.ID, 10)+".eml")
			attachments = append(attachments, Attachment{Filename: fmt.Sprintf("rejection-%d.eml", entry.ID), MediaType: "application/octet-stream", Contents: contents, SourcePath: sourcePath})
			archived, parseErr := message.ParseArchived(contents, p.maxMessageSize)
			if parseErr == nil {
				processedBody = archived.ProcessedBody(MaxRejectionBodyRunes)
				if strings.TrimSpace(processedBody) == "" {
					processedBody = "No readable message text was found."
				}
			} else if p.log != nil {
				p.log.Warn("cannot process saved rejected message", "rejection_id", entry.ID, "error", parseErr)
			}
		case errors.Is(err, ErrMessageNotFound):
		default:
			if p.log != nil {
				p.log.Warn("cannot read saved rejected message", "rejection_id", entry.ID, "error", err)
			}
		}
	}
	return Response{Text: formatRejectionDetail(entry, processedBody), Attachments: attachments}
}
