package admincmd

import (
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"github.com/PhilAnderson1/MilterGuard/internal/threadcpu"
)

// rejectionDetail retrieves and attaches the archived original on demand while
// attempting to regenerate its cleaned body with the current message parser.
func (p *Processor) rejectionDetail(entry stores.Rejection) Response {
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
				processedBody = p.archivedVisibleBody(archived)
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

func (p *Processor) archivedVisibleBody(archived *message.Message) string {
	if p.maxHTMLParseCPUMilliseconds <= 0 {
		return archived.VisibleBodyWithHTMLControl(MaxRejectionBodyRunes, message.HTMLProcessingControl{
			MemoryBytes: p.maxHTMLParseMemoryBytes,
		})
	}
	clock := threadcpu.Now
	if p.threadCPUTime != nil {
		clock = p.threadCPUTime
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	started, ok := clock()
	if !ok {
		return archived.VisibleBodyWithHTMLControl(MaxRejectionBodyRunes, message.HTMLProcessingControl{
			MemoryBytes: p.maxHTMLParseMemoryBytes,
		})
	}
	maximum := time.Duration(p.maxHTMLParseCPUMilliseconds) * time.Millisecond
	checkPrimary := func() {
		current, available := clock()
		if available && current >= started && current-started > maximum {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}
	fallbackStarted := time.Duration(0)
	fallbackStartedOK := false
	checkFallback := func() {
		current, available := clock()
		if !available {
			return
		}
		if !fallbackStartedOK {
			fallbackStarted, fallbackStartedOK = current, true
			return
		}
		if current >= fallbackStarted && current-fallbackStarted > maximum {
			termination.Fail(termination.Failure{Code: termination.CPUExceeded})
		}
	}

	return archived.VisibleBodyWithHTMLControl(MaxRejectionBodyRunes, message.HTMLProcessingControl{
		CheckPrimary:  checkPrimary,
		CheckFallback: checkFallback,
		MemoryBytes:   p.maxHTMLParseMemoryBytes,
	})
}
