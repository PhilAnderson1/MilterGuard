package admincmd

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

const (
	listTruncatedNotice     = "Results were limited to 1,000 matching records.\n"
	responseTruncatedNotice = "\nCommand reply was truncated at 1 MiB.\n"
)

func formatUTC(value time.Time) string {
	return value.UTC().Format(time.DateTime) + " UTC"
}

func Help(admin, commandMode bool) string {
	text := "Send one or more commands, one per line:\n\nWHITELIST ADD sender@example.com\nWHITELIST DELETE sender@example.com\nWHITELIST LIST [day|week|month|year|all]\nREJECTIONS [day|week|month|year|all]\nREJECTION id\nHELP\n\nListing commands default to the previous week. The local address is taken from your authenticated envelope sender.\n"
	if admin && commandMode {
		return "Enter one command at a time:\n\nACTIVITY [day|week|month|year|all]\nWHITELIST ADD sender@example.com recipient@example.com\nWHITELIST DELETE sender@example.com [recipient@example.com|*]\nWHITELIST LIST [recipient@example.com|*] [day|week|month|year|all]\nREJECTIONS [recipient@example.com|*] [day|week|month|year|all]\nREJECTION id\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\nHELP\nEXIT\n\nListing commands default to the previous week and all local recipients. WHITELIST ADD requires an explicit local recipient.\n"
	}
	if admin {
		text += "\nAdministrator commands:\nACTIVITY [day|week|month|year|all]\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\n\nAdministrators may append a local recipient address before the period in WHITELIST LIST and REJECTIONS commands, and to modification commands. They may use * with WHITELIST DELETE, WHITELIST LIST, or REJECTIONS. For example:\n\nWHITELIST LIST * month\nREJECTIONS * year\n"
	}
	return text
}

func formatActivity(pd period, before time.Time, retention time.Duration, summary stores.ActivitySummary, status stores.ServiceStatus, statusAvailable bool) string {
	var body strings.Builder
	if statusAvailable && status.Mode == stores.ServiceModeAccept {
		body.WriteString("MilterGuard is running in accept mode. Scans completed in this mode are accepted even when the AI recommends rejection.\n")
		if activityHasRejections(summary) {
			body.WriteString("This period also contains rejections recorded in enforce mode.\n")
		}
		body.WriteString("\n")
	}
	fmt.Fprintf(&body, "Activity: %s\n", pd.description())
	uptime := "unavailable"
	if statusAvailable && !status.StartedAt.After(before) {
		uptime = formatDuration(before.Sub(status.StartedAt))
	}
	fmt.Fprintf(&body, "Service uptime: %s\n", uptime)
	fmt.Fprintf(&body, "Retention: %s\n\n", formatDuration(retention))
	if activitySummaryEmpty(summary) {
		body.WriteString("No activity was recorded for this period.\n\n")
	}
	totalRejected := summary.ScanRejections + summary.IPRejections + summary.AttachmentRejections + summary.ProtectedSenderDomainRejections
	totalAccepted := summary.ScanAccepted + summary.CorrespondentAccepts + summary.TrustedDomainAccepts
	fmt.Fprintf(&body, "Total rejected: %d\n", totalRejected)
	fmt.Fprintf(&body, "  AI classification: %d\n", summary.ScanRejections)
	fmt.Fprintf(&body, "  IP reputation: %d\n", summary.IPRejections)
	fmt.Fprintf(&body, "  Attachment policy: %d\n", summary.AttachmentRejections)
	fmt.Fprintf(&body, "  Protected sender-domain policy: %d\n\n", summary.ProtectedSenderDomainRejections)
	fmt.Fprintf(&body, "Total accepted: %d\n", totalAccepted)
	fmt.Fprintf(&body, "  AI classification: %d\n", summary.ScanAccepted)
	fmt.Fprintf(&body, "  Correspondent whitelist: %d\n", summary.CorrespondentAccepts)
	fmt.Fprintf(&body, "  Trusted sender domain: %d\n\n", summary.TrustedDomainAccepts)
	fmt.Fprintf(&body, "Total AI scans: %d\n", summary.ScanTotal)
	fmt.Fprintf(&body, "AI evaluations failed: %d\n\n", summary.AIEvaluationsFailed)
	body.WriteString("Token costs are estimates based on endpoint-reported usage and configured prices.\n")
	fmt.Fprintf(&body, "Total token cost: USD %.4f\n", summary.TokenCost)
	if summary.ScanTotal == 0 {
		body.WriteString("Average cost per message scanned: N/A (no scans)\n")
	} else {
		fmt.Fprintf(&body, "Average cost per message scanned: USD %.6f\n", summary.TokenCost/float64(summary.ScanTotal))
	}
	return body.String()
}

func formatDuration(value time.Duration) string {
	if value < 0 {
		return "unavailable"
	}
	days := int64(value / (24 * time.Hour))
	value %= 24 * time.Hour
	hours := int64(value / time.Hour)
	value %= time.Hour
	minutes := int64(value / time.Minute)
	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, durationPart(days, "day"))
	}
	if hours > 0 {
		parts = append(parts, durationPart(hours, "hour"))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, durationPart(minutes, "minute"))
	}
	return strings.Join(parts, ", ")
}

func durationPart(value int64, unit string) string {
	if value != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", value, unit)
}

func activitySummaryEmpty(summary stores.ActivitySummary) bool {
	return summary.ScanTotal == 0 && summary.IPRejections == 0 && summary.CorrespondentAccepts == 0 &&
		summary.TrustedDomainAccepts == 0 && summary.AttachmentRejections == 0 &&
		summary.ProtectedSenderDomainRejections == 0
}

func activityHasRejections(summary stores.ActivitySummary) bool {
	return summary.ScanRejections > 0 || summary.IPRejections > 0 || summary.AttachmentRejections > 0 ||
		summary.ProtectedSenderDomainRejections > 0
}

func formatAllowlist(entries []stores.Correspondent, includeRecipient, truncated bool) string {
	if len(entries) == 0 {
		return "No whitelisted correspondent addresses were found.\n"
	}
	entries, additional := limitRows(entries)
	truncated = truncated || additional
	var body strings.Builder
	for _, entry := range entries {
		var record strings.Builder
		fmt.Fprintf(&record, "Sender: %s\n", entry.Correspondent)
		if includeRecipient {
			fmt.Fprintf(&record, "Recipient: %s\n", entry.LocalAddress)
		}
		fmt.Fprintf(&record, "Added: %s\n\n", allowlistAddedDescription(entry.CorrespondentType))
		if !AppendBoundedResponse(&body, record.String()) {
			return body.String()
		}
	}
	if truncated {
		AppendBoundedResponse(&body, listTruncatedNotice)
	}
	return body.String()
}

func allowlistAddedDescription(kind stores.CorrespondentKind) string {
	switch kind {
	case stores.CorrespondentKindManual:
		return "manually"
	case stores.CorrespondentKindAuthenticatedOutbound:
		return "learned from authenticated outbound email"
	case stores.CorrespondentKindRepeatedLegitimateInbound:
		return "learned from repeated legitimate inbound emails"
	default:
		return "unknown"
	}
}

func formatActiveIPBlocks(entries []stores.IPBlock, includeHostname, truncated bool) string {
	if len(entries) == 0 {
		return "No active IP blocks were found.\n"
	}
	var body strings.Builder
	for _, entry := range entries {
		var record string
		if includeHostname {
			hostname := entry.Hostname
			if hostname == "" {
				hostname = "not found"
			}
			record = fmt.Sprintf("IP: %s (%s) Type: %s Expires: %s\n", entry.Address, hostname, entry.Level, formatUTC(entry.ExpiresAt))
		} else {
			record = fmt.Sprintf("IP: %s Type: %s Expires: %s\n", entry.Address, entry.Level, formatUTC(entry.ExpiresAt))
		}
		if !AppendBoundedResponse(&body, record) {
			return body.String()
		}
	}
	if truncated {
		AppendBoundedResponse(&body, listTruncatedNotice)
	}
	return body.String()
}

func formatRejectionHistory(entries []stores.Rejection, truncated bool) string {
	if len(entries) == 0 {
		return "No retained rejected-email records were found.\n"
	}
	entries, additional := limitRows(entries)
	truncated = truncated || additional
	var body strings.Builder
	for _, entry := range entries {
		subject := entry.Subject
		if subject == "" {
			subject = "(no subject)"
		}
		reason := entry.Reason
		if reason == "" {
			reason = "Unavailable"
		}
		record := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\nDate: %s\nRejection ID: %d\nReason: %s\n\n", entry.Sender, strings.Join(entry.Recipients, ", "), subject, formatUTC(entry.RejectedAt), entry.ID, reason)
		if !AppendBoundedResponse(&body, record) {
			return body.String()
		}
	}
	if truncated {
		AppendBoundedResponse(&body, listTruncatedNotice)
	}
	return body.String()
}

func formatRejectionDetail(entry stores.Rejection, body string) string {
	subject := entry.Subject
	if subject == "" {
		subject = "(no subject)"
	}
	reason := entry.Reason
	if reason == "" {
		reason = "Unavailable"
	}
	return fmt.Sprintf("Rejection ID: %d\nFrom: %s\nTo: %s\nSubject: %s\nDate: %s\nReason for rejection: %s\n\nProcessed email body text:\n%s\n", entry.ID, entry.Sender, strings.Join(entry.Recipients, ", "), subject, formatUTC(entry.RejectedAt), reason, body)
}

func limitRows[T any](entries []T) ([]T, bool) {
	if len(entries) <= MaxListRows {
		return entries, false
	}
	return entries[:MaxListRows], true
}

// AppendBoundedResponse appends text without allowing a command response to
// exceed MaxResponseBytes. If truncation is necessary it preserves valid UTF-8,
// appends a notice, and returns false.
func AppendBoundedResponse(body *strings.Builder, text string) bool {
	remaining := MaxResponseBytes - body.Len()
	if len(text) <= remaining {
		body.WriteString(text)
		return true
	}
	contentLimit := MaxResponseBytes - len(responseTruncatedNotice)
	if body.Len() > contentLimit {
		end := contentLimit
		existing := body.String()
		for end > 0 && !utf8.ValidString(existing[:end]) {
			end--
		}
		preserved := strings.Clone(existing[:end])
		body.Reset()
		body.WriteString(preserved)
	} else if available := contentLimit - body.Len(); available > 0 {
		end := min(available, len(text))
		for end > 0 && !utf8.ValidString(text[:end]) {
			end--
		}
		body.WriteString(text[:end])
	}
	body.WriteString(responseTruncatedNotice)
	return false
}
