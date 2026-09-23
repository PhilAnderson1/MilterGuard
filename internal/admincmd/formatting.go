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
		return "Enter one command at a time:\n\nWHITELIST ADD sender@example.com recipient@example.com\nWHITELIST DELETE sender@example.com [recipient@example.com|*]\nWHITELIST LIST [recipient@example.com|*] [day|week|month|year|all]\nREJECTIONS [recipient@example.com|*] [day|week|month|year|all]\nREJECTION id\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\nHELP\nEXIT\n\nListing commands default to the previous week and all local recipients. WHITELIST ADD requires an explicit local recipient.\n"
	}
	if admin {
		text += "\nAdministrator commands:\nIP LIST [day|week|month|year|all]\nIP LIST LOOKUP [day|week|month|year|all]\nIP ADD 192.0.2.1\nIP DELETE 192.0.2.1\n\nAdministrators may append a local recipient address before the period in WHITELIST LIST and REJECTIONS commands, and to modification commands. They may use * with WHITELIST DELETE, WHITELIST LIST, or REJECTIONS. For example:\n\nWHITELIST LIST * month\nREJECTIONS * year\n"
	}
	return text
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
		fmt.Fprintf(&record, "Added: %s\n\n", allowlistAddedDescription(entry.WhitelistType))
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
