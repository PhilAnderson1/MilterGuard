package mailaddr

import (
	"net/mail"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

// Mailbox parses a single mailbox. If a malformed display name makes the
// complete value invalid, an unambiguous angle-enclosed mailbox is tried
// separately rather than discarding the usable address with the display name.
func Mailbox(value string) (string, bool) {
	value = strings.TrimSpace(value)
	parse := func(candidate string) (*mail.Address, error) {
		address, err := mail.ParseAddress(candidate)
		if err != nil && strings.HasSuffix(candidate, ".") {
			address, err = mail.ParseAddress(strings.TrimSuffix(candidate, "."))
		}
		return address, err
	}
	if address, err := parse(value); err == nil && address.Address != "" {
		return address.Address, true
	}
	if strings.Count(value, "<") != 1 || strings.Count(value, ">") != 1 {
		return "", false
	}
	start := strings.IndexByte(value, '<')
	end := strings.IndexByte(value, '>')
	if start < 0 || end <= start+1 {
		return "", false
	}
	enclosed := strings.TrimSpace(value[start+1 : end])
	address, err := parse(enclosed)
	if err != nil || address.Address == "" || address.Name != "" {
		return "", false
	}
	return address.Address, true
}

// Normalize returns the canonical mailbox representation used by
// MilterGuard's persistent stores and command authorization. Local parts are
// deliberately folded to lower case to preserve existing identity semantics.
func Normalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 320 {
		return ""
	}
	address, ok := Mailbox(value)
	if !ok || strings.Count(address, "@") != 1 {
		return ""
	}
	parts := strings.SplitN(address, "@", 2)
	local := strings.ToLower(strings.TrimSpace(parts[0]))
	domain := netsafety.DNSHostname(parts[1])
	if local == "" || domain == "" || len(local)+len(domain)+1 > 254 {
		return ""
	}
	return local + "@" + domain
}
