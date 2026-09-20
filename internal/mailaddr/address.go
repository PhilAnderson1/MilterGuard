package mailaddr

import (
	"net/mail"
	"strings"
)

// Mailbox parses a single mailbox. If a malformed display name makes the
// complete value invalid, an unambiguous angle-enclosed mailbox is tried
// separately rather than discarding the usable address with the display name.
func Mailbox(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if address, err := mail.ParseAddress(value); err == nil && address.Address != "" {
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
	address, err := mail.ParseAddress(enclosed)
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
	domain := strictHostname(parts[1])
	if local == "" || domain == "" || len(local)+len(domain)+1 > 254 {
		return ""
	}
	return local + "@" + domain
}

func strictHostname(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return value
}
