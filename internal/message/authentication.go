package message

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const maxAuthenticationResultsPerMethod = 10

var (
	authenticationMethodPattern = regexp.MustCompile(`(?i)^\s*(dkim|spf|dmarc)\s*=\s*([a-z][a-z0-9_-]{0,31})\b`)
	dkimDomainPattern           = regexp.MustCompile(`(?i)\bheader\.d\s*=\s*([a-z0-9_.-]+)`)
	spfDomainPattern            = regexp.MustCompile(`(?i)\bsmtp\.mailfrom\s*=\s*<?([a-z0-9_.@+-]+)>?`)
	dmarcDomainPattern          = regexp.MustCompile(`(?i)\bheader\.from\s*=\s*([a-z0-9_.-]+)`)
	receivedSPFResultPattern    = regexp.MustCompile(`(?i)^\s*([a-z][a-z0-9_-]{0,31})\b`)
	receivedSPFEnvelopePattern  = regexp.MustCompile(`(?i)\benvelope-from\s*=\s*<?([a-z0-9_.@+-]+)>?`)
)

type authenticationResult struct {
	method string
	result string
	domain string
}

func writeAuthenticationInformation(b *strings.Builder, msg *Message) {
	fromDomain := visibleFromDomain(msg.Header("From"))
	results := normalizedAuthenticationResults(msg)

	b.WriteString("\nAUTHENTICATION INFORMATION:\n")
	fmt.Fprintf(b, "Visible From domain: %s\n", availableValue(fromDomain))
	for _, method := range []string{"dkim", "spf", "dmarc"} {
		written := 0
		for _, result := range results {
			if result.method != method || written >= maxAuthenticationResultsPerMethod {
				continue
			}
			writeAuthenticationResult(b, result, fromDomain)
			written++
		}
		if written == 0 {
			fmt.Fprintf(b, "%s: no trusted local result\n", strings.ToUpper(method))
		}
	}
	writeDomainRegistrationEvidence(b, msg.DomainRegistration)
}

func normalizedAuthenticationResults(msg *Message) []authenticationResult {
	var results []authenticationResult
	hasAuthenticationResultsSPF := false
	for _, header := range trustedAuthenticationResults(msg.Headers["authentication-results"], msg.TrustedAuthservIDs) {
		_, methods, found := strings.Cut(header, ";")
		if !found {
			continue
		}
		for _, clause := range strings.Split(methods, ";") {
			match := authenticationMethodPattern.FindStringSubmatch(clause)
			if len(match) != 3 {
				continue
			}
			result := authenticationResult{method: strings.ToLower(match[1]), result: strings.ToLower(match[2])}
			switch result.method {
			case "dkim":
				result.domain = matchedDomain(dkimDomainPattern, clause)
			case "spf":
				result.domain = emailDomain(matchedValue(spfDomainPattern, clause))
				hasAuthenticationResultsSPF = true
			case "dmarc":
				result.domain = matchedDomain(dmarcDomainPattern, clause)
			}
			results = appendUniqueAuthenticationResult(results, result)
		}
	}

	// Received-SPF is retained as a fallback for MTAs which do not emit an SPF
	// method in Authentication-Results. Its receiver must still be locally trusted.
	if hasAuthenticationResultsSPF {
		return results
	}
	for _, header := range trustedReceivedSPF(msg.Headers["received-spf"], msg.TrustedAuthservIDs) {
		match := receivedSPFResultPattern.FindStringSubmatch(header)
		if len(match) != 2 {
			continue
		}
		result := authenticationResult{
			method: "spf",
			result: strings.ToLower(match[1]),
			domain: emailDomain(matchedValue(receivedSPFEnvelopePattern, header)),
		}
		results = appendUniqueAuthenticationResult(results, result)
	}
	return results
}

func writeAuthenticationResult(b *strings.Builder, result authenticationResult, fromDomain string) {
	method := strings.ToUpper(result.method)
	switch result.method {
	case "dkim":
		fmt.Fprintf(b, "%s: %s for signing domain %s%s\n", method, result.result, availableValue(result.domain), alignmentText(result.domain, fromDomain))
	case "spf":
		fmt.Fprintf(b, "%s: %s for envelope-sender domain %s%s\n", method, result.result, availableValue(result.domain), alignmentText(result.domain, fromDomain))
	case "dmarc":
		fmt.Fprintf(b, "%s: %s for visible From domain %s (matches supplied visible From domain: %s)\n",
			method, result.result, availableValue(result.domain), yesNo(AuthenticationDomainAligned(result.domain, fromDomain)))
	}
}

func alignmentText(authenticatedDomain, fromDomain string) string {
	return fmt.Sprintf(" (aligned with visible From domain: %s)", yesNo(AuthenticationDomainAligned(authenticatedDomain, fromDomain)))
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func availableValue(value string) string {
	if value == "" {
		return "unavailable"
	}
	return value
}

func visibleFromDomain(value string) string {
	if address, ok := MailboxAddress(value); ok {
		return emailDomain(address)
	}
	return ""
}

func emailDomain(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "<>")
	if separator := strings.LastIndexByte(value, '@'); separator >= 0 {
		value = value[separator+1:]
	}
	return normalizeAuthenticationDomain(value)
}

func matchedDomain(pattern *regexp.Regexp, value string) string {
	return normalizeAuthenticationDomain(matchedValue(pattern, value))
}

func matchedValue(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func normalizeAuthenticationDomain(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				return ""
			}
		}
	}
	return value
}

// AuthenticationDomainAligned reports relaxed organizational-domain alignment.
func AuthenticationDomainAligned(authenticatedDomain, fromDomain string) bool {
	authenticatedDomain = normalizeAuthenticationDomain(authenticatedDomain)
	fromDomain = normalizeAuthenticationDomain(fromDomain)
	if authenticatedDomain == "" || fromDomain == "" {
		return false
	}
	authenticatedOrg, authenticatedErr := publicsuffix.EffectiveTLDPlusOne(authenticatedDomain)
	fromOrg, fromErr := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	if authenticatedErr == nil && fromErr == nil {
		return strings.EqualFold(authenticatedOrg, fromOrg)
	}
	return authenticatedDomain == fromDomain
}

func appendUniqueAuthenticationResult(results []authenticationResult, candidate authenticationResult) []authenticationResult {
	for _, existing := range results {
		if existing == candidate {
			return results
		}
	}
	return append(results, candidate)
}
