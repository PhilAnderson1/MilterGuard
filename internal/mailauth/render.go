package mailauth

import (
	"errors"
	"strings"
)

const (
	maxRenderedDKIMResults = 32
	preferredHeaderLineLen = 78
)

// ErrInvalidAuthservID reports that an Authentication-Results service
// identifier is not a normalized, ASCII domain name.
var ErrInvalidAuthservID = errors.New("invalid authentication service identifier")

// RenderAuthenticationResults returns an RFC 8601 Authentication-Results field
// value. The caller supplies the field name separately when adding the header.
// Only the deliberately selected, bounded subset of Evidence is exposed.
func RenderAuthenticationResults(authservID string, evidence Evidence) (string, error) {
	authservID = NormalizeDomain(authservID)
	if authservID == "" {
		return "", ErrInvalidAuthservID
	}

	methods := renderableMethods(evidence)
	if len(methods) == 0 {
		return authservID + "; none", nil
	}

	var rendered strings.Builder
	rendered.WriteString(authservID)
	lineLen := len("Authentication-Results: ") + len(authservID)
	for _, method := range methods {
		rendered.WriteString(";")
		rendered.WriteString("\r\n\t")
		lineLen = 1
		for index, token := range method {
			separator := ""
			if index > 0 {
				separator = " "
			}
			if lineLen+len(separator)+len(token) > preferredHeaderLineLen && index > 0 {
				rendered.WriteString("\r\n\t")
				lineLen = 1
				separator = ""
			}
			rendered.WriteString(separator)
			rendered.WriteString(token)
			lineLen += len(separator) + len(token)
		}
	}
	return rendered.String(), nil
}

func renderableMethods(evidence Evidence) [][]string {
	methods := make([][]string, 0, len(evidence.Results))
	spfRendered := false
	dkimRendered := 0
	dmarcRendered := false
	for _, result := range evidence.Results {
		outcome := renderableOutcome(result.Method, result.Outcome)
		if outcome == "" {
			continue
		}
		switch result.Method {
		case MethodSPF:
			if spfRendered {
				continue
			}
			spfRendered = true
			tokens := []string{"spf=" + outcome}
			if domain := NormalizeDomain(result.Domain); domain != "" {
				property := ""
				switch result.SPFIdentity {
				case "mailfrom":
					property = "mailfrom"
				case "helo":
					property = "helo"
				}
				if property != "" {
					tokens = append(tokens, "smtp."+property+"="+domain)
				}
			}
			methods = append(methods, tokens)
		case MethodDKIM:
			if dkimRendered >= maxRenderedDKIMResults {
				continue
			}
			dkimRendered++
			tokens := []string{"dkim=" + outcome}
			if domain := NormalizeDomain(result.Domain); domain != "" {
				tokens = append(tokens, "header.d="+domain)
			}
			if selector := NormalizeDomain(result.Selector); selector != "" {
				tokens = append(tokens, "header.s="+selector)
			}
			if algorithm := authenticationKeyword(result.Algorithm, 64); algorithm != "" {
				tokens = append(tokens, "header.a="+algorithm)
			}
			methods = append(methods, tokens)
		case MethodDMARC:
			if dmarcRendered {
				continue
			}
			dmarcRendered = true
			tokens := []string{"dmarc=" + outcome}
			if domain := NormalizeDomain(evidence.VisibleDomain); domain != "" {
				tokens = append(tokens, "header.from="+domain)
			}
			if policy := effectiveDMARCPolicy(result, evidence.VisibleDomain); policy != "" {
				tokens = append(tokens, "policy.dmarc="+policy)
			}
			methods = append(methods, tokens)
		}
	}
	return methods
}

func renderableOutcome(method Method, outcome Outcome) string {
	value := strings.ToLower(string(outcome))
	allowed := false
	switch method {
	case MethodSPF:
		switch Outcome(value) {
		case OutcomeNone, OutcomeNeutral, OutcomePass, OutcomeFail, OutcomeSoftfail, OutcomeTemperror, OutcomePermerror:
			allowed = true
		}
	case MethodDKIM:
		switch Outcome(value) {
		case OutcomeNone, OutcomeNeutral, OutcomePass, OutcomeFail, OutcomePolicy, OutcomeTemperror, OutcomePermerror:
			allowed = true
		}
	case MethodDMARC:
		switch Outcome(value) {
		case OutcomeNone, OutcomePass, OutcomeFail, OutcomeTemperror, OutcomePermerror:
			allowed = true
		}
	}
	if !allowed {
		return ""
	}
	return value
}

func authenticationKeyword(value string, maxBytes int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > maxBytes {
		return ""
	}
	for _, character := range value {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '-' && character != '_' {
					return ""
				}
			}
		}
	}
	return value
}

func effectiveDMARCPolicy(result Result, visibleDomain string) string {
	if result.Outcome != OutcomeFail {
		return ""
	}
	policy := result.PolicyDisposition
	policyDomain := NormalizeDomain(result.PolicyDomain)
	visibleDomain = NormalizeDomain(visibleDomain)
	if policyDomain != "" && visibleDomain != "" && policyDomain != visibleDomain && result.SubdomainPolicy != "" {
		policy = result.SubdomainPolicy
	}
	policy = strings.ToLower(policy)
	switch policy {
	case "none", "quarantine", "reject":
		if !result.PolicyApplied {
			return "none"
		}
		return policy
	default:
		return ""
	}
}
