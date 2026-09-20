// Package mailauth parses authentication evidence added by trusted local mail
// services. It deliberately does not verify DKIM, SPF, or DMARC itself.
package mailauth

import (
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Method identifies an email authentication method.
type Method string

const (
	MethodDKIM  Method = "dkim"
	MethodSPF   Method = "spf"
	MethodDMARC Method = "dmarc"
)

var (
	authenticationMethodPattern = regexp.MustCompile(`(?i)^\s*(dkim|spf|dmarc)\s*=\s*([a-z][a-z0-9_-]{0,31})\b`)
	dkimDomainPattern           = regexp.MustCompile(`(?i)\bheader\.d\s*=\s*([a-z0-9_.-]+)`)
	spfDomainPattern            = regexp.MustCompile(`(?i)\bsmtp\.mailfrom\s*=\s*<?([a-z0-9_.@+-]+)>?`)
	dmarcDomainPattern          = regexp.MustCompile(`(?i)\bheader\.from\s*=\s*([a-z0-9_.-]+)`)
	receivedSPFResultPattern    = regexp.MustCompile(`(?i)^\s*([a-z][a-z0-9_-]{0,31})\b`)
	receivedSPFEnvelopePattern  = regexp.MustCompile(`(?i)\benvelope-from\s*=\s*<?([a-z0-9_.@+-]+)>?`)
)

// Result is one trusted authentication result and the domain it authenticates.
type Result struct {
	Method  Method
	Outcome string
	Domain  string
}

// Input contains untrusted message headers and the local authentication
// service identifiers that are permitted to have produced trustworthy results.
type Input struct {
	AuthenticationResults []string
	ReceivedSPF           []string
	TrustedAuthservIDs    []string
}

// Parse returns trusted DKIM, SPF, and DMARC results. Received-SPF is used only
// when no trusted Authentication-Results field contains an SPF method.
func Parse(input Input) []Result {
	trusted := normalizedAuthservIDs(input.TrustedAuthservIDs)
	results := make([]Result, 0)
	hasAuthenticationResultsSPF := false

	for _, header := range input.AuthenticationResults {
		clauses := splitAuthenticationClauses(header)
		if len(clauses) < 2 {
			continue
		}
		fields := strings.Fields(clauses[0])
		if len(fields) == 0 || !trusted[normalizeAuthservID(fields[0])] {
			continue
		}
		for _, clause := range clauses[1:] {
			match := authenticationMethodPattern.FindStringSubmatch(clause)
			if len(match) != 3 {
				continue
			}
			result := Result{Method: Method(strings.ToLower(match[1])), Outcome: strings.ToLower(match[2])}
			switch result.Method {
			case MethodDKIM:
				result.Domain = matchedDomain(dkimDomainPattern, clause)
			case MethodSPF:
				result.Domain = DomainFromIdentity(matchedValue(spfDomainPattern, clause))
				hasAuthenticationResultsSPF = true
			case MethodDMARC:
				result.Domain = matchedDomain(dmarcDomainPattern, clause)
			}
			results = appendUnique(results, result)
		}
	}

	if hasAuthenticationResultsSPF {
		return results
	}
	for _, header := range input.ReceivedSPF {
		receiver, ok := receivedSPFReceiver(header)
		if !ok || !trusted[normalizeAuthservID(receiver)] {
			continue
		}
		match := receivedSPFResultPattern.FindStringSubmatch(header)
		if len(match) != 2 {
			continue
		}
		results = appendUnique(results, Result{
			Method:  MethodSPF,
			Outcome: strings.ToLower(match[1]),
			Domain:  DomainFromIdentity(matchedValue(receivedSPFEnvelopePattern, header)),
		})
	}
	return results
}

// NormalizeDomain normalizes and validates a domain found in authentication
// evidence. Underscores are accepted because they occur in deployed mail data.
func NormalizeDomain(value string) string {
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

// DomainFromIdentity extracts and normalizes the domain from a mailbox or
// domain-valued authentication property.
func DomainFromIdentity(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "<>")
	if separator := strings.LastIndexByte(value, '@'); separator >= 0 {
		value = value[separator+1:]
	}
	return NormalizeDomain(value)
}

// DomainAligned reports relaxed organizational-domain alignment.
func DomainAligned(authenticatedDomain, fromDomain string) bool {
	authenticatedDomain = NormalizeDomain(authenticatedDomain)
	fromDomain = NormalizeDomain(fromDomain)
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

func splitAuthenticationClauses(value string) []string {
	clauses := make([]string, 0, strings.Count(value, ";")+1)
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		switch char := value[index]; {
		case quoted && escaped:
			escaped = false
		case quoted && char == '\\':
			escaped = true
		case char == '"':
			quoted = !quoted
		case char == ';' && !quoted:
			clauses = append(clauses, value[start:index])
			start = index + 1
		}
	}
	return append(clauses, value[start:])
}

func matchedDomain(pattern *regexp.Regexp, value string) string {
	return NormalizeDomain(matchedValue(pattern, value))
}

func matchedValue(pattern *regexp.Regexp, value string) string {
	match := pattern.FindStringSubmatch(value)
	if len(match) != 2 {
		return ""
	}
	return match[1]
}

func appendUnique(results []Result, candidate Result) []Result {
	for _, existing := range results {
		if existing == candidate {
			return results
		}
	}
	return append(results, candidate)
}

func normalizedAuthservIDs(values []string) map[string]bool {
	trusted := make(map[string]bool, len(values))
	for _, value := range values {
		if value = normalizeAuthservID(value); value != "" {
			trusted[value] = true
		}
	}
	return trusted
}

func normalizeAuthservID(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

// receivedSPFReceiver extracts receiver= only from the parameter list of a
// Received-SPF field. Comments and quoted values cannot manufacture a receiver.
func receivedSPFReceiver(value string) (string, bool) {
	i := 0
	skipWhitespace := func() {
		for i < len(value) && (value[i] == ' ' || value[i] == '\t') {
			i++
		}
	}
	skipWhitespace()
	start := i
	for i < len(value) && isSPFTokenByte(value[i]) {
		i++
	}
	if i == start {
		return "", false
	}

	for {
		for {
			skipWhitespace()
			for i < len(value) && value[i] == ';' {
				i++
				skipWhitespace()
			}
			if i >= len(value) || value[i] != '(' {
				break
			}
			if !skipSPFComment(value, &i) {
				return "", false
			}
		}
		if i >= len(value) {
			return "", false
		}

		keyStart := i
		for i < len(value) && isSPFTokenByte(value[i]) {
			i++
		}
		if i == keyStart {
			return "", false
		}
		key := value[keyStart:i]
		skipWhitespace()
		if i >= len(value) || value[i] != '=' {
			return "", false
		}
		i++
		skipWhitespace()
		parameter, ok := readSPFParameterValue(value, &i)
		if !ok {
			return "", false
		}
		if strings.EqualFold(key, "receiver") {
			return parameter, true
		}
	}
}

func isSPFTokenByte(value byte) bool {
	return value >= '!' && value <= '~' && !strings.ContainsRune(`()<>@,;:\\[]="`, rune(value))
}

func skipSPFComment(value string, offset *int) bool {
	depth := 0
	escaped := false
	for *offset < len(value) {
		char := value[*offset]
		*offset++
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		switch char {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return true
			}
		}
	}
	return false
}

func readSPFParameterValue(value string, offset *int) (string, bool) {
	if *offset >= len(value) {
		return "", false
	}
	if value[*offset] != '"' {
		start := *offset
		for *offset < len(value) && value[*offset] != ' ' && value[*offset] != '\t' && value[*offset] != ';' && value[*offset] != '(' {
			*offset++
		}
		return value[start:*offset], *offset > start
	}

	*offset++
	var decoded strings.Builder
	escaped := false
	for *offset < len(value) {
		char := value[*offset]
		*offset++
		if escaped {
			decoded.WriteByte(char)
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '"' {
			return decoded.String(), true
		}
		decoded.WriteByte(char)
	}
	return "", false
}
