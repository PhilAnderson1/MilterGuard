package mailauth

import (
	"regexp"
	"strings"
)

var (
	authenticationMethodPattern = regexp.MustCompile(`(?i)^\s*(dkim|spf|dmarc)\s*=\s*([a-z][a-z0-9_-]{0,31})\b`)
	dkimDomainPattern           = regexp.MustCompile(`(?i)\bheader\s*\.\s*d\s*=\s*([a-z0-9_.-]+)`)
	dmarcDomainPattern          = regexp.MustCompile(`(?i)\bheader\s*\.\s*from\s*=\s*([a-z0-9_.-]+)`)
)

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
		var valid bool
		header, valid = stripAuthenticationComments(header)
		if !valid {
			continue
		}
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
			method := Method(strings.ToLower(match[1]))
			result := Result{Method: method, Outcome: normalizeHeaderOutcome(method, match[2])}
			switch result.Method {
			case MethodDKIM:
				result.Domain = matchedDomain(dkimDomainPattern, clause)
			case MethodSPF:
				result.Domain = authenticationResultsSPFDomain(clause)
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
	return appendReceivedSPF(results, input.ReceivedSPF, trusted)
}

// authenticationResultsSPFDomain returns the RFC 7208 identity recorded in a
// trusted Authentication-Results SPF clause. MAIL FROM is preferred; HELO is
// the applicable fallback for checks made against the HELO identity, including
// messages with a null reverse path.
func authenticationResultsSPFDomain(clause string) string {
	if identity, ok := authenticationProperty(clause, "smtp", "mailfrom"); ok {
		if domain := DomainFromIdentity(identity); domain != "" {
			return domain
		}
	}
	if identity, ok := authenticationProperty(clause, "smtp", "helo"); ok {
		return DomainFromIdentity(identity)
	}
	return ""
}

// authenticationProperty extracts an exact ptype.property value while
// ignoring property-like text embedded in quoted strings. Values may be an
// Authentication-Results token, a quoted string, or the commonly emitted
// angle-bracket form of an SMTP mailbox.
func authenticationProperty(clause, wantType, wantProperty string) (string, bool) {
	for offset := 0; offset < len(clause); {
		if clause[offset] == '"' {
			if _, next, ok := readAuthenticationQuotedValue(clause, offset); ok {
				offset = next
				continue
			}
			return "", false
		}
		if !isAuthenticationNameByte(clause[offset]) {
			offset++
			continue
		}
		start := offset
		for offset < len(clause) && isAuthenticationNameByte(clause[offset]) {
			offset++
		}
		if !strings.EqualFold(clause[start:offset], wantType) {
			continue
		}

		cursor := skipAuthenticationWhitespace(clause, offset)
		if cursor >= len(clause) || clause[cursor] != '.' {
			continue
		}
		cursor = skipAuthenticationWhitespace(clause, cursor+1)
		propertyStart := cursor
		for cursor < len(clause) && isAuthenticationNameByte(clause[cursor]) {
			cursor++
		}
		if propertyStart == cursor || !strings.EqualFold(clause[propertyStart:cursor], wantProperty) {
			continue
		}
		cursor = skipAuthenticationWhitespace(clause, cursor)
		if cursor >= len(clause) || clause[cursor] != '=' {
			continue
		}
		cursor = skipAuthenticationWhitespace(clause, cursor+1)
		if cursor >= len(clause) {
			return "", false
		}

		switch clause[cursor] {
		case '"':
			value, _, ok := readAuthenticationQuotedValue(clause, cursor)
			return value, ok
		case '<':
			end := strings.IndexByte(clause[cursor+1:], '>')
			if end < 0 {
				return "", false
			}
			return clause[cursor+1 : cursor+1+end], true
		default:
			end := cursor
			for end < len(clause) && clause[end] != ' ' && clause[end] != '\t' {
				end++
			}
			if end == cursor {
				return "", false
			}
			return clause[cursor:end], true
		}
	}
	return "", false
}

func readAuthenticationQuotedValue(value string, offset int) (string, int, bool) {
	if offset >= len(value) || value[offset] != '"' {
		return "", offset, false
	}
	var decoded strings.Builder
	for offset++; offset < len(value); offset++ {
		switch value[offset] {
		case '\\':
			offset++
			if offset >= len(value) {
				return "", offset, false
			}
			decoded.WriteByte(value[offset])
		case '"':
			return decoded.String(), offset + 1, true
		default:
			decoded.WriteByte(value[offset])
		}
	}
	return "", offset, false
}

func skipAuthenticationWhitespace(value string, offset int) int {
	for offset < len(value) && (value[offset] == ' ' || value[offset] == '\t') {
		offset++
	}
	return offset
}

func isAuthenticationNameByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == '-'
}

// normalizeHeaderOutcome translates known implementation-specific aliases at
// the trusted-header boundary. OpenDMARC's built-in SPF verifier writes
// "tempfail" where Authentication-Results and internal verification use
// "temperror". Other extension values remain intact.
func normalizeHeaderOutcome(method Method, value string) Outcome {
	value = strings.ToLower(value)
	if method == MethodSPF && value == "tempfail" {
		return OutcomeTemperror
	}
	return Outcome(value)
}

// stripAuthenticationComments replaces RFC 5322 comments with whitespace so
// semicolons and property-like text inside them cannot affect parsing. Quoted
// strings remain intact; malformed comments or quoted strings reject the
// complete Authentication-Results field rather than yielding partial evidence.
func stripAuthenticationComments(value string) (string, bool) {
	var clean strings.Builder
	clean.Grow(len(value))
	commentDepth := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		char := value[index]
		if commentDepth > 0 {
			switch {
			case escaped:
				escaped = false
			case char == '\\':
				escaped = true
			case char == '(':
				commentDepth++
			case char == ')':
				commentDepth--
				if commentDepth == 0 {
					clean.WriteByte(' ')
				}
			}
			continue
		}
		if quoted {
			clean.WriteByte(char)
			switch {
			case escaped:
				escaped = false
			case char == '\\':
				escaped = true
			case char == '"':
				quoted = false
			}
			continue
		}
		switch char {
		case '(':
			commentDepth = 1
		case ')':
			return "", false
		case '"':
			quoted = true
			clean.WriteByte(char)
		default:
			clean.WriteByte(char)
		}
	}
	if commentDepth != 0 || quoted || escaped {
		return "", false
	}
	return clean.String(), true
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
	// Authentication service identifiers are comparison keys, not necessarily
	// DNS hostnames, so canonicalize them without imposing hostname syntax.
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
