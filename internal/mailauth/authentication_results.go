package mailauth

import (
	"regexp"
	"strings"
)

var (
	authenticationMethodPattern = regexp.MustCompile(`(?i)^\s*(dkim|spf|dmarc)\s*=\s*([a-z][a-z0-9_-]{0,31})\b`)
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
			properties := authenticationProperties(clause[len(match[0]):])
			method := Method(strings.ToLower(match[1]))
			result := Result{Method: method, Outcome: normalizeHeaderOutcome(method, match[2])}
			switch result.Method {
			case MethodDKIM:
				result.Domain = NormalizeDomain(properties["header.d"])
			case MethodSPF:
				result.Domain, result.SPFIdentity = authenticationResultsSPFIdentity(properties)
				hasAuthenticationResultsSPF = true
			case MethodDMARC:
				result.Domain = NormalizeDomain(properties["header.from"])
			}
			results = appendUnique(results, result)
		}
	}

	if hasAuthenticationResultsSPF {
		return results
	}
	return appendReceivedSPF(results, input.ReceivedSPF, trusted)
}

// authenticationResultsSPFIdentity returns the RFC 7208 identity recorded in a
// trusted Authentication-Results SPF clause. MAIL FROM is preferred; HELO is
// the applicable fallback for checks made against the HELO identity, including
// messages with a null reverse path.
func authenticationResultsSPFIdentity(properties map[string]string) (string, SPFIdentity) {
	if domain := DomainFromIdentity(properties["smtp.mailfrom"]); domain != "" {
		return domain, SPFIdentityMailFrom
	}
	if identity, ok := properties["smtp.helo"]; ok {
		return DomainFromIdentity(identity), SPFIdentityHELO
	}
	return "", ""
}

// authenticationProperties consumes whole assignments, including unknown
// properties and reason values. Never search within a value for another key:
// DKIM identities can legitimately contain text such as header.d=example.com.
// Malformed or duplicate assignments invalidate all identity evidence in the
// clause. The caller still records its method, preventing an invalid SPF clause
// from activating the Received-SPF fallback.
func authenticationProperties(clause string) map[string]string {
	properties := make(map[string]string)
	for offset := 0; offset < len(clause); {
		next := skipAuthenticationWhitespace(clause, offset)
		if next == len(clause) {
			return properties
		}
		if next == offset {
			return nil
		}
		offset = next
		start := offset
		for offset < len(clause) && isAuthenticationNameByte(clause[offset]) {
			offset++
		}
		if start == offset {
			return nil
		}
		key := strings.ToLower(clause[start:offset])
		offset = skipAuthenticationWhitespace(clause, offset)
		if offset < len(clause) && clause[offset] == '.' {
			offset = skipAuthenticationWhitespace(clause, offset+1)
			start = offset
			for offset < len(clause) && isAuthenticationNameByte(clause[offset]) {
				offset++
			}
			if start == offset {
				return nil
			}
			key += "." + strings.ToLower(clause[start:offset])
			offset = skipAuthenticationWhitespace(clause, offset)
		}
		if offset >= len(clause) || clause[offset] != '=' {
			return nil
		}
		offset = skipAuthenticationWhitespace(clause, offset+1)
		if offset == len(clause) {
			return nil
		}
		var value string
		switch clause[offset] {
		case '"':
			var ok bool
			value, offset, ok = readAuthenticationQuotedValue(clause, offset)
			if !ok {
				return nil
			}
		case '<':
			end := strings.IndexByte(clause[offset+1:], '>')
			if end < 0 {
				return nil
			}
			value = clause[offset+1 : offset+1+end]
			offset += end + 2
		default:
			start = offset
			for offset < len(clause) && !isAuthenticationWhitespace(clause[offset]) {
				// Quotes and angle brackets must delimit the entire value.
				if strings.ContainsRune("\"<>", rune(clause[offset])) {
					return nil
				}
				offset++
			}
			value = clause[start:offset]
		}
		if _, duplicate := properties[key]; duplicate {
			return nil
		}
		properties[key] = value
	}
	return properties
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
	for offset < len(value) && isAuthenticationWhitespace(value[offset]) {
		offset++
	}
	return offset
}

func isAuthenticationWhitespace(value byte) bool {
	return value == ' ' || value == '\t' || value == '\r' || value == '\n'
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
