package mailauth

import (
	"regexp"
	"strings"
)

var (
	receivedSPFResultPattern = regexp.MustCompile(`(?i)^\s*([a-z][a-z0-9_-]{0,31})\b`)
)

func appendReceivedSPF(results []Result, headers []string, trusted map[string]bool) []Result {
	for _, header := range headers {
		receiver, ok := receivedSPFParameter(header, "receiver")
		if !ok || !trusted[normalizeAuthservID(receiver)] {
			continue
		}
		match := receivedSPFResultPattern.FindStringSubmatch(header)
		if len(match) != 2 {
			continue
		}
		results = appendUnique(results, Result{
			Method:  MethodSPF,
			Outcome: normalizeHeaderOutcome(MethodSPF, match[1]),
			Domain:  receivedSPFEnvelopeDomain(header),
		})
	}
	return results
}

func receivedSPFEnvelopeDomain(header string) string {
	identity, _ := receivedSPFParameter(header, "envelope-from")
	return DomainFromIdentity(identity)
}

// receivedSPFParameter extracts an exact parameter from a Received-SPF field.
// Comments and quoted values cannot manufacture parameter names, while quoted
// and angle-bracketed parameter values remain available to their caller.
func receivedSPFParameter(value, wanted string) (string, bool) {
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
		if strings.EqualFold(key, wanted) {
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
