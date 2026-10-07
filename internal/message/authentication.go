package message

import (
	"fmt"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

const maxAuthenticationResultsPerMethod = 10

func writeAuthenticationInformation(b *strings.Builder, msg *Message, context AnalysisContext) {
	if context.AuthenticatedSubmission {
		b.WriteString("\nAUTHENTICATION INFORMATION:\n")
		b.WriteString("Authenticated SMTP submission: yes\n")
		return
	}
	fromDomain := context.Authentication.VisibleDomain
	results := context.Authentication.Results

	b.WriteString("\nAUTHENTICATION INFORMATION:\n")
	if msg.FromHeaderCount() > 1 {
		b.WriteString("Visible From domain: ambiguous (multiple From headers)\n")
	} else {
		fmt.Fprintf(b, "Visible From domain: %s\n", availableValue(fromDomain))
	}
	for _, method := range []mailauth.Method{mailauth.MethodDKIM, mailauth.MethodSPF, mailauth.MethodDMARC} {
		written := 0
		for _, result := range results {
			if result.Method != method || !authenticationResultForPrompt(result) || written >= maxAuthenticationResultsPerMethod {
				continue
			}
			writeAuthenticationResult(b, result, fromDomain)
			written++
		}
		if written == 0 {
			fmt.Fprintf(b, "%s: no trusted local result\n", strings.ToUpper(string(method)))
		}
	}
	writeDomainRegistrationEvidence(b, context.DomainRegistration)
}

func authenticationResultForPrompt(result mailauth.Result) bool {
	return result.Method != mailauth.MethodDKIM || result.Outcome != mailauth.OutcomePolicy || !result.BodyLengthLimited
}

func writeAuthenticationResult(b *strings.Builder, result mailauth.Result, visibleDomain string) {
	method := strings.ToUpper(string(result.Method))
	if result.Outcome == mailauth.OutcomeNone {
		switch result.Method {
		case mailauth.MethodDKIM:
			b.WriteString("DKIM: no signature present\n")
		case mailauth.MethodSPF:
			fmt.Fprintf(b, "SPF: no SPF policy for envelope-sender domain %s\n", availableValue(result.Domain))
		case mailauth.MethodDMARC:
			fmt.Fprintf(b, "DMARC: no DMARC policy for visible From domain %s\n", availableValue(visibleDomain))
		}
		return
	}
	description := authenticationOutcomeDescription(result)
	switch result.Method {
	case mailauth.MethodDKIM:
		fmt.Fprintf(b, "%s: %s for signing domain %s%s\n", method, description, availableValue(result.Domain), passAlignmentText(result))
	case mailauth.MethodSPF:
		fmt.Fprintf(b, "%s: %s for envelope-sender domain %s%s\n", method, description, availableValue(result.Domain), passAlignmentText(result))
	case mailauth.MethodDMARC:
		fmt.Fprintf(b, "%s: %s for visible From domain %s\n", method, description, availableValue(result.Domain))
	}
}

func authenticationOutcomeDescription(result mailauth.Result) string {
	switch result.Outcome {
	case mailauth.OutcomeTemperror:
		return "verification temporarily unavailable"
	case mailauth.OutcomePermerror:
		switch result.Method {
		case mailauth.MethodSPF:
			return "invalid SPF policy"
		case mailauth.MethodDKIM:
			return "no usable signature"
		case mailauth.MethodDMARC:
			return "invalid DMARC policy"
		}
	case mailauth.OutcomePolicy, mailauth.OutcomeNeutral:
		if result.Method == mailauth.MethodDKIM {
			return "no usable signature"
		}
	}
	return string(result.Outcome)
}

func passAlignmentText(result mailauth.Result) string {
	if result.Outcome != mailauth.OutcomePass {
		return ""
	}
	return fmt.Sprintf(" (aligned with visible From domain: %s)", yesNo(result.Aligned))
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
