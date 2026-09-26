package message

import (
	"fmt"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

const maxAuthenticationResultsPerMethod = 10

func writeAuthenticationInformation(b *strings.Builder, msg *Message) {
	if msg.AuthenticatedSubmission {
		b.WriteString("\nAUTHENTICATION INFORMATION:\n")
		b.WriteString("Authenticated SMTP submission: yes\n")
		return
	}
	fromDomain := ""
	if msg.FromHeaderCount() == 1 {
		fromDomain = visibleFromDomain(msg.Header("From"))
	}
	results := msg.Authentication.Results

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
	writeDomainRegistrationEvidence(b, msg.DomainRegistration)
}

func authenticationResultForPrompt(result mailauth.Result) bool {
	return result.Method != mailauth.MethodDKIM || result.Outcome != mailauth.OutcomePolicy || !result.BodyLengthLimited
}

func writeAuthenticationResult(b *strings.Builder, result mailauth.Result, fromDomain string) {
	method := strings.ToUpper(string(result.Method))
	switch result.Method {
	case mailauth.MethodDKIM:
		fmt.Fprintf(b, "%s: %s for signing domain %s%s\n", method, result.Outcome, availableValue(result.Domain), passAlignmentText(result, fromDomain))
	case mailauth.MethodSPF:
		fmt.Fprintf(b, "%s: %s for envelope-sender domain %s%s\n", method, result.Outcome, availableValue(result.Domain), passAlignmentText(result, fromDomain))
	case mailauth.MethodDMARC:
		fmt.Fprintf(b, "%s: %s for visible From domain %s\n", method, result.Outcome, availableValue(result.Domain))
	}
}

func passAlignmentText(result mailauth.Result, fromDomain string) string {
	if result.Outcome != mailauth.OutcomePass {
		return ""
	}
	return fmt.Sprintf(" (aligned with visible From domain: %s)", yesNo(mailauth.DomainAligned(result.Domain, fromDomain)))
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
	return mailaddr.Domain(value)
}
