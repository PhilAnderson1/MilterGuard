package message

import (
	"fmt"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

const maxAuthenticationResultsPerMethod = 10

func writeAuthenticationInformation(b *strings.Builder, msg *Message) {
	if msg.AuthenticatedSubmission {
		b.WriteString("\nAUTHENTICATION INFORMATION:\n")
		b.WriteString("Authenticated SMTP submission: yes\n")
		return
	}
	fromDomain := visibleFromDomain(msg.Header("From"))
	results := normalizedAuthenticationResults(msg)

	b.WriteString("\nAUTHENTICATION INFORMATION:\n")
	fmt.Fprintf(b, "Visible From domain: %s\n", availableValue(fromDomain))
	for _, method := range []mailauth.Method{mailauth.MethodDKIM, mailauth.MethodSPF, mailauth.MethodDMARC} {
		written := 0
		for _, result := range results {
			if result.Method != method || written >= maxAuthenticationResultsPerMethod {
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

func normalizedAuthenticationResults(msg *Message) []mailauth.Result {
	return mailauth.Parse(mailauth.Input{
		AuthenticationResults: msg.Headers["authentication-results"],
		ReceivedSPF:           msg.Headers["received-spf"],
		TrustedAuthservIDs:    msg.TrustedAuthservIDs,
	})
}

func writeAuthenticationResult(b *strings.Builder, result mailauth.Result, fromDomain string) {
	method := strings.ToUpper(string(result.Method))
	switch result.Method {
	case mailauth.MethodDKIM:
		fmt.Fprintf(b, "%s: %s for signing domain %s%s\n", method, result.Outcome, availableValue(result.Domain), alignmentText(result.Domain, fromDomain))
	case mailauth.MethodSPF:
		fmt.Fprintf(b, "%s: %s for envelope-sender domain %s%s\n", method, result.Outcome, availableValue(result.Domain), alignmentText(result.Domain, fromDomain))
	case mailauth.MethodDMARC:
		fmt.Fprintf(b, "%s: %s for visible From domain %s (matches supplied visible From domain: %s)\n",
			method, result.Outcome, availableValue(result.Domain), yesNo(mailauth.DomainAligned(result.Domain, fromDomain)))
	}
}

func alignmentText(authenticatedDomain, fromDomain string) string {
	return fmt.Sprintf(" (aligned with visible From domain: %s)", yesNo(mailauth.DomainAligned(authenticatedDomain, fromDomain)))
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
	return mailauth.DomainFromIdentity(value)
}
