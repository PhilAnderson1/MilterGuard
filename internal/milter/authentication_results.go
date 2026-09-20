package milter

import (
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type senderAuthenticationEvidence struct {
	DKIMAligned  bool
	DMARCAligned bool
}

func (e senderAuthenticationEvidence) anyAligned() bool {
	return e.DKIMAligned || e.DMARCAligned
}

func trustedSenderAuthentication(msg *message.Message, trustedAuthservIDs []string, fromDomain string) senderAuthenticationEvidence {
	var evidence senderAuthenticationEvidence
	if fromDomain == "" {
		return evidence
	}
	results := mailauth.Parse(mailauth.Input{
		AuthenticationResults: msg.Headers["authentication-results"],
		TrustedAuthservIDs:    trustedAuthservIDs,
	})
	for _, result := range results {
		if result.Outcome != "pass" || !mailauth.DomainAligned(result.Domain, fromDomain) {
			continue
		}
		switch result.Method {
		case mailauth.MethodDKIM:
			evidence.DKIMAligned = true
		case mailauth.MethodDMARC:
			evidence.DMARCAligned = true
		}
	}
	return evidence
}

func allowedSenderDomain(fromDomain string, allowedDomains []string) string {
	fromDomain = normalizeDomain(fromDomain)
	if fromDomain == "" {
		return ""
	}
	for _, allowed := range allowedDomains {
		if domainMatches(fromDomain, normalizeDomain(allowed)) {
			return fromDomain
		}
	}
	return ""
}
