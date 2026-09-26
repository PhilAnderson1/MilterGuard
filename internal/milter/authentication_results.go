package milter

import "github.com/PhilAnderson1/MilterGuard/internal/mailauth"

type senderAuthenticationEvidence struct {
	DKIMAligned  bool
	DMARCAligned bool
}

func (e senderAuthenticationEvidence) anyAligned() bool {
	return e.DKIMAligned || e.DMARCAligned
}

func trustedSenderAuthentication(authentication mailauth.Evidence) senderAuthenticationEvidence {
	return senderAuthenticationEvidence{
		DKIMAligned: authentication.DKIMAligned, DMARCAligned: authentication.DMARCAligned,
	}
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
