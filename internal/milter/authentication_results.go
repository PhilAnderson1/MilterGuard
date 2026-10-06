package milter

import (
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

func meetsTrustRequirement(e mailauth.Evidence, requirement string) bool {
	switch requirement {
	case config.AuthenticationTrustSPF:
		return e.SPFAligned
	case config.AuthenticationTrustEither:
		return e.DKIMAligned || e.SPFAligned
	case config.AuthenticationTrustBoth:
		return e.DKIMAligned && e.SPFAligned
	default:
		return e.DKIMAligned
	}
}

func allowedSenderDomain(fromDomain string, allowedDomains []string) string {
	fromDomain = netsafety.DNSHostname(fromDomain)
	if fromDomain == "" {
		return ""
	}
	for _, allowed := range allowedDomains {
		if domainMatches(fromDomain, netsafety.DNSHostname(allowed)) {
			return fromDomain
		}
	}
	return ""
}
