package mailauth

import (
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
	"golang.org/x/net/publicsuffix"
)

// NormalizeDomain normalizes and validates a domain found in authentication
// evidence. Underscores are accepted because they occur in deployed mail data.
func NormalizeDomain(value string) string {
	return netsafety.NormalizeDNSName(value, true)
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
	if authenticatedErr != nil || fromErr != nil {
		return false
	}
	return strings.EqualFold(authenticatedOrg, fromOrg)
}
