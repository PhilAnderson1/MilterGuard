package milter

import (
	"regexp"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

var (
	dkimPassPattern    = regexp.MustCompile(`(?i)(?:^|\s)dkim\s*=\s*pass\b`)
	dmarcPassPattern   = regexp.MustCompile(`(?i)(?:^|\s)dmarc\s*=\s*pass\b`)
	dkimDomainPattern  = regexp.MustCompile(`(?i)\bheader\.d\s*=\s*([a-z0-9_.-]+)`)
	dmarcDomainPattern = regexp.MustCompile(`(?i)\bheader\.from\s*=\s*([a-z0-9_.-]+)`)
)

type senderAuthenticationEvidence struct {
	DKIMAligned  bool
	DMARCAligned bool
}

func (e senderAuthenticationEvidence) anyAligned() bool {
	return e.DKIMAligned || e.DMARCAligned
}

func trustedSenderAuthentication(msg *message.Message, trustedAuthservIDs []string, fromAddress string) senderAuthenticationEvidence {
	var evidence senderAuthenticationEvidence
	fromAddress = normalizeEmailAddress(fromAddress)
	separator := strings.LastIndexByte(fromAddress, '@')
	if separator < 0 {
		return evidence
	}
	fromDomain := fromAddress[separator+1:]
	trusted := make(map[string]bool, len(trustedAuthservIDs))
	for _, value := range trustedAuthservIDs {
		if value = normalizeDomain(value); value != "" {
			trusted[value] = true
		}
	}
	for _, header := range msg.Headers["authentication-results"] {
		authserv, results, found := strings.Cut(header, ";")
		if !found {
			continue
		}
		authservFields := strings.Fields(authserv)
		if len(authservFields) == 0 || !trusted[normalizeDomain(authservFields[0])] {
			continue
		}
		for _, result := range strings.Split(results, ";") {
			if dkimPassPattern.MatchString(result) {
				if match := dkimDomainPattern.FindStringSubmatch(result); len(match) == 2 && message.AuthenticationDomainAligned(match[1], fromDomain) {
					evidence.DKIMAligned = true
				}
			}
			if dmarcPassPattern.MatchString(result) {
				if match := dmarcDomainPattern.FindStringSubmatch(result); len(match) == 2 && message.AuthenticationDomainAligned(match[1], fromDomain) {
					evidence.DMARCAligned = true
				}
			}
		}
	}
	return evidence
}

func allowedSenderDomain(fromAddress string, allowedDomains []string) string {
	address := normalizeEmailAddress(fromAddress)
	separator := strings.LastIndexByte(address, '@')
	if separator < 0 {
		return ""
	}
	fromDomain := normalizeDomain(address[separator+1:])
	for _, allowed := range allowedDomains {
		if domainMatches(fromDomain, normalizeDomain(allowed)) {
			return fromDomain
		}
	}
	return ""
}
