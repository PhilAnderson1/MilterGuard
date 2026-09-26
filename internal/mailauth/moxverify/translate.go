package moxverify

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/spf"
)

func translateDKIM(source dkim.Result) mailauth.Result {
	result := mailauth.Result{
		Method: mailauth.MethodDKIM, Outcome: outcome(string(source.Status)),
		DNSAuthentic: source.RecordAuthentic,
	}
	if source.Sig != nil {
		result.Domain = normalizeDomain(source.Sig.Domain)
		result.Selector = bounded(source.Sig.Selector.ASCII, 253)
		if source.Sig.Identity != nil {
			result.Identity = bounded(source.Sig.Identity.String(), 320)
		}
		result.Algorithm = bounded(strings.ToLower(source.Sig.Algorithm()), 64)
		result.HeaderCanonicalization, result.BodyCanonicalization = canonicalizations(source.Sig.Canonicalization)
		result.BodyLengthLimited = source.Sig.Length >= 0
		if result.BodyLengthLimited {
			result.BodyLength = source.Sig.Length
		}
	}
	result.ErrorCategory, result.Reason = classifyDKIM(source.Status, source.Err)
	return result
}

func translateDMARC(source dmarc.Result, visibleDomain string) mailauth.Result {
	result := mailauth.Result{
		Method: mailauth.MethodDMARC, Outcome: outcome(string(source.Status)),
		Domain: normalizeDomain(source.Domain), PolicyDomain: normalizeDomain(source.Domain),
		DNSAuthentic: source.RecordAuthentic, AlignedSPFPass: source.AlignedSPFPass,
		AlignedDKIMPass: source.AlignedDKIMPass,
	}
	if result.Domain == "" {
		result.Domain = mailauth.NormalizeDomain(visibleDomain)
	}
	if source.Record != nil {
		result.PolicyDisposition = bounded(string(source.Record.Policy), 16)
		result.SubdomainPolicy = bounded(string(source.Record.SubdomainPolicy), 16)
		result.DKIMAlignmentMode = bounded(string(source.Record.ADKIM), 1)
		result.SPFAlignmentMode = bounded(string(source.Record.ASPF), 1)
		result.PolicyPercentage = source.Record.Percentage
	}
	result.ErrorCategory, result.Reason = classifyDMARC(source.Status, source.Err)
	return result
}

func outcome(value string) mailauth.Outcome {
	value = strings.ToLower(value)
	switch mailauth.Outcome(value) {
	case mailauth.OutcomeNone, mailauth.OutcomeNeutral, mailauth.OutcomePass, mailauth.OutcomeFail,
		mailauth.OutcomeSoftfail, mailauth.OutcomePolicy, mailauth.OutcomeTemperror, mailauth.OutcomePermerror:
		return mailauth.Outcome(value)
	default:
		return mailauth.OutcomePermerror
	}
}

func normalizeDomain(domain dns.Domain) string {
	return mailauth.NormalizeDomain(domain.ASCII)
}

func canonicalizations(value string) (string, string) {
	parts := strings.SplitN(strings.ToLower(value), "/", 2)
	header := parts[0]
	body := "simple"
	if len(parts) == 2 {
		body = parts[1]
	}
	return bounded(header, 16), bounded(body, 16)
}

func classifySPF(status spf.Status, err error) (mailauth.ErrorCategory, string) {
	if err == nil || status == spf.StatusNone && errors.Is(err, spf.ErrNoRecord) {
		return mailauth.ErrorNone, ""
	}
	switch {
	case errors.Is(err, spf.ErrDNS):
		return mailauth.ErrorDNS, "DNS lookup failed"
	case errors.Is(err, spf.ErrTooManyDNSRequests), errors.Is(err, spf.ErrTooManyVoidLookups):
		return mailauth.ErrorLimit, "SPF lookup limit exceeded"
	case errors.Is(err, spf.ErrNoRecord):
		return mailauth.ErrorLookup, "referenced SPF record unavailable"
	default:
		return mailauth.ErrorSyntax, "invalid SPF policy"
	}
}

func classifyDKIM(status dkim.Status, err error) (mailauth.ErrorCategory, string) {
	if err == nil {
		return mailauth.ErrorNone, ""
	}
	switch {
	case errors.Is(err, errTooManySignatures):
		return mailauth.ErrorLimit, "DKIM signature limit exceeded"
	case status == dkim.StatusPolicy || errors.Is(err, dkim.ErrPolicy):
		return mailauth.ErrorPolicy, "signature rejected by DKIM policy"
	case errors.Is(err, dkim.ErrMultipleRecords), errors.Is(err, dkim.ErrSyntax):
		return mailauth.ErrorSyntax, "invalid DKIM key records"
	case errors.Is(err, dkim.ErrDNS):
		return mailauth.ErrorDNS, "DNS lookup failed"
	case errors.Is(err, dkim.ErrNoRecord):
		return mailauth.ErrorLookup, "DKIM key unavailable"
	case errors.Is(err, dkim.ErrBodyhashMismatch), errors.Is(err, dkim.ErrSigVerify):
		return mailauth.ErrorCrypto, "DKIM signature verification failed"
	case status == dkim.StatusTemperror:
		return mailauth.ErrorDNS, "temporary DKIM verification failure"
	case status == dkim.StatusFail:
		return mailauth.ErrorCrypto, "DKIM signature verification failed"
	default:
		return mailauth.ErrorSyntax, "invalid DKIM signature or key"
	}
}

func classifyDMARC(status dmarc.Status, err error) (mailauth.ErrorCategory, string) {
	if err == nil || status == dmarc.StatusNone && errors.Is(err, dmarc.ErrNoRecord) {
		return mailauth.ErrorNone, ""
	}
	switch {
	case errors.Is(err, dmarc.ErrDNS), status == dmarc.StatusTemperror:
		return mailauth.ErrorDNS, "DNS lookup failed"
	case errors.Is(err, dmarc.ErrNoRecord):
		return mailauth.ErrorLookup, "DMARC policy unavailable"
	default:
		return mailauth.ErrorSyntax, "invalid DMARC policy"
	}
}

func bounded(value string, maxBytes int) string {
	value = strings.ToValidUTF8(strings.TrimSpace(value), "�")
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}
