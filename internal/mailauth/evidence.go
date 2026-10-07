package mailauth

import (
	"context"
	"io"
	"net/netip"
)

// Method identifies an email authentication method.
type Method string

const (
	MethodDKIM  Method = "dkim"
	MethodSPF   Method = "spf"
	MethodDMARC Method = "dmarc"
)

// Outcome is the normalized RFC authentication result. Unknown extension
// values are retained as bounded strings by providers rather than collapsed
// into a misleading standard result.
type Outcome string

const (
	OutcomeNone      Outcome = "none"
	OutcomeNeutral   Outcome = "neutral"
	OutcomePass      Outcome = "pass"
	OutcomeFail      Outcome = "fail"
	OutcomeSoftfail  Outcome = "softfail"
	OutcomePolicy    Outcome = "policy"
	OutcomeTemperror Outcome = "temperror"
	OutcomePermerror Outcome = "permerror"
)

// ErrorCategory is a bounded description of why authentication did not pass.
// It deliberately does not retain resolver errors or unbounded parser text.
type ErrorCategory string

const (
	ErrorNone     ErrorCategory = ""
	ErrorDNS      ErrorCategory = "dns"
	ErrorSyntax   ErrorCategory = "syntax"
	ErrorPolicy   ErrorCategory = "policy"
	ErrorCrypto   ErrorCategory = "cryptographic"
	ErrorLookup   ErrorCategory = "lookup"
	ErrorLimit    ErrorCategory = "resource-limit"
	ErrorInternal ErrorCategory = "internal"
)

// Result is one trusted authentication result and the domain it authenticates.
type Result struct {
	Method        Method
	Outcome       Outcome
	Domain        string
	Aligned       bool
	Reason        string
	ErrorCategory ErrorCategory
	DNSAuthentic  bool

	// DKIM details. There is one Result for every signature, including failures.
	Selector               string
	Identity               string
	Algorithm              string
	HeaderCanonicalization string
	BodyCanonicalization   string
	BodyLengthLimited      bool
	BodyLength             int64

	// SPF details.
	SPFIdentity  string // "mailfrom" or "helo"
	SPFMechanism string

	// DMARC policy details.
	PolicyDomain      string
	PolicyDisposition string
	SubdomainPolicy   string
	DKIMAlignmentMode string
	SPFAlignmentMode  string
	PolicyPercentage  int
	PolicyApplied     bool
	AlignedSPFPass    bool
	AlignedDKIMPass   bool
}

// Evidence is the provider-neutral authentication conclusion for one message.
// Consumers share this single value so policy and prompt rendering cannot
// independently reinterpret authentication headers.
type Evidence struct {
	Results       []Result
	DKIMAligned   bool
	SPFAligned    bool
	DMARCAligned  bool
	VisibleDomain string
}

// Transaction contains standards-derived SMTP inputs available to an
// authentication provider. It intentionally has no dependency on a Milter
// session or on Mox-specific types.
type Transaction struct {
	RemoteIP           netip.Addr
	HELO               string
	EnvelopeSender     string
	ReceiverHostname   string
	ReceiverIP         netip.Addr
	VisibleFromDomain  string
	VisibleFromInvalid bool
	SMTPUTF8           bool
	Message            io.ReaderAt
	MessageSize        int64
	// HeaderVerifier-only inputs. Internal verification leaves these empty and
	// derives evidence from the SMTP fields and byte-exact message above.
	AuthenticationResults []string
	ReceivedSPF           []string
	TrustedAuthservIDs    []string
}

// Verifier supplies authentication evidence for a complete SMTP transaction.
type Verifier interface {
	Verify(context.Context, Transaction) (Evidence, error)
}

// HeaderVerifier derives evidence from Authentication-Results and Received-SPF
// fields written by explicitly trusted local authentication services.
type HeaderVerifier struct{}

func (HeaderVerifier) Verify(_ context.Context, transaction Transaction) (Evidence, error) {
	results := Parse(Input{
		AuthenticationResults: transaction.AuthenticationResults,
		ReceivedSPF:           transaction.ReceivedSPF,
		TrustedAuthservIDs:    transaction.TrustedAuthservIDs,
	})
	return NewEvidence(results, transaction.VisibleFromDomain), nil
}

// NewEvidence normalizes alignment conclusions once for all consumers.
func NewEvidence(results []Result, visibleDomain string) Evidence {
	visibleDomain = NormalizeDomain(visibleDomain)
	evidence := Evidence{Results: append([]Result(nil), results...), VisibleDomain: visibleDomain}
	for index := range evidence.Results {
		result := &evidence.Results[index]
		result.Aligned = result.Outcome == OutcomePass && DomainAligned(result.Domain, visibleDomain)
		if result.Method == MethodDMARC && result.Outcome == OutcomePass &&
			(result.AlignedSPFPass || result.AlignedDKIMPass) {
			// Internal DMARC verification knows which underlying mechanism
			// actually aligned. Prefer that conclusion when it is available;
			// trusted header evidence falls back to domain comparison above.
			result.Aligned = true
		}
		switch result.Method {
		case MethodDKIM:
			evidence.DKIMAligned = evidence.DKIMAligned || result.Aligned
		case MethodSPF:
			evidence.SPFAligned = evidence.SPFAligned || result.Aligned
		case MethodDMARC:
			evidence.DMARCAligned = evidence.DMARCAligned || result.Aligned
		}
	}
	return evidence
}

// EvidenceWithUnavailableMethods preserves existing authentication results and
// adds an internal temporary-error result for each requested method that is
// absent.
func EvidenceWithUnavailableMethods(results []Result, visibleDomain, reason string, methods ...Method) Evidence {
	results = append([]Result(nil), results...)
	for _, method := range methods {
		found := false
		for _, result := range results {
			if result.Method == method {
				found = true
				break
			}
		}
		if !found {
			results = append(results, Result{
				Method: method, Outcome: OutcomeTemperror,
				ErrorCategory: ErrorInternal, Reason: reason,
			})
		}
	}
	return NewEvidence(results, visibleDomain)
}

// AnyAligned reports whether DKIM, SPF or DMARC authenticated the visible domain.
func (e Evidence) AnyAligned() bool { return e.DKIMAligned || e.SPFAligned || e.DMARCAligned }
