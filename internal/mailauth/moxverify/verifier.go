package moxverify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/mjl-/adns"
	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dmarc"
	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/smtp"
	"github.com/mjl-/mox/spf"
)

var (
	ErrInvalidOptions     = errors.New("invalid Mox verifier options")
	ErrMessageUnavailable = errors.New("exact message unavailable for authentication")
	errTooManySignatures  = errors.New("DKIM signature limit exceeded")
)

const maxDKIMSignatures = 32

// Options configures the bounded authentication service.
type Options struct {
	Timeout       time.Duration
	MaxConcurrent int
	Logger        *slog.Logger
}

// Verifier owns the resolver and resource bounds used for authentication.
type Verifier struct {
	timeout  time.Duration
	slots    chan struct{}
	resolver dns.Resolver
	log      *slog.Logger
	run      func(context.Context, mailauth.Transaction) (mailauth.Evidence, error)
}

var _ mailauth.Verifier = (*Verifier)(nil)

// New constructs a verifier with a dedicated strict resolver. It does not use
// either net.DefaultResolver or adns.DefaultResolver.
func New(options Options) (*Verifier, error) {
	if options.Timeout <= 0 {
		return nil, fmt.Errorf("%w: timeout must be positive", ErrInvalidOptions)
	}
	if options.MaxConcurrent <= 0 {
		return nil, fmt.Errorf("%w: max concurrent must be positive", ErrInvalidOptions)
	}
	log := options.Logger
	if log == nil {
		log = slog.Default()
	}
	// Mox debug logging includes complete DNS responses. Give Mox a discard
	// logger and emit only bounded summaries through the service logger below.
	moxLog := slog.New(slog.DiscardHandler)
	resolver := dns.StrictResolver{
		Resolver: &adns.Resolver{PreferGo: true, StrictErrors: true},
		Log:      moxLog,
	}
	verifier := &Verifier{
		timeout: options.Timeout, slots: make(chan struct{}, options.MaxConcurrent),
		resolver: resolver, log: log,
	}
	verifier.run = verifier.verifyTransaction
	return verifier, nil
}

// Verify bounds both queueing and verification by the configured timeout.
func (v *Verifier) Verify(parent context.Context, transaction mailauth.Transaction) (mailauth.Evidence, error) {
	if v == nil || v.run == nil || v.timeout <= 0 || v.slots == nil {
		return mailauth.Evidence{}, fmt.Errorf("%w: verifier is not initialized", ErrInvalidOptions)
	}
	ctx, cancel := context.WithTimeout(parent, v.timeout)
	defer cancel()
	select {
	case v.slots <- struct{}{}:
		defer func() { <-v.slots }()
		if err := ctx.Err(); err != nil {
			return mailauth.Evidence{}, fmt.Errorf("authentication queue: %w", err)
		}
	case <-ctx.Done():
		return mailauth.Evidence{}, fmt.Errorf("authentication queue: %w", ctx.Err())
	}

	started := time.Now()
	evidence, err := v.run(ctx, transaction)
	if contextErr := ctx.Err(); contextErr != nil {
		return mailauth.Evidence{}, fmt.Errorf("authentication verification: %w", contextErr)
	}
	if v.log != nil {
		v.log.DebugContext(ctx, "mail authentication completed",
			"results", len(evidence.Results), "duration", time.Since(started), "error", err)
	}
	return evidence, err
}

func (v *Verifier) verifyTransaction(ctx context.Context, transaction mailauth.Transaction) (mailauth.Evidence, error) {
	spfResult, spfStatus, spfDomain := v.verifySPF(ctx, transaction)
	results := []mailauth.Result{spfResult}
	if err := ctx.Err(); err != nil {
		return mailauth.Evidence{}, err
	}

	if transaction.Message == nil || transaction.MessageSize <= 0 {
		return unavailableMessageEvidence(results, transaction.VisibleFromDomain, "exact message unavailable", nil)
	}

	var finalByte [1]byte
	if n, err := transaction.Message.ReadAt(finalByte[:], transaction.MessageSize-1); n != 1 || err != nil && !errors.Is(err, io.EOF) {
		return unavailableMessageEvidence(results, transaction.VisibleFromDomain, "exact message read failed", err)
	}
	observedMessage := &observedReaderAt{ReaderAt: transaction.Message}
	message := io.NewSectionReader(observedMessage, 0, transaction.MessageSize)
	seenSignatures := 0
	policy := func(signature *dkim.Sig) error {
		seenSignatures++
		if seenSignatures > maxDKIMSignatures {
			return errTooManySignatures
		}
		return dkim.DefaultPolicy(signature)
	}
	dkimResults, err := dkim.Verify(ctx, slog.New(slog.DiscardHandler), v.resolver,
		transaction.SMTPUTF8, policy, message, true)
	if contextErr := ctx.Err(); contextErr != nil {
		return mailauth.Evidence{}, contextErr
	}
	if readErr := observedMessage.Err(); readErr != nil {
		return unavailableMessageEvidence(results, transaction.VisibleFromDomain, "exact message read failed", readErr)
	}
	if err != nil {
		results = append(results, mailauth.Result{
			Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePermerror,
			ErrorCategory: mailauth.ErrorSyntax, Reason: "malformed message headers",
		})
		dkimResults = nil
	} else if len(dkimResults) == 0 {
		results = append(results, mailauth.Result{Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomeNone})
	} else {
		for _, result := range dkimResults[:min(len(dkimResults), maxDKIMSignatures)] {
			results = append(results, translateDKIM(result))
		}
		if len(dkimResults) > maxDKIMSignatures {
			results = append(results, mailauth.Result{
				Method: mailauth.MethodDKIM, Outcome: mailauth.OutcomePolicy,
				ErrorCategory: mailauth.ErrorLimit, Reason: "additional DKIM signatures omitted",
			})
		}
	}

	fromDomain, fromErr := parseDomain(transaction.VisibleFromDomain)
	if fromErr != nil {
		result := mailauth.Result{Method: mailauth.MethodDMARC, Outcome: mailauth.OutcomeNone}
		if strings.TrimSpace(transaction.VisibleFromDomain) != "" {
			result.ErrorCategory = mailauth.ErrorSyntax
			result.Reason = "invalid visible From domain"
		}
		results = append(results, result)
		return mailauth.NewEvidence(results, transaction.VisibleFromDomain), nil
	}

	var spfIdentity *dns.Domain
	if !spfDomain.IsZero() {
		spfIdentity = &spfDomain
	}
	useResult, dmarcResult := dmarc.Verify(ctx, slog.New(slog.DiscardHandler), v.resolver,
		fromDomain, dkimResults, spfStatus, spfIdentity, true)
	translatedDMARC := translateDMARC(dmarcResult, transaction.VisibleFromDomain)
	translatedDMARC.PolicyApplied = useResult
	results = append(results, translatedDMARC)
	evidence := mailauth.NewEvidence(results, transaction.VisibleFromDomain)
	if translatedDMARC.Outcome == mailauth.OutcomePass && (translatedDMARC.AlignedSPFPass || translatedDMARC.AlignedDKIMPass) {
		evidence.DMARCAligned = true
		evidence.Results[len(evidence.Results)-1].Aligned = true
	}
	return evidence, nil
}

func (v *Verifier) verifySPF(ctx context.Context, transaction mailauth.Transaction) (mailauth.Result, spf.Status, dns.Domain) {
	inputFailure := func(outcome mailauth.Outcome, status spf.Status, category mailauth.ErrorCategory, reason string) (mailauth.Result, spf.Status, dns.Domain) {
		return mailauth.Result{Method: mailauth.MethodSPF, Outcome: outcome, ErrorCategory: category, Reason: reason}, status, dns.Domain{}
	}
	remoteIP := addressIP(transaction.RemoteIP)
	if remoteIP == nil {
		return inputFailure(mailauth.OutcomeTemperror, spf.StatusTemperror, mailauth.ErrorInternal, "remote IP unavailable")
	}
	localIP := addressIP(transaction.ReceiverIP)
	if localIP == nil {
		return inputFailure(mailauth.OutcomeTemperror, spf.StatusTemperror, mailauth.ErrorInternal, "receiver IP unavailable")
	}
	localHostname, err := parseDomain(transaction.ReceiverHostname)
	if err != nil {
		return inputFailure(mailauth.OutcomeTemperror, spf.StatusTemperror, mailauth.ErrorInternal, "receiver hostname unavailable")
	}
	helo, err := parseIPDomain(transaction.HELO)
	if err != nil {
		return inputFailure(mailauth.OutcomePermerror, spf.StatusPermerror, mailauth.ErrorSyntax, "invalid HELO identity")
	}

	args := spf.Args{RemoteIP: remoteIP, HelloDomain: helo, LocalIP: localIP, LocalHostname: localHostname}
	sender := strings.TrimSpace(transaction.EnvelopeSender)
	if sender != "" && sender != "<>" {
		if strings.HasPrefix(sender, "<") && strings.HasSuffix(sender, ">") {
			sender = sender[1 : len(sender)-1]
		}
		address, err := smtp.ParseAddress(sender)
		if err != nil {
			return inputFailure(mailauth.OutcomePermerror, spf.StatusPermerror, mailauth.ErrorSyntax, "invalid envelope sender")
		}
		args.MailFromLocalpart = address.Localpart
		args.MailFromDomain = address.Domain
	}

	received, domain, _, authentic, verifyErr := spf.Verify(ctx, slog.New(slog.DiscardHandler), v.resolver, args)
	result := mailauth.Result{
		Method: mailauth.MethodSPF, Outcome: outcome(string(received.Result)),
		Domain: normalizeDomain(domain), DNSAuthentic: authentic,
		SPFIdentity: bounded(string(received.Identity), 16), SPFMechanism: bounded(received.Mechanism, 256),
	}
	result.ErrorCategory, result.Reason = classifySPF(received.Result, verifyErr)
	return result, received.Result, domain
}

func parseDomain(value string) (dns.Domain, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if value == "" {
		return dns.Domain{}, errors.New("empty domain")
	}
	return dns.ParseDomain(value)
}

func parseIPDomain(value string) (dns.IPDomain, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return dns.IPDomain{}, nil
	}
	literal := value
	if strings.HasPrefix(literal, "[") && strings.HasSuffix(literal, "]") {
		literal = literal[1 : len(literal)-1]
		if strings.HasPrefix(strings.ToLower(literal), "ipv6:") {
			literal = literal[len("ipv6:"):]
		}
		address, err := netip.ParseAddr(literal)
		if err != nil {
			return dns.IPDomain{}, err
		}
		return dns.IPDomain{IP: addressIP(address)}, nil
	}
	if address, err := netip.ParseAddr(literal); err == nil {
		return dns.IPDomain{IP: addressIP(address)}, nil
	}
	domain, err := parseDomain(value)
	return dns.IPDomain{Domain: domain}, err
}

func addressIP(address netip.Addr) net.IP {
	if !address.IsValid() {
		return nil
	}
	address = address.Unmap()
	return net.IP(append([]byte(nil), address.AsSlice()...))
}

func unavailableResult(method mailauth.Method, reason string) mailauth.Result {
	return mailauth.Result{Method: method, Outcome: mailauth.OutcomeTemperror, ErrorCategory: mailauth.ErrorInternal, Reason: reason}
}

func unavailableMessageEvidence(results []mailauth.Result, visibleDomain, reason string, cause error) (mailauth.Evidence, error) {
	results = append(results, unavailableResult(mailauth.MethodDKIM, reason), unavailableResult(mailauth.MethodDMARC, reason))
	err := ErrMessageUnavailable
	if cause != nil {
		err = fmt.Errorf("%w: %v", ErrMessageUnavailable, cause)
	}
	return mailauth.NewEvidence(results, visibleDomain), err
}

type observedReaderAt struct {
	io.ReaderAt
	mu  sync.Mutex
	err error
}

func (r *observedReaderAt) ReadAt(payload []byte, offset int64) (int, error) {
	n, err := r.ReaderAt.ReadAt(payload, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		r.mu.Lock()
		r.err = errors.Join(r.err, err)
		r.mu.Unlock()
	}
	return n, err
}

func (r *observedReaderAt) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
