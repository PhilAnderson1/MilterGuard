package milter

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type session struct {
	deps                        *sessionDependencies
	conn                        net.Conn
	reader                      *bufio.Reader
	phase                       protocolPhase
	connected                   bool
	peerIP                      netip.Addr
	peerHostname                string
	mtaHostname                 string
	pendingMTAHostname          string
	receiverIP                  netip.Addr
	pendingReceiverIP           netip.Addr
	heloIdentity                string
	smtpUTF8                    bool
	authentication              authenticationState
	envelopeSender              string
	envelopeRecipients          []string
	envelopeRecipientsTruncated bool
	visibleSender               string
	visibleSenderDomain         string
	connectionDNS               connectionDNSResult
	connectionDNSPending        <-chan connectionDNSResult
	message                     *message.Message
	exactMessage                mailauth.ExactMessage
	exactMessageErr             error
	negotiatedActions           uint32
}

// finishMessage runs policies that need the complete message, obtains an AI
// result when necessary, sends the final Milter response, and schedules the
// resulting reputation and correspondent updates.
func (ss *session) finishMessage(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, ss.deps.analysis.analysisTimeout())
	defer cancel()
	if ss.phase != phaseBody {
		return ss.protocolError("unexpected milter end-of-body command")
	}
	if err := ss.conn.SetDeadline(time.Now().Add(ss.deps.analysis.analysisTimeout())); err != nil {
		if ctx.Err() == nil {
			ss.deps.log.WarnContext(ctx, "cannot set Milter connection deadline",
				"stage", "message processing",
				"local_addr", ss.conn.LocalAddr().String(),
				"remote_addr", ss.conn.RemoteAddr().String(),
				"error", err)
		}
		return false
	}
	if count := ss.message.FromHeaderCount(); count > 1 {
		ss.deps.log.WarnContext(ctx, "message has ambiguous sender identity", "message_id", ss.message.Header("Message-ID"), "from_header_count", count)
	} else {
		ss.visibleSender = mailaddr.Normalize(ss.message.Header("From"))
		ss.visibleSenderDomain = mailaddr.Domain(ss.visibleSender)
	}
	if ss.isInternalMessage() {
		return ss.finishInternalMessage(ctx)
	}
	if handled, keepConnection := ss.handleEmailCommand(ctx); handled {
		return keepConnection
	}
	if handled, keepConnection := ss.applyAuthenticatedOnlySenderDomain(ctx); handled {
		return keepConnection
	}
	if ss.authentication.Authenticated && !ss.deps.filtering.ScanAuthenticated {
		return ss.finishBypassedMessage(ctx, "authenticated_connection", true, false)
	}
	if ss.deps.attachments.enabled() {
		if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
			ss.deps.log.WarnContext(ctx, "cannot send Milter progress response before attachment inspection", "error", err)
			return false
		}
	}
	if handled, keepConnection := ss.applyAttachments(ctx); handled {
		return keepConnection
	}
	authentication := mailauth.Evidence{}
	var progressErr error
	if !ss.internalAuthentication() || !ss.authentication.Authenticated {
		authentication, progressErr = ss.verifyAuthenticationWithProgress(ctx)
	}
	ss.closeExactMessage()
	if progressErr != nil {
		ss.deps.log.WarnContext(ctx, "authentication verification failed", "error", progressErr)
		if ss.internalAuthentication() {
			authentication = mailauth.EvidenceWithUnavailableMethods(authentication.Results, ss.visibleSenderDomain,
				"authentication unavailable", mailauth.MethodSPF, mailauth.MethodDKIM, mailauth.MethodDMARC)
		}
	}
	inbound := ss.deps.policy.prepareInboundEvidence(ctx, ss.messageContext(ss.recipientSetComplete()), authentication, ss.deps.filtering)
	if inbound.allowedSenderDomain != "" {
		return ss.finishBypassedMessage(ctx, "sender_domain_allowlist", false, inbound.knownCorrespondent && inbound.trustRequirementMet,
			"sender_domain", inbound.allowedSenderDomain,
			"aligned_dkim", inbound.alignedDKIM,
			"aligned_spf", inbound.alignedSPF)
	}
	if inbound.bypassAI {
		return ss.finishBypassedMessage(ctx, "known_correspondent", false, inbound.trustRequirementMet,
			ss.knownCorrespondentLogAttrs()...)
	}
	result, progressErr := ss.evaluateWithProgress(ctx, inbound, authentication)
	if progressErr != nil {
		ss.deps.log.WarnContext(ctx, "message analysis with progress failed", "error", progressErr)
		ss.deps.activity.recordScan(ctx, result, progressErr)
		return false
	}
	var err error
	if result.selected == actionAccept {
		err = ss.writeAcceptedResultHeaders(&result)
	}
	if err == nil {
		err = writeFrame(ss.conn, responseForAction(result.selected, ss.deps.filtering.RejectMessage))
	}
	ss.deps.analysis.logOutcome(ctx, ss.message, result, ss.deps.mode, ss.deps.logging.IncludeSubject, err == nil, err)
	ss.deps.activity.recordScan(ctx, result, err)
	if err != nil {
		return false
	}
	ss.applyPostDecisionUpdates(ctx, result, inbound)
	ss.resetMessage(phaseConnection)
	return true
}

// verifyAuthenticationWithProgress keeps all Milter socket writes in the
// session goroutine while a provider performs DNS or cryptographic work.
func (ss *session) verifyAuthenticationWithProgress(ctx context.Context) (mailauth.Evidence, error) {
	verifier := ss.deps.authentication
	envelopeSender := ss.envelopeSender
	if envelopeSender != "<>" {
		envelopeSender = mailaddr.Normalize(envelopeSender)
	}
	transaction := mailauth.Transaction{
		RemoteIP: ss.peerIP, HELO: ss.heloIdentity, EnvelopeSender: envelopeSender,
		ReceiverHostname: ss.mtaHostname, ReceiverIP: ss.receiverIP, VisibleFromDomain: ss.visibleSenderDomain,
		SMTPUTF8: ss.smtpUTF8,
	}
	if !ss.internalAuthentication() {
		transaction.AuthenticationResults = ss.message.HeaderValues("Authentication-Results")
		transaction.ReceivedSPF = ss.message.HeaderValues("Received-SPF")
		transaction.TrustedAuthservIDs = ss.trustedAuthservIDs()
	}
	if ss.exactMessageErr == nil && ss.exactMessage != nil {
		reader, size, err := ss.exactMessage.ReaderAt()
		if err != nil {
			ss.exactMessageErr = err
		} else {
			transaction.Message, transaction.MessageSize = reader, size
		}
	}
	if ss.exactMessageErr != nil {
		ss.deps.log.DebugContext(ctx, "exact authentication input unavailable", "error", ss.exactMessageErr)
	}

	type verificationResult struct {
		evidence mailauth.Evidence
		err      error
	}
	results := make(chan verificationResult, 1)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	go func() {
		result := verificationResult{}
		defer func() {
			if panicValue := recover(); panicValue != nil {
				logRecoveredWorkerPanic(ss.deps.log, workerCtx, "authentication verification", panicValue)
				result.err = fmt.Errorf("authentication verification panic: %v", panicValue)
			}
			results <- result
		}()
		result.evidence, result.err = verifier.Verify(workerCtx, transaction)
	}()

	interval := ss.deps.protocol.progressInterval
	if interval <= 0 {
		interval = defaultMilterProgressInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case result := <-results:
			return result.evidence, result.err
		case <-ctx.Done():
			cancelWorker()
			<-results
			return mailauth.Evidence{}, fmt.Errorf("authentication verification interrupted: %w", ctx.Err())
		case <-ticker.C:
			if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
				cancelWorker()
				<-results
				return mailauth.Evidence{}, fmt.Errorf("send authentication progress response: %w", err)
			}
		}
	}
}

// evaluateWithProgress runs potentially slow message analysis in a worker and
// sends periodic progress frames so the MTA does not time out the transaction.
func (ss *session) evaluateWithProgress(ctx context.Context, inbound inboundEvidence, authentication mailauth.Evidence) (evaluationResult, error) {
	started := time.Now()
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	results := make(chan evaluationResult, 1)
	go func() {
		defer func() {
			if panicValue := recover(); panicValue != nil {
				logRecoveredWorkerPanic(ss.deps.log, workerCtx, "message analysis", panicValue)
				results <- ss.deps.analysis.analysisFailure(fmt.Errorf("message analysis panic: %v", panicValue), started, ss.deps.mode, ss.deps.filtering.AIErrorAction)
			}
		}()
		results <- ss.evaluateMessage(workerCtx, inbound, authentication)
	}()

	interval := ss.deps.protocol.progressInterval
	if interval <= 0 {
		interval = defaultMilterProgressInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case result := <-results:
			return result, nil
		case <-ctx.Done():
			cancelWorker()
			result := <-results
			return result, fmt.Errorf("message analysis interrupted: %w", ctx.Err())
		case <-ticker.C:
			if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
				cancelWorker()
				result := <-results
				return result, fmt.Errorf("send Milter progress response: %w", err)
			}
		}
	}
}

// evaluateMessage adds lazily obtained domain and connection evidence before
// handing the completed message to the analysis service.
func (ss *session) evaluateMessage(ctx context.Context, inbound inboundEvidence, authentication mailauth.Evidence) evaluationResult {
	analysisContext := message.AnalysisContext{
		AuthenticatedSubmission: ss.authentication.Authenticated,
		Authentication:          authentication,
		Correspondent:           inbound.correspondent,
	}
	if inbound.authenticatedDomain != "" {
		info, err := ss.deps.policy.domainRegistrationEvidence(ctx, inbound.authenticatedDomain)
		if err != nil {
			ss.deps.log.DebugContext(ctx, "domain registration evidence unavailable", "domain", registrableDomain(inbound.authenticatedDomain), "error", err)
		} else {
			analysisContext.DomainRegistration = info
		}
	}
	analysisContext.Connection = ss.connectionInformation(ctx)
	return ss.deps.analysis.evaluate(ctx, ss.message, analysisContext, ss.deps.mode, ss.deps.filtering.RejectScore,
		ss.deps.filtering.AIErrorAction, ss.deps.logging.IncludeAIInput)
}

func (ss *session) finishInternalMessage(ctx context.Context) bool {
	if ss.negotiatedActions&actionChangeHeaders == 0 {
		ss.deps.log.ErrorContext(ctx, "cannot safely accept internal command reply because MTA did not offer header removal")
		if err := writeFrame(ss.conn, []byte{responseTempfail}); err != nil {
			return false
		}
		ss.resetMessage(phaseConnection)
		return true
	}
	for range ss.message.HeaderOccurrences(internalMessageHeader) {
		if err := writeFrame(ss.conn, deleteHeaderResponse(internalMessageHeader)); err != nil {
			return false
		}
	}
	return ss.finishBypassedMessage(ctx, "internal_command_reply", false, false)
}

func (ss *session) knownCorrespondentLogAttrs() []any {
	attrs := []any{"correspondent", ss.visibleSender}
	seen := make(map[string]bool, len(ss.envelopeRecipients))
	localAddresses := make([]string, 0, len(ss.envelopeRecipients))
	for _, recipient := range ss.envelopeRecipients {
		recipient = mailaddr.Normalize(recipient)
		if recipient == "" || seen[recipient] {
			continue
		}
		seen[recipient] = true
		localAddresses = append(localAddresses, recipient)
	}
	if len(localAddresses) == 1 {
		return append(attrs, "local_address", localAddresses[0])
	}
	return append(attrs, "local_addresses", localAddresses)
}

func (ss *session) recipientSetComplete() bool {
	if ss.envelopeRecipientsTruncated || len(ss.envelopeRecipients) == 0 {
		return false
	}
	for _, recipient := range ss.envelopeRecipients {
		if mailaddr.Normalize(recipient) == "" {
			return false
		}
	}
	return true
}

func (ss *session) applyPostDecisionUpdates(ctx context.Context, result evaluationResult, inbound inboundEvidence) {
	if ss.deps.mode != "enforce" {
		return
	}
	ss.deps.policy.applyPostDecisionUpdates(ctx, ss.messageContext(inbound.recipientsComplete), result, inbound, ss.deps.filtering.RejectScore)
}

func (ss *session) finishBypassedMessage(ctx context.Context, source string, learn, touchInbound bool, extraAttrs ...any) bool {
	err := ss.writeAcceptedBypassHeaders()
	if err == nil {
		err = writeFrame(ss.conn, responseForAction(actionAccept, ss.deps.filtering.RejectMessage))
	}
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.deps.mode,
		"actual_action", actionAccept.String(),
		"source", source,
		"response_sent", err == nil,
	}
	attrs = append(attrs, extraAttrs...)
	attrs = ss.appendDecisionSubject(attrs)
	switch source {
	case "known_correspondent":
		ss.deps.activity.recordDeterministic(ctx, stores.ActivityEventCorrespondentAccept, actionAccept, err)
	case "sender_domain_allowlist":
		ss.deps.activity.recordDeterministic(ctx, stores.ActivityEventTrustedDomainAccept, actionAccept, err)
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "message bypass response failed", attrs...)
		return false
	}
	if ss.deps.mode == "enforce" {
		if !ss.authentication.Authenticated && (source == "known_correspondent" || source == "sender_domain_allowlist") {
			ss.deps.policy.recordLegitimateIP(ctx, ss.peerIP)
		}
		if learn {
			ss.learnAuthenticatedRecipients(ctx)
		}
		if touchInbound {
			ss.touchInboundCorrespondent(ctx)
		}
	}
	if source == "internal_command_reply" {
		ss.deps.log.DebugContext(ctx, "message bypassed AI analysis", attrs...)
	} else {
		ss.deps.log.InfoContext(ctx, "message bypassed AI analysis", attrs...)
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) touchInboundCorrespondent(ctx context.Context) {
	ss.deps.policy.touchInboundCorrespondent(ctx, ss.visibleSender, ss.envelopeRecipients)
}

func (ss *session) learnAuthenticatedRecipients(ctx context.Context) {
	ss.deps.policy.learnAuthenticatedRecipients(ctx, ss.envelopeSender, ss.envelopeRecipients)
}

func (ss *session) messageContext(recipientsComplete bool) messageContext {
	return messageContext{
		message: ss.message, peerIP: ss.peerIP, connectionDNS: ss.connectionDNS,
		authenticated: ss.authentication.Authenticated, visibleSender: ss.visibleSender,
		visibleSenderDomain: ss.visibleSenderDomain, envelopeSender: ss.envelopeSender,
		envelopeRecipients: append([]string(nil), ss.envelopeRecipients...), recipientsComplete: recipientsComplete,
	}
}

func (ss *session) rejectReputationIP(ctx context.Context) (bool, bool) {
	ctx, cancel := context.WithTimeout(ctx, ss.deps.protocol.timeout)
	defer cancel()
	if ss.deps.mode != "enforce" || ss.authentication.Authenticated {
		return false, true
	}
	if _, allowed := ss.deps.policy.ipReputation.allowed(ss.peerIP); allowed {
		return false, true
	}
	if ss.deps.policy.ipReputation.usesDomainAllowlist() {
		dns := ss.awaitConnectionDNS(ctx)
		if hostname, domain, allowed := ss.deps.policy.ipReputation.domainAllowed(dns); allowed {
			ss.deps.log.DebugContext(ctx, "sending IP block bypassed by reverse-DNS domain allowlist",
				"remote_ip", ss.peerIP.String(), "reverse_dns", hostname, "matched_domain", domain)
			return false, true
		}
	}
	entry, ok := ss.deps.policy.ipReputation.lookup(ctx, ss.peerIP)
	if !ok {
		return false, true
	}
	rejectMessage := ss.deps.policy.ipReputation.rejectMessage
	if rejectMessage == "" {
		rejectMessage = ss.deps.filtering.RejectMessage
	}
	err := writeFrame(ss.conn, responseForAction(actionReject, rejectMessage))
	ss.deps.activity.recordDeterministic(ctx, stores.ActivityEventIPRejection, actionReject, err)
	attrs := []any{
		"remote_ip", ss.peerIP.String(),
		"mode", ss.deps.mode,
		"proposed_action", actionReject.String(),
		"actual_action", actionReject.String(),
		"source", "rejected_ip_reputation",
		"block_level", entry.Level,
		"strike_count", entry.StrikeCount,
		"block_expires_at", entry.ExpiresAt,
		"block_remaining_ms", time.Until(entry.ExpiresAt).Milliseconds(),
		"response_sent", err == nil,
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "message rejected by sending IP reputation", attrs...)
		return true, false
	}
	ss.deps.log.InfoContext(ctx, "message rejected by sending IP reputation", attrs...)
	return true, true
}
