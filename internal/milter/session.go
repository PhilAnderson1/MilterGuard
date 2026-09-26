package milter

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

type protocolPhase uint8

type authenticationState struct {
	Authenticated bool
	Identity      string
}

const (
	phaseNegotiation protocolPhase = iota
	phaseConnection
	phaseEnvelope
	phaseBody
)

const maxEnvelopeRecipients = 100

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

func newSession(deps *sessionDependencies, conn net.Conn) *session {
	ss := &session{deps: deps, conn: conn, reader: bufio.NewReader(conn)}
	ss.resetMessage(phaseNegotiation)
	return ss
}

// run owns one Milter connection until EOF, cancellation, or a protocol or
// transport failure. Message state is reset between transactions on the same
// connection.
func (ss *session) run(ctx context.Context) {
	stopClose := context.AfterFunc(ctx, func() {
		_ = ss.conn.Close()
	})
	defer stopClose()
	defer ss.closeExactMessage()
	for {
		deadline := time.Now().Add(ss.deps.protocol.timeout)
		if err := ss.conn.SetDeadline(deadline); err != nil {
			if ctx.Err() == nil {
				ss.deps.log.Warn("cannot set Milter connection deadline",
					"stage", "protocol read",
					"local_addr", ss.conn.LocalAddr().String(),
					"remote_addr", ss.conn.RemoteAddr().String(),
					"error", err)
			}
			return
		}
		frame, bytesRead, err := readFrameProgress(ss.reader)
		if err != nil {
			if ss.handleReadError(ctx, bytesRead, err) {
				continue
			}
			return
		}
		if !ss.handleCommand(ctx, frame[0], frame[1:]) {
			return
		}
	}
}

// Protocol command handling

func (ss *session) handleReadError(ctx context.Context, bytesRead int, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if bytesRead == 0 {
			return true
		}
		ss.deps.log.Warn("milter connection timed out during frame", "bytes_read", bytesRead, "error", err)
		return false
	}
	if err != io.EOF {
		ss.deps.log.Warn("milter connection error", "error", err)
	}
	return false
}

func (ss *session) handleCommand(ctx context.Context, command byte, payload []byte) bool {
	// MACRO is explicitly allowed at any point for forward compatibility.
	if ss.phase == phaseNegotiation && command != commandOptionNegotiation && command != commandMacro && command != commandQuit {
		return ss.protocolError("milter command before option negotiation", "command", commandName(command))
	}

	switch command {
	case commandOptionNegotiation:
		return ss.negotiate(payload)
	case commandMacro:
		ss.captureSessionMacros(payload)
		return true
	case commandAbort:
		ss.resetMessage(phaseConnection)
		return true
	case commandQuitConnection:
		ss.connected = false
		ss.peerIP = netip.Addr{}
		ss.peerHostname = ""
		ss.mtaHostname = ""
		ss.pendingMTAHostname = ""
		ss.receiverIP = netip.Addr{}
		ss.pendingReceiverIP = netip.Addr{}
		ss.heloIdentity = ""
		ss.authentication = authenticationState{}
		ss.connectionDNS = connectionDNSResult{status: message.ReverseDNSNotApplicable}
		ss.connectionDNSPending = nil
		ss.resetMessage(phaseConnection)
		return true
	case commandConnect:
		if ss.phase != phaseConnection || ss.connected {
			return ss.protocolError("unexpected milter CONNECT command")
		}
		ss.connected = true
		ss.mtaHostname = ss.pendingMTAHostname
		ss.pendingMTAHostname = ""
		ss.receiverIP = ss.pendingReceiverIP
		ss.pendingReceiverIP = netip.Addr{}
		ss.peerIP = netip.Addr{}
		ss.peerHostname = ""
		ss.heloIdentity = ""
		ss.authentication = authenticationState{}
		ss.connectionDNS = connectionDNSResult{status: message.ReverseDNSNotApplicable}
		ss.connectionDNSPending = nil
		if hostname, ok := parseConnectHostname(payload); ok {
			ss.peerHostname = cleanSMTPIdentity(hostname)
		}
		if addr, ok := parseConnectIP(payload); ok {
			ss.peerIP = addr
			ss.startConnectionDNS(ctx)
		} else {
			ss.deps.log.Debug("milter CONNECT did not provide a usable IP address")
		}
		return ss.sendContinue(command)
	case commandHelo:
		if ss.phase != phaseConnection || !ss.connected {
			return ss.protocolError("milter HELO command without active connection")
		}
		ss.heloIdentity = ""
		if identity, ok := parseSMTPIdentity(payload); ok {
			ss.heloIdentity = cleanSMTPIdentity(identity)
		}
		return ss.sendContinue(command)
	case commandMail:
		if ss.phase != phaseConnection || !ss.connected {
			return ss.protocolError("milter MAIL command without active connection")
		}
		if blocked, keepConnection := ss.rejectReputationIP(ctx); blocked {
			return keepConnection
		}
		ss.resetMessage(phaseEnvelope)
		if sender, ok := parseEnvelopeAddress(payload); ok {
			ss.envelopeSender = sender
		}
		return ss.sendContinue(command)
	case commandRecipient:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("milter transaction command outside message", "command", commandName(command))
		}
		if recipient, ok := parseEnvelopeAddress(payload); ok && len(ss.envelopeRecipients) < maxEnvelopeRecipients {
			ss.envelopeRecipients = append(ss.envelopeRecipients, recipient)
		} else if ok {
			ss.envelopeRecipientsTruncated = true
		}
		return ss.sendContinue(command)
	case commandData:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("milter transaction command outside message", "command", commandName(command))
		}
		return ss.sendContinue(command)
	case commandUnknown:
		return ss.sendContinue(command)
	case commandHeader:
		return ss.addHeader(payload)
	case commandEndHeaders:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("unexpected milter end-of-headers command")
		}
		ss.phase = phaseBody
		ss.captureExact(func(exact mailauth.ExactMessage) error { return exact.EndHeaders() })
		return ss.sendContinue(command)
	case commandBody:
		if ss.phase != phaseBody {
			return ss.protocolError("milter body outside body phase")
		}
		ss.message.AddBody(payload)
		ss.captureExact(func(exact mailauth.ExactMessage) error { return exact.AddBody(payload) })
		return ss.sendContinue(command)
	case commandEndBody:
		if ss.phase != phaseBody {
			return ss.protocolError("unexpected milter end-of-body command")
		}
		if len(payload) > 0 {
			ss.message.AddBody(payload)
			ss.captureExact(func(exact mailauth.ExactMessage) error { return exact.AddBody(payload) })
		}
		return ss.finishMessage(ctx)
	case commandQuit:
		return false
	default:
		return ss.protocolError("unsupported milter command", "command", commandName(command))
	}
}

func (ss *session) negotiate(payload []byte) bool {
	if ss.phase != phaseNegotiation || len(payload) != optionPayloadBytes {
		return ss.protocolError("invalid milter option negotiation", "payload_bytes", len(payload), "repeated", ss.phase != phaseNegotiation)
	}
	version := binary.BigEndian.Uint32(payload[:4])
	offeredActions := binary.BigEndian.Uint32(payload[4:8])
	if version < minimumProtocolVersion {
		return ss.protocolError("unsupported milter protocol version", "version", version)
	}
	if version > supportedProtocolVersion {
		version = supportedProtocolVersion
	}
	// Request result-header capabilities even when result generation is disabled:
	// sender-supplied X-MilterGuard result headers must still be removable.
	requestedActions := offeredActions & resultHeaderActions
	wantsResultHeaders := ss.deps.filtering.AddEmailHeaders || ss.deps.mode == "tag"
	if wantsResultHeaders && offeredActions&actionAddHeaders == 0 {
		ss.deps.log.Warn("result headers disabled for Milter connection because MTA did not offer add-header support",
			"offered_actions", offeredActions)
	}
	wantsInternalHeaderRemoval := ss.deps.commands.cfg.Enabled && ss.deps.commands.cfg.SendReplies
	if wantsInternalHeaderRemoval && offeredActions&actionChangeHeaders == 0 {
		ss.deps.log.Warn("internal reply protection disabled for Milter connection because MTA did not offer change-header support",
			"offered_actions", offeredActions)
	}
	ss.negotiatedActions = requestedActions
	if !ss.send(commandOptionNegotiation, optionResponse(version, requestedActions)) {
		return false
	}
	ss.phase = phaseConnection
	return true
}

func (ss *session) addHeader(payload []byte) bool {
	if ss.phase != phaseEnvelope {
		return ss.protocolError("milter header outside header phase")
	}
	name, value, ok := parseHeader(payload)
	if !ok {
		return ss.protocolError("malformed milter header command")
	}
	ss.message.AddHeader(name, value)
	ss.captureExact(func(exact mailauth.ExactMessage) error { return exact.AddHeader(name, value) })
	return ss.sendContinue(commandHeader)
}

// End-of-message policy evaluation

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
		ss.visibleSenderDomain = emailAddressDomain(ss.visibleSender)
	}
	if ss.isInternalMessage() {
		return ss.finishInternalMessage(ctx)
	}
	if handled, keepConnection := ss.handleEmailCommand(ctx); handled {
		return keepConnection
	}
	ss.message.AuthenticatedSubmission = ss.authentication.Authenticated
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
	authentication, progressErr := ss.verifyAuthenticationWithProgress(ctx)
	ss.closeExactMessage()
	if progressErr != nil {
		ss.deps.log.WarnContext(ctx, "authentication verification failed", "error", progressErr)
	}
	ss.message.Authentication = authentication
	inbound := ss.deps.policy.prepareInboundEvidence(ctx, ss.messageContext(ss.recipientSetComplete()), authentication, ss.deps.filtering)
	if inbound.allowedSenderDomain != "" {
		return ss.finishBypassedMessage(ctx, "sender_domain_allowlist", false, inbound.knownCorrespondent && inbound.trustedDKIM,
			"sender_domain", inbound.allowedSenderDomain,
			"trusted_aligned_dkim", inbound.trustedDKIM)
	}
	if inbound.bypassAI {
		return ss.finishBypassedMessage(ctx, "known_correspondent", false, inbound.trustedDKIM,
			ss.knownCorrespondentLogAttrs()...)
	}
	result, progressErr := ss.evaluateWithProgress(ctx, inbound)
	if progressErr != nil {
		ss.deps.log.WarnContext(ctx, "message analysis with progress failed", "error", progressErr)
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
	if verifier == nil {
		verifier = mailauth.HeaderVerifier{}
	}
	envelopeSender := ss.envelopeSender
	if envelopeSender != "<>" {
		envelopeSender = mailaddr.Normalize(envelopeSender)
	}
	transaction := mailauth.Transaction{
		RemoteIP: ss.peerIP, HELO: ss.heloIdentity, EnvelopeSender: envelopeSender,
		ReceiverHostname: ss.mtaHostname, ReceiverIP: ss.receiverIP, VisibleFromDomain: ss.visibleSenderDomain,
		AuthenticationResults: append([]string(nil), ss.message.Headers["authentication-results"]...),
		ReceivedSPF:           append([]string(nil), ss.message.Headers["received-spf"]...),
		TrustedAuthservIDs:    ss.trustedAuthservIDs(),
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
func (ss *session) evaluateWithProgress(ctx context.Context, inbound inboundEvidence) (evaluationResult, error) {
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
		results <- ss.evaluateMessage(workerCtx, inbound)
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
			<-results
			return evaluationResult{}, fmt.Errorf("message analysis interrupted: %w", ctx.Err())
		case <-ticker.C:
			if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
				cancelWorker()
				<-results
				return evaluationResult{}, fmt.Errorf("send Milter progress response: %w", err)
			}
		}
	}
}

// evaluateMessage adds lazily obtained domain and connection evidence before
// handing the completed message to the analysis service.
func (ss *session) evaluateMessage(ctx context.Context, inbound inboundEvidence) evaluationResult {
	if inbound.authenticatedDomain != "" {
		info, err := ss.deps.policy.domainRegistrationEvidence(ctx, inbound.authenticatedDomain)
		if err != nil {
			ss.deps.log.DebugContext(ctx, "domain registration evidence unavailable", "domain", registrableDomain(inbound.authenticatedDomain), "error", err)
		} else {
			ss.message.DomainRegistration = info
		}
	}
	ss.message.Connection = ss.connectionInformation(ctx)
	return ss.deps.analysis.evaluate(ctx, ss.message, ss.deps.mode, ss.deps.filtering.RejectScore,
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

// Authentication, correspondent, and connection evidence

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

// Post-decision state updates

func (ss *session) applyPostDecisionUpdates(ctx context.Context, result evaluationResult, inbound inboundEvidence) {
	if ss.deps.mode != "enforce" {
		return
	}
	ss.deps.policy.applyPostDecisionUpdates(ctx, ss.messageContext(inbound.recipientsComplete), result, inbound, ss.deps.filtering.RejectScore)
}

func (ss *session) captureSessionMacros(payload []byte) {
	target, values, valid := parseSessionMacros(payload)
	if !valid {
		ss.deps.log.Debug("ignored malformed milter macro data")
		return
	}
	if values.MTAHostnameFound {
		hostname := validMTAHostname(values.MTAHostname)
		if target == commandConnect {
			ss.pendingMTAHostname = hostname
		} else if ss.connected {
			ss.mtaHostname = hostname
		}
	}
	if values.ReceiverAddressFound {
		address := canonicalMacroIP(values.ReceiverAddress)
		if target == commandConnect {
			ss.pendingReceiverIP = address
		} else if ss.connected {
			ss.receiverIP = address
		}
	}
	if !ss.connected || !values.AuthenticationFound || (target != commandMail && target != commandData && target != commandEndHeaders && target != commandEndBody) {
		return
	}
	identity := cleanSMTPIdentity(values.AuthenticationIdentity)
	ss.authentication = authenticationState{Authenticated: identity != "", Identity: identity}
}

func canonicalMacroIP(value string) netip.Addr {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	if strings.HasPrefix(strings.ToLower(value), "ipv6:") {
		value = value[len("ipv6:"):]
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return netsafety.CanonicalIP(address)
}

func (ss *session) trustedAuthservIDs() []string {
	return ss.deps.policy.trustedAuthservIDs(ss.mtaHostname)
}

func validMTAHostname(value string) string {
	value = netsafety.DNSHostname(value)
	if value == "" {
		return ""
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return ""
	}
	return value
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
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "message bypass response failed", attrs...)
		return false
	}
	if ss.deps.mode == "enforce" {
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

func (ss *session) startConnectionDNS(ctx context.Context) {
	ss.connectionDNSPending = ss.deps.dns.start(ctx, ss.peerIP)
}

func (ss *session) connectionInformation(ctx context.Context) message.ConnectionInfo {
	ss.awaitConnectionDNS(ctx)
	info := message.ConnectionInfo{
		MTAReportedHostname: ss.peerHostname,
		HELOIdentity:        ss.heloIdentity,
		ReverseDNSStatus:    ss.connectionDNS.status,
		ReverseDNS:          append([]message.ReverseDNSName(nil), ss.connectionDNS.names...),
	}
	if ss.envelopeSender == "<>" {
		info.EnvelopeSender = "<>"
	} else {
		info.EnvelopeSender = mailaddr.Normalize(ss.envelopeSender)
	}
	if ss.peerIP.IsValid() {
		info.RemoteIP = ss.peerIP.String()
	}
	return info
}

func (ss *session) awaitConnectionDNS(ctx context.Context) connectionDNSResult {
	if ss.connectionDNSPending != nil {
		select {
		case ss.connectionDNS = <-ss.connectionDNSPending:
		case <-ctx.Done():
			ss.connectionDNS = connectionDNSResult{status: message.ReverseDNSLookupFailed}
		}
		ss.connectionDNSPending = nil
	}
	return ss.connectionDNS
}

func cleanSMTPIdentity(value string) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") || strings.EqualFold(value, "[unknown]") {
		return ""
	}
	if utf8.RuneCountInString(value) > 255 {
		value = string([]rune(value)[:255])
	}
	return value
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
	err := writeFrame(ss.conn, responseForAction(actionReject, ss.deps.filtering.RejectMessage))
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

// Milter response writing and session reset

func (ss *session) resetMessage(phase protocolPhase) {
	ss.closeExactMessage()
	ss.message = message.New(ss.deps.protocol.maxMessageSize)
	ss.exactMessageErr = nil
	ss.envelopeSender = ""
	ss.envelopeRecipients = nil
	ss.envelopeRecipientsTruncated = false
	ss.visibleSender = ""
	ss.visibleSenderDomain = ""
	ss.phase = phase
	if phase != phaseEnvelope {
		ss.exactMessage = nil
		return
	}
	storage := ss.deps.protocol.exactStorage
	if storage == "" {
		storage = "memory"
	}
	factory := ss.deps.newExactMessage
	if factory == nil {
		factory = mailauth.NewExactMessage
	}
	ss.exactMessage, ss.exactMessageErr = factory(storage, ss.deps.protocol.maxMessageSize)
}

func (ss *session) captureExact(write func(mailauth.ExactMessage) error) {
	if ss.exactMessage == nil || ss.exactMessageErr != nil {
		return
	}
	if err := write(ss.exactMessage); err != nil {
		ss.exactMessageErr = err
	}
}

func (ss *session) closeExactMessage() {
	if ss.exactMessage == nil {
		return
	}
	if err := ss.exactMessage.Close(); err != nil && ss.exactMessageErr == nil {
		ss.exactMessageErr = err
	}
	ss.exactMessage = nil
}

func (ss *session) sendContinue(command byte) bool {
	return ss.send(command, []byte{responseContinue})
}

func (ss *session) send(command byte, response []byte) bool {
	if err := writeFrame(ss.conn, response); err != nil {
		ss.deps.log.Warn("cannot send milter response", "command", commandName(command), "error", err)
		return false
	}
	return true
}

func (ss *session) protocolError(message string, attrs ...any) bool {
	ss.deps.log.Warn(message, attrs...)
	return false
}

func commandName(command byte) string {
	return fmt.Sprintf("0x%02x", command)
}
