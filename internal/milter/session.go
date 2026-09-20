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

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
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
	negotiatedActions           uint32
}

func newSession(deps *sessionDependencies, conn net.Conn) *session {
	ss := &session{deps: deps, conn: conn, reader: bufio.NewReader(conn)}
	ss.resetMessage(phaseNegotiation)
	return ss
}

func (ss *session) run(ctx context.Context) {
	stopClose := context.AfterFunc(ctx, func() {
		_ = ss.conn.Close()
	})
	defer stopClose()
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
		return ss.sendContinue(command)
	case commandBody:
		if ss.phase != phaseBody {
			return ss.protocolError("milter body outside body phase")
		}
		ss.message.AddBody(payload)
		return ss.sendContinue(command)
	case commandEndBody:
		if ss.phase != phaseBody {
			return ss.protocolError("unexpected milter end-of-body command")
		}
		if len(payload) > 0 {
			ss.message.AddBody(payload)
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
	wantsResultHeaders := ss.deps.policy.filtering.AddEmailHeaders || ss.deps.protocol.mode == "tag"
	if wantsResultHeaders && offeredActions&actionAddHeaders == 0 {
		ss.deps.log.Warn("result headers disabled for Milter connection because MTA did not offer add-header support",
			"offered_actions", offeredActions)
	}
	wantsInternalHeaderRemoval := ss.deps.commands != nil && ss.deps.commands.cfg.Enabled && ss.deps.commands.cfg.SendReplies
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
	return ss.sendContinue(commandHeader)
}

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
	ss.visibleSender = normalizeEmailAddress(ss.message.Header("From"))
	ss.visibleSenderDomain = emailAddressDomain(ss.visibleSender)
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
	if ss.authentication.Authenticated && !ss.deps.policy.filtering.ScanAuthenticated {
		return ss.finishBypassedMessage(ctx, "authenticated_connection", true, false)
	}
	if ss.deps.attachments != nil && ss.deps.attachments.scanner != nil {
		if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
			ss.deps.log.WarnContext(ctx, "cannot send Milter progress response before attachment inspection", "error", err)
			return false
		}
	}
	if handled, keepConnection := ss.applyAttachments(ctx); handled {
		return keepConnection
	}
	inbound := ss.prepareInboundEvidence(ctx)
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
		ss.deps.log.WarnContext(ctx, "cannot send Milter progress response", "error", progressErr)
		return false
	}
	var err error
	if result.selected == actionAccept {
		err = ss.writeAcceptedResultHeaders(&result)
	}
	if err == nil {
		err = writeFrame(ss.conn, ss.deps.analysis.encodeAction(result.selected))
	}
	ss.deps.analysis.logOutcome(ctx, ss.message, result, err == nil, err)
	if err != nil {
		return false
	}
	ss.applyPostDecisionUpdates(ctx, result, inbound)
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) evaluateWithProgress(ctx context.Context, inbound inboundEvidence) (evaluationResult, error) {
	started := time.Now()
	workerCtx, cancelWorker := context.WithCancel(ctx)
	defer cancelWorker()
	results := make(chan evaluationResult, 1)
	go func() {
		defer func() {
			if panicValue := recover(); panicValue != nil {
				logRecoveredWorkerPanic(ss.deps.log, workerCtx, "message analysis", panicValue)
				results <- ss.deps.analysis.analysisFailure(fmt.Errorf("message analysis panic: %v", panicValue), started)
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
			return evaluationResult{}, ctx.Err()
		case <-ticker.C:
			if err := writeFrame(ss.conn, []byte{responseProgress}); err != nil {
				cancelWorker()
				<-results
				return evaluationResult{}, err
			}
		}
	}
}

func (ss *session) evaluateMessage(ctx context.Context, inbound inboundEvidence) evaluationResult {
	if inbound.authenticatedDomain != "" {
		info, err := ss.deps.policy.domainRegistration.evidence(ctx, inbound.authenticatedDomain)
		if err != nil {
			ss.deps.log.DebugContext(ctx, "domain registration lookup unavailable", "domain", registrableDomain(inbound.authenticatedDomain), "error", err)
		} else {
			ss.message.DomainRegistration = info
		}
	}
	ss.message.TrustedAuthservIDs = ss.trustedAuthservIDs()
	ss.message.Connection = ss.connectionInformation(ctx)
	return ss.deps.analysis.evaluate(ctx, ss.message)
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
		recipient = normalizeEmailAddress(recipient)
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

type inboundEvidence struct {
	recipientsComplete  bool
	trustedDKIM         bool
	knownCorrespondent  bool
	bypassAI            bool
	allowedSenderDomain string
	authenticatedDomain string
}

func (ss *session) prepareInboundEvidence(ctx context.Context) inboundEvidence {
	evidence := inboundEvidence{recipientsComplete: ss.recipientSetComplete()}
	if ss.authentication.Authenticated {
		return evidence
	}
	authentication := trustedSenderAuthentication(ss.message, ss.trustedAuthservIDs(), ss.visibleSenderDomain)
	evidence.trustedDKIM = authentication.DKIMAligned
	if authentication.anyAligned() {
		evidence.authenticatedDomain = ss.visibleSenderDomain
	}
	if domain := allowedSenderDomain(ss.visibleSenderDomain, ss.deps.policy.filtering.SenderDomainAllowlist); domain != "" &&
		(!ss.deps.policy.filtering.SenderDomainAllowlistRequireDKIM || authentication.DKIMAligned) {
		evidence.allowedSenderDomain = domain
	}
	if !ss.deps.policy.correspondentCfg.UseAllowlist {
		return evidence
	}
	match, err := ss.deps.policy.correspondents.Match(ctx, ss.visibleSender, ss.envelopeRecipients)
	if err != nil && ss.deps.log != nil {
		ss.deps.log.ErrorContext(ctx, "correspondent database operation failed", "operation", "match correspondent", "error", err)
	}
	known := match.Known
	if ss.deps.policy.correspondentCfg.Scope == "per_sender" && ss.deps.policy.correspondentCfg.RecipientMatch == "all" {
		known = evidence.recipientsComplete && match.AllRecipientsMatched
	}
	evidence.knownCorrespondent = known
	ss.message.Correspondent = message.CorrespondentInfo{
		Enabled:               true,
		Known:                 known,
		Scope:                 ss.deps.policy.correspondentCfg.Scope,
		AuthenticationAligned: known && authentication.anyAligned(),
	}
	bypassAuthentication := !ss.deps.policy.correspondentCfg.RequireDKIMForBypass || authentication.DKIMAligned
	evidence.bypassAI = ss.deps.policy.correspondentCfg.BypassAI && evidence.recipientsComplete && known && bypassAuthentication
	return evidence
}

func (ss *session) recipientSetComplete() bool {
	if ss.envelopeRecipientsTruncated || len(ss.envelopeRecipients) == 0 {
		return false
	}
	for _, recipient := range ss.envelopeRecipients {
		if normalizeEmailAddress(recipient) == "" {
			return false
		}
	}
	return true
}

func (ss *session) applyPostDecisionUpdates(ctx context.Context, result evaluationResult, inbound inboundEvidence) {
	ss.deps.policy.applyPostDecisionUpdates(ctx, ss.messageContext(inbound.recipientsComplete), result, inbound)
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
	if !ss.connected || !values.AuthenticationFound || (target != commandMail && target != commandData && target != commandEndHeaders && target != commandEndBody) {
		return
	}
	identity := cleanSMTPIdentity(values.AuthenticationIdentity)
	ss.authentication = authenticationState{Authenticated: identity != "", Identity: identity}
}

func (ss *session) trustedAuthservIDs() []string {
	configured := ss.deps.policy.correspondentCfg.TrustedAuthservIDs
	trusted := make([]string, 0, len(configured))
	for _, authservID := range configured {
		if authservID == config.MTAHostnameAuthservID {
			if ss.mtaHostname != "" {
				trusted = append(trusted, ss.mtaHostname)
			}
			continue
		}
		trusted = append(trusted, authservID)
	}
	return trusted
}

func validMTAHostname(value string) string {
	value = normalizeDomain(value)
	if value == "" || len(value) > 253 {
		return ""
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return value
}

func (ss *session) finishBypassedMessage(ctx context.Context, source string, learn, touchInbound bool, extraAttrs ...any) bool {
	err := ss.writeAcceptedBypassHeaders()
	if err == nil {
		err = writeFrame(ss.conn, ss.deps.analysis.encodeAction(actionAccept))
	}
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.deps.protocol.mode,
		"actual_action", actionAccept.String(),
		"source", source,
		"response_sent", err == nil,
	}
	attrs = append(attrs, extraAttrs...)
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.deps.log.ErrorContext(ctx, "message bypass response failed", attrs...)
		return false
	}
	if ss.deps.protocol.mode == "enforce" {
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
	timeout := ss.deps.dns.timeout
	if timeout <= 0 || !connectionAddressRoutable(ss.peerIP) || ss.deps.dns.resolver == nil {
		return
	}
	pending := make(chan connectionDNSResult, 1)
	ss.connectionDNSPending = pending
	addr := ss.peerIP
	go func() {
		pending <- ss.deps.dns.resolveSafely(ctx, addr)
	}()
}

func (s *connectionDNSService) resolveSafely(ctx context.Context, addr netip.Addr) (result connectionDNSResult) {
	result = connectionDNSResult{status: message.ReverseDNSLookupFailed}
	defer func() {
		if panicValue := recover(); panicValue != nil {
			logRecoveredWorkerPanic(s.log, ctx, "connection DNS lookup", panicValue, "remote_ip", addr.String())
		}
	}()
	return resolveConnectionDNS(ctx, s.resolver, addr, s.timeout)
}

func (ss *session) connectionInformation(ctx context.Context) message.ConnectionInfo {
	ss.awaitConnectionDNS(ctx)
	info := message.ConnectionInfo{
		MTAReportedHostname: ss.peerHostname,
		HELOIdentity:        ss.heloIdentity,
		ReverseDNSStatus:    ss.connectionDNS.status,
		ReverseDNS:          append([]message.ReverseDNSName(nil), ss.connectionDNS.names...),
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
	if ss.deps.protocol.mode != "enforce" || ss.authentication.Authenticated {
		return false, true
	}
	if _, allowed := ss.deps.policy.ipReputation.allowed(ss.peerIP); allowed {
		return false, true
	}
	if len(ss.deps.policy.ipReputation.domainAllowlist) > 0 {
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
	err := writeFrame(ss.conn, ss.deps.analysis.encodeAction(actionReject))
	attrs := []any{
		"remote_ip", ss.peerIP.String(),
		"mode", ss.deps.protocol.mode,
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

func (ss *session) resetMessage(phase protocolPhase) {
	ss.message = message.New(ss.deps.protocol.maxMessageSize)
	ss.envelopeSender = ""
	ss.envelopeRecipients = nil
	ss.envelopeRecipientsTruncated = false
	ss.visibleSender = ""
	ss.visibleSenderDomain = ""
	ss.phase = phase
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
