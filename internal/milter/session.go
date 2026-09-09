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

type session struct {
	server                      *Server
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
	connectionDNS               connectionDNSResult
	connectionDNSPending        <-chan connectionDNSResult
	message                     *message.Message
	negotiatedActions           uint32
	idleSince                   time.Time
}

func newSession(server *Server, conn net.Conn) *session {
	ss := &session{server: server, conn: conn, reader: bufio.NewReader(conn), idleSince: time.Now()}
	ss.resetMessage(phaseNegotiation)
	return ss
}

func (ss *session) run(ctx context.Context) {
	stopClose := context.AfterFunc(ctx, func() {
		_ = ss.conn.Close()
	})
	defer stopClose()
	for {
		now := time.Now()
		deadline := now.Add(ss.server.cfg.Milter.Timeout.Value())
		if idleDeadline := ss.idleSince.Add(milterIdleTimeout); idleDeadline.Before(deadline) {
			deadline = idleDeadline
		}
		if err := ss.conn.SetDeadline(deadline); err != nil {
			if ctx.Err() == nil {
				ss.server.log.Warn("cannot set Milter connection deadline",
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
		ss.idleSince = time.Now()
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
			if time.Since(ss.idleSince) >= milterIdleTimeout {
				ss.server.log.Debug("closing idle Milter connection",
					"idle_timeout", milterIdleTimeout.String(),
					"local_addr", ss.conn.LocalAddr().String(),
					"remote_addr", ss.conn.RemoteAddr().String())
				return false
			}
			return true
		}
		ss.server.log.Warn("milter connection timed out during frame", "bytes_read", bytesRead, "error", err)
		return false
	}
	if err != io.EOF {
		ss.server.log.Warn("milter connection error", "error", err)
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
			ss.server.log.Debug("milter CONNECT did not provide a usable IP address")
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
		if recipient, ok := parseEnvelopeAddress(payload); ok && ss.isCommandRecipient(recipient) {
			authorized, reason := ss.commandIdentityAuthorization()
			if !authorized {
				ss.server.log.WarnContext(ctx, "email command recipient rejected", "authenticated_identity", ss.authentication.Identity, "authenticated", ss.authentication.Authenticated, "reason", reason)
				return ss.send(commandRecipient, replyCode("550", "5.7.1", "MilterGuard command rejected: "+reason))
			}
			if len(ss.envelopeRecipients) < maxLearnedRecipients {
				ss.envelopeRecipients = append(ss.envelopeRecipients, recipient)
			} else {
				ss.envelopeRecipientsTruncated = true
			}
		} else if ok && len(ss.envelopeRecipients) < maxLearnedRecipients {
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
	requestedActions := uint32(0)
	wantsResultHeaders := ss.server.cfg.Filtering.AddEmailHeaders || ss.server.cfg.Mode == "tag"
	if wantsResultHeaders && offeredActions&resultHeaderActions == resultHeaderActions {
		requestedActions = resultHeaderActions
	} else if wantsResultHeaders {
		ss.server.log.Warn("result headers disabled for Milter connection because MTA did not offer add/change-header support",
			"offered_actions", offeredActions)
	}
	wantsInternalHeaderRemoval := ss.server.cfg.EmailCommands.Enabled && ss.server.cfg.EmailCommands.SendReplies
	if wantsInternalHeaderRemoval && offeredActions&actionChangeHeaders != 0 {
		requestedActions |= actionChangeHeaders
	} else if wantsInternalHeaderRemoval {
		ss.server.log.Warn("internal reply protection disabled for Milter connection because MTA did not offer change-header support",
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
	if ss.phase != phaseBody {
		return ss.protocolError("unexpected milter end-of-body command")
	}
	if ss.isInternalMessage() {
		return ss.finishInternalMessage(ctx)
	}
	if handled, keepConnection := ss.handleEmailCommand(ctx); handled {
		return keepConnection
	}
	if ss.authentication.Authenticated && !ss.server.cfg.Filtering.ScanAuthenticated {
		return ss.finishBypassedMessage(ctx, "authenticated_connection", true, false)
	}
	if handled, keepConnection := ss.applyAttachments(ctx); handled {
		return keepConnection
	}
	inbound := ss.prepareInboundEvidence()
	if inbound.allowedSenderDomain != "" {
		return ss.finishBypassedMessage(ctx, "sender_domain_allowlist", false, inbound.knownCorrespondent && inbound.trustedDKIM,
			"sender_domain", inbound.allowedSenderDomain,
			"trusted_aligned_dkim", inbound.trustedDKIM)
	}
	if inbound.bypassAI {
		return ss.finishBypassedMessage(ctx, "known_correspondent", false, inbound.trustedDKIM,
			ss.knownCorrespondentLogAttrs()...)
	}
	if inbound.authenticatedDomain != "" {
		info, err := ss.server.domainRegistration.evidence(ctx, inbound.authenticatedDomain)
		if err != nil {
			ss.server.log.DebugContext(ctx, "domain registration lookup unavailable", "domain", registrableDomain(inbound.authenticatedDomain), "error", err)
		} else {
			ss.message.DomainRegistration = info
		}
	}
	ss.message.TrustedAuthservIDs = ss.trustedAuthservIDs()
	ss.message.Connection = ss.connectionInformation(ctx)
	if err := ss.conn.SetDeadline(time.Now().Add(ss.server.analysisTimeout())); err != nil {
		if ctx.Err() == nil {
			ss.server.log.WarnContext(ctx, "cannot set Milter connection deadline",
				"stage", "analysis",
				"local_addr", ss.conn.LocalAddr().String(),
				"remote_addr", ss.conn.RemoteAddr().String(),
				"error", err)
		}
		return false
	}
	result := ss.server.evaluate(ctx, ss.message)
	var err error
	if result.selected == actionAccept {
		err = ss.writeAcceptedResultHeaders(&result)
	}
	if err == nil {
		err = writeFrame(ss.conn, ss.server.encodeAction(result.selected))
	}
	ss.server.logOutcome(ctx, ss.message, result, err == nil, err)
	if err != nil {
		return false
	}
	ss.applyPostDecisionUpdates(ctx, result, inbound)
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) finishInternalMessage(ctx context.Context) bool {
	if ss.negotiatedActions&actionChangeHeaders == 0 {
		ss.server.log.ErrorContext(ctx, "cannot safely accept internal command reply because MTA did not offer header removal")
		if err := writeFrame(ss.conn, []byte{responseTempfail}); err != nil {
			return false
		}
		ss.resetMessage(phaseConnection)
		return true
	}
	for range ss.message.Headers[strings.ToLower(internalMessageHeader)] {
		if err := writeFrame(ss.conn, deleteHeaderResponse(internalMessageHeader)); err != nil {
			return false
		}
	}
	return ss.finishBypassedMessage(ctx, "internal_command_reply", false, false)
}

func (ss *session) knownCorrespondentLogAttrs() []any {
	attrs := []any{"correspondent", normalizeEmailAddress(ss.message.Header("From"))}
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

func (ss *session) prepareInboundEvidence() inboundEvidence {
	evidence := inboundEvidence{recipientsComplete: ss.recipientSetComplete()}
	if ss.authentication.Authenticated {
		return evidence
	}
	authentication := trustedSenderAuthentication(ss.message, ss.trustedAuthservIDs(), ss.message.Header("From"))
	evidence.trustedDKIM = authentication.DKIMAligned
	if authentication.anyAligned() {
		address := normalizeEmailAddress(ss.message.Header("From"))
		if separator := strings.LastIndexByte(address, '@'); separator >= 0 {
			evidence.authenticatedDomain = address[separator+1:]
		}
	}
	if domain := allowedSenderDomain(ss.message.Header("From"), ss.server.cfg.Filtering.SenderDomainAllowlist); domain != "" &&
		(!ss.server.cfg.Filtering.SenderDomainAllowlistRequireDKIM || authentication.DKIMAligned) {
		evidence.allowedSenderDomain = domain
	}
	if !ss.server.cfg.Correspondents.UseAllowlist {
		return evidence
	}
	match := ss.server.correspondents.match(ss.message.Header("From"), ss.envelopeRecipients)
	known := match.Known
	if ss.server.cfg.Correspondents.Scope == "per_sender" && ss.server.cfg.Correspondents.RecipientMatch == "all" {
		known = evidence.recipientsComplete && match.AllRecipientsMatched
	}
	evidence.knownCorrespondent = known
	ss.message.Correspondent = message.CorrespondentInfo{
		Enabled:               true,
		Known:                 known,
		Scope:                 ss.server.cfg.Correspondents.Scope,
		AuthenticationAligned: known && authentication.anyAligned(),
	}
	bypassAuthentication := !ss.server.cfg.Correspondents.RequireDKIMForBypass || authentication.DKIMAligned
	evidence.bypassAI = ss.server.cfg.Correspondents.BypassAI && evidence.recipientsComplete && known && bypassAuthentication
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
	if ss.server.cfg.Mode != "enforce" {
		return
	}
	if result.selected == actionReject {
		ss.server.recordRejection(ctx, ss.message, ss.envelopeSender, ss.envelopeRecipients, result.reasons, "ai")
		ss.server.ipReputation.add(ss.peerIP, result.score, ss.connectionDNS)
	}
	if result.err == nil && result.classification == "legitimate" {
		ss.server.ipReputation.recordLegitimate(ss.peerIP)
	}
	if result.selected == actionAccept && ss.authentication.Authenticated {
		ss.learnAuthenticatedRecipients(ctx)
	} else if !ss.authentication.Authenticated && result.err == nil {
		ss.recordInboundClassification(ctx, result, inbound.recipientsComplete, inbound.trustedDKIM)
	}
}

func (ss *session) recordInboundClassification(ctx context.Context, result evaluationResult, recipientsComplete, dkimAligned bool) {
	if err := ss.server.correspondents.recordInboundClassification(
		ss.message.Header("From"), ss.envelopeRecipients, recipientsComplete,
		result.classification, result.score, ss.server.cfg.Filtering.RejectScore, dkimAligned,
	); err != nil {
		ss.server.log.ErrorContext(ctx, "cannot update inbound correspondent learning", "error", err)
	}
}

func (ss *session) captureSessionMacros(payload []byte) {
	target, values, valid := parseSessionMacros(payload)
	if !valid {
		ss.server.log.Debug("ignored malformed milter macro data")
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
	if identity != "" {
		ss.authentication = authenticationState{Authenticated: true, Identity: identity}
	}
}

func (ss *session) trustedAuthservIDs() []string {
	configured := ss.server.cfg.Correspondents.TrustedAuthservIDs
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
		err = writeFrame(ss.conn, ss.server.encodeAction(actionAccept))
	}
	attrs := []any{
		"message_id", ss.message.Header("Message-ID"),
		"mode", ss.server.cfg.Mode,
		"actual_action", actionAccept.String(),
		"source", source,
		"response_sent", err == nil,
	}
	attrs = append(attrs, extraAttrs...)
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.server.log.ErrorContext(ctx, "message bypass response failed", attrs...)
		return false
	}
	if ss.server.cfg.Mode == "enforce" {
		if learn {
			ss.learnAuthenticatedRecipients(ctx)
		}
		if touchInbound {
			ss.touchInboundCorrespondent(ctx)
		}
	}
	if source == "internal_command_reply" {
		ss.server.log.DebugContext(ctx, "message bypassed AI analysis", attrs...)
	} else {
		ss.server.log.InfoContext(ctx, "message bypassed AI analysis", attrs...)
	}
	ss.resetMessage(phaseConnection)
	return true
}

func (ss *session) touchInboundCorrespondent(ctx context.Context) {
	if err := ss.server.correspondents.touchInbound(ss.message.Header("From"), ss.envelopeRecipients); err != nil {
		ss.server.log.ErrorContext(ctx, "cannot update correspondent activity", "error", err)
	}
}

func (ss *session) learnAuthenticatedRecipients(ctx context.Context) {
	if err := ss.server.correspondents.learn(ss.envelopeSender, ss.envelopeRecipients); err != nil {
		ss.server.log.ErrorContext(ctx, "cannot update correspondent allowlist", "error", err)
	}
}

func (ss *session) startConnectionDNS(ctx context.Context) {
	timeout := ss.server.cfg.Milter.ConnectionDNSTimeout.Value()
	if timeout <= 0 || !connectionAddressRoutable(ss.peerIP) || ss.server.resolver == nil {
		return
	}
	pending := make(chan connectionDNSResult, 1)
	ss.connectionDNSPending = pending
	resolver := ss.server.resolver
	addr := ss.peerIP
	go func() {
		pending <- ss.server.resolveConnectionDNSSafely(ctx, resolver, addr, timeout)
	}()
}

func (s *Server) resolveConnectionDNSSafely(ctx context.Context, resolver dnsResolver, addr netip.Addr, timeout time.Duration) (result connectionDNSResult) {
	result = connectionDNSResult{status: message.ReverseDNSLookupFailed}
	defer func() {
		if panicValue := recover(); panicValue != nil {
			s.logRecoveredWorkerPanic(ctx, "connection DNS lookup", panicValue, "remote_ip", addr.String())
		}
	}()
	return resolveConnectionDNS(ctx, resolver, addr, timeout)
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
	if ss.server.cfg.Mode != "enforce" {
		return false, true
	}
	if _, allowed := ss.server.ipReputation.allowed(ss.peerIP); allowed {
		return false, true
	}
	if len(ss.server.ipReputation.domainAllowlist) > 0 {
		dns := ss.awaitConnectionDNS(ctx)
		if hostname, domain, allowed := ss.server.ipReputation.domainAllowed(dns); allowed {
			ss.server.log.DebugContext(ctx, "sending IP block bypassed by reverse-DNS domain allowlist",
				"remote_ip", ss.peerIP.String(), "reverse_dns", hostname, "matched_domain", domain)
			return false, true
		}
	}
	entry, ok := ss.server.ipReputation.lookup(ss.peerIP)
	if !ok {
		return false, true
	}
	err := writeFrame(ss.conn, ss.server.encodeAction(actionReject))
	attrs := []any{
		"remote_ip", ss.peerIP.String(),
		"mode", ss.server.cfg.Mode,
		"score", entry.score,
		"proposed_action", actionReject.String(),
		"actual_action", actionReject.String(),
		"source", "rejected_ip_reputation",
		"block_level", entry.level,
		"strike_count", entry.strikeCount,
		"block_expires_at", entry.expires,
		"block_remaining_ms", time.Until(entry.expires).Milliseconds(),
		"response_sent", err == nil,
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
		ss.server.log.ErrorContext(ctx, "message rejected by sending IP reputation", attrs...)
		return true, false
	}
	ss.server.log.InfoContext(ctx, "message rejected by sending IP reputation", attrs...)
	return true, true
}

func (ss *session) resetMessage(phase protocolPhase) {
	ss.message = message.New(ss.server.cfg.Milter.MaxMessageSize)
	ss.envelopeSender = ""
	ss.envelopeRecipients = nil
	ss.envelopeRecipientsTruncated = false
	ss.phase = phase
}

func (ss *session) sendContinue(command byte) bool {
	return ss.send(command, []byte{responseContinue})
}

func (ss *session) send(command byte, response []byte) bool {
	if err := writeFrame(ss.conn, response); err != nil {
		ss.server.log.Warn("cannot send milter response", "command", commandName(command), "error", err)
		return false
	}
	return true
}

func (ss *session) protocolError(message string, attrs ...any) bool {
	ss.server.log.Warn(message, attrs...)
	return false
}

func commandName(command byte) string {
	return fmt.Sprintf("0x%02x", command)
}
