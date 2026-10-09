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

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

type protocolPhase uint8

const (
	phaseNegotiation protocolPhase = iota
	phaseConnection
	phaseEnvelope
	phaseBody
)

const maxEnvelopeRecipients = 100

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
	if ss.phase == phaseNegotiation && command != commandOptionNegotiation && command != commandMacro && command != commandQuitMilterConnection {
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
	case commandQuitSMTPConnection:
		ss.connected = false
		ss.peerIP = netip.Addr{}
		ss.peerHostname = ""
		ss.mtaHostname = ""
		ss.pendingMTAHostname = ""
		ss.receiverIP = netip.Addr{}
		ss.pendingReceiverIP = netip.Addr{}
		ss.heloIdentity = ""
		ss.smtpUTF8 = false
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
			ss.deps.log.Warn("milter CONNECT did not provide a usable client IP address; IP reputation, reverse DNS and IP-based authentication checks are unavailable for this connection")
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
			ss.smtpUTF8 = containsNonASCII(sender) || envelopeHasSMTPUTF8(payload)
		}
		return ss.sendContinue(command)
	case commandRecipient:
		if ss.phase != phaseEnvelope {
			return ss.protocolError("milter transaction command outside message", "command", commandName(command))
		}
		if recipient, ok := parseEnvelopeAddress(payload); !ok {
			ss.envelopeRecipientsTruncated = true
		} else if len(ss.envelopeRecipients) < maxEnvelopeRecipients {
			ss.envelopeRecipients = append(ss.envelopeRecipients, recipient)
		} else {
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
	case commandQuitMilterConnection:
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
	requestedActions := offeredActions & (resultHeaderActions | actionDeleteRecipient)
	wantsResultHeaders := ss.deps.filtering.AddEmailHeaders
	if wantsResultHeaders && offeredActions&actionAddHeaders == 0 {
		ss.deps.log.Warn("result headers disabled for Milter connection because MTA did not offer add-header support",
			"offered_actions", offeredActions)
	}
	wantsInternalHeaderRemoval := ss.deps.protocol.protectInternalReplies
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
	if strings.EqualFold(strings.TrimSpace(name), "From") && ss.protectedSenderDomain == "" {
		ss.protectedSenderDomain = authenticatedOnlyFromValue(
			value, ss.deps.filtering.AuthenticatedOnlySenderDomains,
		)
	}
	if strings.EqualFold(strings.TrimSpace(name), "From") {
		for _, sender := range strictVisibleFromMailboxes([]string{value}) {
			seen := false
			for _, existing := range ss.senderBlocklistFrom {
				if existing == sender {
					seen = true
					break
				}
			}
			if seen {
				continue
			}
			if len(ss.senderBlocklistFrom) >= maxSenderBlockAddresses {
				ss.senderBlocklistFromTruncated = true
				break
			}
			ss.senderBlocklistFrom = append(ss.senderBlocklistFrom, sender)
		}
	}
	ss.message.AddHeader(name, value)
	ss.captureExact(func(exact mailauth.ExactMessage) error { return exact.AddHeader(name, value) })
	return ss.sendContinue(commandHeader)
}

func (ss *session) resetMessage(phase protocolPhase) {
	ss.closeExactMessage()
	ss.message = message.New(ss.deps.protocol.maxMessageSize)
	ss.exactMessageErr = nil
	ss.envelopeSender = ""
	ss.envelopeRecipients = nil
	ss.envelopeRecipientsTruncated = false
	ss.visibleSender = ""
	ss.visibleSenderDomain = ""
	ss.visibleFromInvalid = false
	ss.protectedSenderDomain = ""
	ss.pendingSenderBlocks = nil
	ss.senderBlocklistFrom = nil
	ss.senderBlocklistFromTruncated = false
	ss.smtpUTF8 = false
	ss.phase = phase
	if phase != phaseEnvelope || !ss.requiresExactMessage() {
		ss.exactMessage = nil
		return
	}
	storage := ss.deps.protocol.exactStorage
	if storage == "" {
		storage = "memory"
	}
	factory := ss.deps.newExactMessage
	if factory == nil {
		ss.exactMessage = nil
		ss.exactMessageErr = fmt.Errorf("exact-message factory is unavailable")
		return
	}
	ss.exactMessage, ss.exactMessageErr = factory(storage, ss.deps.protocol.maxMessageSize)
}

func (ss *session) requiresExactMessage() bool {
	return ss.internalAuthentication()
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
