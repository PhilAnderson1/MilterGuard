package milter

import (
	"context"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/mailaddr"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/netsafety"
)

type authenticationState struct {
	Authenticated bool
	Identity      string
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

func (ss *session) internalAuthentication() bool {
	return ss.deps.authenticationMode == config.AuthenticationModeInternal
}

func containsNonASCII(value string) bool {
	for index := range len(value) {
		if value[index] >= utf8.RuneSelf {
			return true
		}
	}
	return false
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
