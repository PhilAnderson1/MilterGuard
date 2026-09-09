package milter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

const (
	commandAbort             = byte('A')
	commandBody              = byte('B')
	commandConnect           = byte('C')
	commandMacro             = byte('D')
	commandEndBody           = byte('E')
	commandHelo              = byte('H')
	commandHeader            = byte('L')
	commandMail              = byte('M')
	commandEndHeaders        = byte('N')
	commandOptionNegotiation = byte('O')
	commandQuit              = byte('Q')
	commandRecipient         = byte('R')
	commandData              = byte('T')
	commandUnknown           = byte('U')
	commandQuitConnection    = byte('K')

	responseAccept       = byte('a')
	responseContinue     = byte('c')
	responseDiscard      = byte('d')
	responseTempfail     = byte('t')
	responseReply        = byte('y')
	responseAddHeader    = byte('h')
	responseChangeHeader = byte('m')

	minimumProtocolVersion   = uint32(2)
	supportedProtocolVersion = uint32(6)
	optionPayloadBytes       = 12
	// Postfix normally sends message bodies in much smaller chunks. Keeping a
	// conservative hard ceiling prevents a peer from forcing a large allocation
	// merely by declaring an oversized frame.
	maxFrameBytes          = 1 << 20
	maxSMTPReplyBytes      = 510 // Excludes the terminating CRLF.
	maxMacroPairs          = 128
	maxAuthenticationBytes = 1024

	actionAddHeaders    = uint32(0x00000001)
	actionChangeHeaders = uint32(0x00000010)
	resultHeaderActions = actionAddHeaders | actionChangeHeaders
)

type action uint8

type sessionMacroValues struct {
	AuthenticationIdentity string
	MTAHostname            string
	AuthenticationFound    bool
	MTAHostnameFound       bool
}

const (
	actionAccept action = iota
	actionReject
	actionTempfail
)

func (a action) String() string {
	switch a {
	case actionReject:
		return "reject"
	case actionTempfail:
		return "tempfail"
	default:
		return "accept"
	}
}

func optionResponse(version, actions uint32) []byte {
	response := make([]byte, 13)
	response[0] = commandOptionNegotiation
	binary.BigEndian.PutUint32(response[1:5], version)
	binary.BigEndian.PutUint32(response[5:9], actions)
	binary.BigEndian.PutUint32(response[9:13], 0)
	return response
}

func addHeaderResponse(name, value string) []byte {
	response := []byte{responseAddHeader}
	response = append(response, name...)
	response = append(response, 0)
	response = append(response, value...)
	return append(response, 0)
}

func deleteHeaderResponse(name string) []byte {
	response := make([]byte, 5)
	response[0] = responseChangeHeader
	// Repeatedly removing occurrence one safely deletes every existing value.
	binary.BigEndian.PutUint32(response[1:5], 1)
	response = append(response, name...)
	response = append(response, 0, 0)
	return response
}

func replyCode(code, enhanced, text string) []byte {
	clean := func(value string) string {
		value = strings.ReplaceAll(value, "\x00", "")
		value = strings.ReplaceAll(value, "\r", " ")
		return strings.ReplaceAll(value, "\n", " ")
	}
	reply := clean(code) + " " + clean(enhanced) + " " + clean(text)
	reply = truncateUTF8(reply, maxSMTPReplyBytes)
	reply = strings.ReplaceAll(reply, "%", "%%")
	return append([]byte{responseReply}, []byte(reply+"\x00")...)
}

func truncateUTF8(value string, maxBytes int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maxBytes {
		return value
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end]
}

func parseHeader(payload []byte) (string, string, bool) {
	name, remainder, found := bytes.Cut(payload, []byte{0})
	if !found || len(name) == 0 || len(remainder) == 0 || remainder[len(remainder)-1] != 0 {
		return "", "", false
	}
	value := remainder[:len(remainder)-1]
	if bytes.IndexByte(value, 0) >= 0 {
		return "", "", false
	}
	return string(name), string(value), true
}

func parseEnvelopeAddress(payload []byte) (string, bool) {
	address, _, found := bytes.Cut(payload, []byte{0})
	if !found || len(address) == 0 {
		return "", false
	}
	return string(address), true
}

func parseConnectHostname(payload []byte) (string, bool) {
	hostname, _, found := bytes.Cut(payload, []byte{0})
	if !found {
		return "", false
	}
	return string(hostname), true
}

func parseSMTPIdentity(payload []byte) (string, bool) {
	if len(payload) == 0 || payload[len(payload)-1] != 0 || bytes.IndexByte(payload[:len(payload)-1], 0) >= 0 {
		return "", false
	}
	return string(payload[:len(payload)-1]), true
}

func parseAuthenticationMacro(payload []byte) (target byte, identity string, found, valid bool) {
	target, values, valid := parseSessionMacros(payload)
	return target, values.AuthenticationIdentity, values.AuthenticationFound, valid
}

func parseSessionMacros(payload []byte) (target byte, values sessionMacroValues, valid bool) {
	if len(payload) == 0 {
		return 0, values, false
	}
	target = payload[0]
	remainder := payload[1:]
	if len(remainder) == 0 {
		return target, values, true
	}
	if remainder[len(remainder)-1] != 0 {
		return target, values, false
	}
	for pairs := 0; len(remainder) > 0; pairs++ {
		if pairs >= maxMacroPairs {
			return target, values, false
		}
		name, rest, ok := bytes.Cut(remainder, []byte{0})
		if !ok || len(name) == 0 {
			return target, values, false
		}
		value, rest, ok := bytes.Cut(rest, []byte{0})
		if !ok {
			return target, values, false
		}
		remainder = rest
		macroName := strings.Trim(string(name), "{}")
		switch {
		case strings.EqualFold(macroName, "auth_authen"):
			if values.AuthenticationFound || len(value) > maxAuthenticationBytes {
				return target, values, false
			}
			values.AuthenticationIdentity = string(value)
			values.AuthenticationFound = true
		case strings.EqualFold(macroName, "j"):
			if values.MTAHostnameFound || len(value) > 253 {
				return target, values, false
			}
			values.MTAHostname = string(value)
			values.MTAHostnameFound = true
		}
	}
	return target, values, true
}

func parseConnectIP(payload []byte) (netip.Addr, bool) {
	_, remainder, found := bytes.Cut(payload, []byte{0})
	if !found || len(remainder) < 4 {
		return netip.Addr{}, false
	}
	family := remainder[0]
	if family != '4' && family != '6' {
		return netip.Addr{}, false
	}
	addressBytes := remainder[3:]
	if len(addressBytes) < 2 || addressBytes[len(addressBytes)-1] != 0 || bytes.IndexByte(addressBytes[:len(addressBytes)-1], 0) >= 0 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(string(addressBytes[:len(addressBytes)-1]))
	if err != nil || (family == '4' && !addr.Is4() && !addr.Is4In6()) || (family == '6' && !addr.Is6()) {
		return netip.Addr{}, false
	}
	return canonicalIP(addr), true
}

func readFrame(reader io.Reader) ([]byte, error) {
	frame, _, err := readFrameProgress(reader)
	return frame, err
}

func readFrameProgress(reader io.Reader) ([]byte, int, error) {
	var header [4]byte
	headerBytes, err := io.ReadFull(reader, header[:])
	if err != nil {
		return nil, headerBytes, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > maxFrameBytes {
		return nil, headerBytes, fmt.Errorf("invalid frame length %d", length)
	}
	frame := make([]byte, length)
	frameBytes, err := io.ReadFull(reader, frame)
	return frame, headerBytes + frameBytes, err
}

func writeFrame(writer io.Writer, payload []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
