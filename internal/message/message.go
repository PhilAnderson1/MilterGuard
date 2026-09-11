package message

import (
	"bytes"
	"strings"
	"time"
)

type Message struct {
	Headers            map[string][]string
	decodedHeaders     map[string][]string
	headerOccurrences  map[string]int
	Body               bytes.Buffer
	Connection         ConnectionInfo
	Correspondent      CorrespondentInfo
	DomainRegistration DomainRegistrationInfo
	TrustedAuthservIDs []string
	Truncated          bool
	BodyTruncated      bool
	MaxBytes           int64
	bodySize           int64
	headerSize         int64
	headerBytesByName  map[string]int64
	archiveHeaders     bytes.Buffer
	archiveHeaderBytes int64
	archiveTruncated   bool
}

type ConnectionInfo struct {
	RemoteIP            string
	MTAReportedHostname string
	HELOIdentity        string
	ReverseDNSStatus    string
	ReverseDNS          []ReverseDNSName
}

type ReverseDNSName struct {
	Hostname     string
	Confirmation string
}

type CorrespondentInfo struct {
	Enabled               bool
	Known                 bool
	Scope                 string
	AuthenticationAligned bool
}

type DomainRegistrationInfo struct {
	Available    bool
	Domain       string
	RegisteredAt time.Time
}

const (
	ReverseDNSNotApplicable = "not-applicable"
	ReverseDNSAbsent        = "absent"
	ReverseDNSLookupFailed  = "lookup-failed"
	ReverseDNSAvailable     = "available"

	ForwardConfirmed    = "forward-confirmed"
	ForwardUnconfirmed  = "unconfirmed"
	ForwardLookupFailed = "lookup-failed"
)

type VisionOptions struct {
	Mode         string
	MinTextChars int
	MaxImages    int
	MaxBytes     int64
	MaxPixels    int64
}

type Image struct {
	MediaType string
	Data      []byte
}

type Analysis struct {
	Prompt string
	Images []Image
}

const (
	maxRetainedHeaderBytesPerName = 16 << 10
	maxAuthenticationHeaderBytes  = 32 << 10
	maxHeaderValueBytes           = 8 << 10
)

var retainedHeaders = map[string]bool{
	"authentication-results":       true,
	"content-disposition":          true,
	"content-transfer-encoding":    true,
	"content-type":                 true,
	"date":                         true,
	"from":                         true,
	"message-id":                   true,
	"x-milterguard-action":         true,
	"x-milterguard-classification": true,
	"x-milterguard-confidence":     true,
	"x-milterguard-score":          true,
	"x-milterguard-internal":       true,
	"received-spf":                 true,
	"reply-to":                     true,
	"return-path":                  true,
	"subject":                      true,
	"to":                           true,
}

var humanReadableHeaders = map[string]bool{
	"from":     true,
	"reply-to": true,
	"subject":  true,
	"to":       true,
}

var countedSecurityHeaders = map[string]bool{
	"x-milterguard-action":         true,
	"x-milterguard-classification": true,
	"x-milterguard-confidence":     true,
	"x-milterguard-internal":       true,
	"x-milterguard-score":          true,
}

func New(maxBytes int64) *Message {
	return &Message{
		Headers:           make(map[string][]string),
		decodedHeaders:    make(map[string][]string),
		headerOccurrences: make(map[string]int),
		headerBytesByName: make(map[string]int64),
		MaxBytes:          maxBytes,
	}
}
func (m *Message) AddHeader(name, value string) {
	m.addArchiveHeader(name, value)
	name = strings.ToLower(strings.TrimSpace(name))
	if countedSecurityHeaders[name] {
		m.headerOccurrences[name]++
	}
	if !retainedHeaders[name] {
		return
	}
	value = strings.TrimSpace(value)
	if len(value) > maxHeaderValueBytes {
		value = value[:maxHeaderValueBytes]
		m.Truncated = true
	}
	entrySize := int64(len(name) + len(value) + 2)
	limit := int64(maxRetainedHeaderBytesPerName)
	if name == "authentication-results" {
		limit = maxAuthenticationHeaderBytes
	}
	if m.headerBytesByName[name]+entrySize > limit {
		m.Truncated = true
		return
	}
	m.headerSize += entrySize
	m.headerBytesByName[name] += entrySize
	m.Headers[name] = append(m.Headers[name], value)
	if humanReadableHeaders[name] {
		m.decodedHeaders[name] = append(m.decodedHeaders[name], decodeHeaderValue(value))
	}
}

// HeaderOccurrences returns the number of security-sensitive headers received,
// including occurrences omitted from Headers by the retained-header byte limit.
func (m *Message) HeaderOccurrences(name string) int {
	return m.headerOccurrences[strings.ToLower(strings.TrimSpace(name))]
}

func (m *Message) addArchiveHeader(name, value string) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, ":\r\n\x00") {
		m.archiveTruncated = true
		return
	}
	for _, char := range name {
		if char < 33 || char > 126 {
			m.archiveTruncated = true
			return
		}
	}
	value = strings.ReplaceAll(value, "\x00", "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.ReplaceAll(value, "\n", "\r\n ")
	line := name + ": " + value + "\r\n"
	// Reserve at least half of the configured message budget for the body so
	// excessive headers cannot suppress all content presented for analysis.
	headerLimit := m.MaxBytes / 2
	if m.archiveHeaderBytes+int64(len(line)) > headerLimit {
		m.archiveTruncated = true
		return
	}
	m.archiveHeaderBytes += int64(len(line))
	_, _ = m.archiveHeaders.WriteString(line)
}
func (m *Message) AddBody(p []byte) {
	remaining := m.MaxBytes - m.archiveHeaderBytes - m.bodySize
	if remaining <= 0 {
		m.Truncated = true
		m.BodyTruncated = true
		return
	}
	if int64(len(p)) > remaining {
		p = p[:remaining]
		m.Truncated = true
		m.BodyTruncated = true
	}
	m.bodySize += int64(len(p))
	_, _ = m.Body.Write(p)
}
func (m *Message) Header(name string) string {
	return strings.Join(m.Headers[strings.ToLower(name)], ", ")
}

// DecodedHeader returns a human-readable RFC 2047-decoded header while the
// original value remains available through Header for protocol-sensitive use.
func (m *Message) DecodedHeader(name string) string {
	name = strings.ToLower(name)
	if values, ok := m.decodedHeaders[name]; ok {
		return strings.Join(values, ", ")
	}
	return strings.Join(m.Headers[name], ", ")
}

func (m *Message) decodedHeaderValues(name string) []string {
	if values, ok := m.decodedHeaders[name]; ok {
		return values
	}
	return m.Headers[name]
}

// RetainedBytes reports the bounded raw header and body bytes kept by the Milter.
func (m *Message) RetainedBytes() int64 { return m.archiveHeaderBytes + m.bodySize }

// BodyBytes returns the retained message body without copying it. Callers must
// treat the returned bytes as read-only and must not retain them after Message
// processing completes.
func (m *Message) BodyBytes() []byte { return m.Body.Bytes() }

// ArchiveBytes returns a bounded RFC 5322/MIME message reconstructed from the
// headers and body supplied through the Milter protocol.
func (m *Message) ArchiveBytes() []byte {
	limit := m.MaxBytes
	if limit < 0 {
		limit = 0
	}
	var output bytes.Buffer
	estimated := m.archiveHeaderBytes + 2 + m.bodySize
	if m.archiveTruncated || m.BodyTruncated {
		estimated += int64(len("X-MilterGuard-Archive-Truncated: yes\r\n"))
	}
	if estimated > limit {
		estimated = limit
	}
	if estimated > 0 && estimated <= int64(int(^uint(0)>>1)) {
		output.Grow(int(estimated))
	}
	_, _ = output.Write(m.archiveHeaders.Bytes())
	if m.archiveTruncated || m.BodyTruncated {
		_, _ = output.WriteString("X-MilterGuard-Archive-Truncated: yes\r\n")
	}
	_, _ = output.WriteString("\r\n")
	remaining := limit - int64(output.Len())
	if remaining <= 0 {
		return output.Bytes()[:min(int64(output.Len()), limit)]
	}
	body := m.BodyBytes()
	if int64(len(body)) > remaining {
		body = body[:remaining]
	}
	_, _ = output.Write(body)
	return output.Bytes()
}

// CommandText returns decoded visible MIME text for the authenticated command
// mailbox. Callers separately constrain the accepted top-level MIME types.
func (m *Message) CommandText() string {
	content := extractMIME(m.Header("Content-Type"), m.Header("Content-Transfer-Encoding"), "", m.BodyBytes(), 0)
	return stripInvisibleFormatting(content.VisibleText)
}
