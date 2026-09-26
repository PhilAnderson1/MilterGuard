package message

import (
	"bytes"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

type Message struct {
	Headers                 map[string][]string
	decodedHeaders          map[string][]string
	headerOccurrences       map[string]int
	analysisTime            time.Time
	body                    bytes.Buffer
	Connection              ConnectionInfo
	AuthenticatedSubmission bool
	Correspondent           CorrespondentInfo
	DomainRegistration      DomainRegistrationInfo
	Authentication          mailauth.Evidence
	Truncated               bool
	BodyTruncated           bool
	MIMEHeadersTruncated    bool
	ArchiveTruncated        bool
	maxBytes                int64
	bodySize                int64
	headerBytesByName       map[string]int64
	fromHeaderCount         int
	toHeaderSeen            bool
	archiveHeaders          bytes.Buffer
	archiveHeaderBytes      int64
	archiveTruncated        bool
}

type ConnectionInfo struct {
	RemoteIP            string
	MTAReportedHostname string
	HELOIdentity        string
	EnvelopeSender      string
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
	maxMIMEHeaderValueBytes       = 64 << 10
	archiveTruncationHeader       = "X-MilterGuard-Archive-Truncated: yes\r\n"
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

// New creates empty bounded message state for one SMTP transaction.
func New(maxBytes int64) *Message {
	return &Message{
		Headers:           make(map[string][]string),
		decodedHeaders:    make(map[string][]string),
		headerOccurrences: make(map[string]int),
		headerBytesByName: make(map[string]int64),
		analysisTime:      time.Now().UTC(),
		maxBytes:          maxBytes,
	}
}

// AddHeader records one supplied header while enforcing aggregate retention
// limits and decoding selected identity headers once for later consumers.
func (m *Message) AddHeader(name, value string) {
	m.addArchiveHeader(name, value)
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "from" {
		m.fromHeaderCount++
	}
	if name == "to" {
		m.toHeaderSeen = true
	}
	if countedSecurityHeaders[name] {
		m.headerOccurrences[name]++
	}
	if !retainedHeaders[name] {
		return
	}
	value = strings.TrimSpace(value)
	value = strings.ToValidUTF8(value, "�")
	valueLimit := maxHeaderValueBytes
	if structuralMIMEHeaders[name] {
		valueLimit = maxMIMEHeaderValueBytes
	}
	if len(value) > valueLimit {
		end := valueLimit
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		value = value[:end]
		m.Truncated = true
		if structuralMIMEHeaders[name] {
			m.MIMEHeadersTruncated = true
		}
	}
	entrySize := int64(len(name) + len(value) + 2)
	limit := int64(maxRetainedHeaderBytesPerName)
	if structuralMIMEHeaders[name] {
		limit = maxMIMEHeaderValueBytes + 256
	} else if name == "authentication-results" {
		limit = maxAuthenticationHeaderBytes
	}
	if m.headerBytesByName[name]+entrySize > limit {
		m.Truncated = true
		if structuralMIMEHeaders[name] {
			m.MIMEHeadersTruncated = true
		}
		return
	}
	m.headerBytesByName[name] += entrySize
	m.Headers[name] = append(m.Headers[name], value)
	if humanReadableHeaders[name] {
		m.decodedHeaders[name] = append(m.decodedHeaders[name], decodeHeaderValue(value))
	}
}

var structuralMIMEHeaders = map[string]bool{
	"content-disposition":       true,
	"content-transfer-encoding": true,
	"content-type":              true,
}

// HeaderOccurrences returns the number of security-sensitive headers received,
// including occurrences omitted from Headers by the retained-header byte limit.
func (m *Message) HeaderOccurrences(name string) int {
	return m.headerOccurrences[strings.ToLower(strings.TrimSpace(name))]
}

// FromHeaderCount includes fields omitted by retention limits, so sender
// ambiguity cannot be hidden by an oversized earlier From field.
func (m *Message) FromHeaderCount() int { return m.fromHeaderCount }

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
	headerLimit := m.maxBytes / 2
	if m.archiveHeaderBytes+int64(len(line)) > headerLimit {
		m.archiveTruncated = true
		return
	}
	m.archiveHeaderBytes += int64(len(line))
	_, _ = m.archiveHeaders.WriteString(line)
}

// AddBody appends as much of a body chunk as fits within the configured
// message limit and marks the message as truncated when bytes are discarded.
func (m *Message) AddBody(p []byte) {
	remaining := m.maxBytes - m.archiveHeaderBytes - m.bodySize
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
	_, _ = m.body.Write(p)
}
func (m *Message) Header(name string) string {
	return strings.Join(m.Headers[strings.ToLower(name)], ", ")
}

// FirstHeader returns the first retained field value. Structural MIME fields
// cannot be comma-joined without changing their syntax, and Go's MIME parser
// likewise uses the first occurrence for nested message parts.
func (m *Message) FirstHeader(name string) string {
	values := m.Headers[strings.ToLower(name)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
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

// BodyBytes returns the retained message body without copying it. Callers must
// treat the returned bytes as read-only and must not retain them after Message
// processing completes.
func (m *Message) BodyBytes() []byte { return m.body.Bytes() }

// ArchiveBytes returns a syntactically valid bounded RFC 5322/MIME message
// reconstructed from the retained headers and body for rejected-message
// storage.
func (m *Message) ArchiveBytes() []byte {
	limit := m.maxBytes
	if limit < 2 {
		return nil
	}
	truncated := m.archiveTruncated || m.BodyTruncated
	reserved := int64(2)
	includeMarker := truncated && limit >= int64(len(archiveTruncationHeader))+reserved
	if includeMarker {
		reserved += int64(len(archiveTruncationHeader))
	}
	headers := completeArchiveHeaderPrefix(m.archiveHeaders.Bytes(), limit-reserved)
	var output bytes.Buffer
	estimated := int64(len(headers)) + reserved + m.bodySize
	if estimated > limit {
		estimated = limit
	}
	if estimated > 0 && estimated <= int64(int(^uint(0)>>1)) {
		output.Grow(int(estimated))
	}
	_, _ = output.Write(headers)
	if includeMarker {
		_, _ = output.WriteString(archiveTruncationHeader)
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

// completeArchiveHeaderPrefix returns only complete RFC 5322 fields. Folded
// continuation lines remain attached to their field, so the archive is never
// cut in the middle of a header or continuation line.
func completeArchiveHeaderPrefix(headers []byte, maxBytes int64) []byte {
	if maxBytes <= 0 {
		return nil
	}
	if int64(len(headers)) <= maxBytes {
		return headers
	}
	lastComplete := 0
	lineStart := 0
	for lineStart < len(headers) {
		lineLength := bytes.Index(headers[lineStart:], []byte("\r\n"))
		if lineLength < 0 {
			break
		}
		lineEnd := lineStart + lineLength + 2
		continuationFollows := lineEnd < len(headers) && (headers[lineEnd] == ' ' || headers[lineEnd] == '\t')
		if !continuationFollows {
			if int64(lineEnd) > maxBytes {
				break
			}
			lastComplete = lineEnd
		}
		lineStart = lineEnd
	}
	return headers[:lastComplete]
}

// CommandText returns decoded visible MIME text from a bounded prefix of an
// authenticated command message. Callers separately constrain the accepted
// top-level MIME types.
func (m *Message) CommandText(maxBytes int64) string {
	body := m.BodyBytes()
	if maxBytes >= 0 && int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}
	content := extractMIME(m.FirstHeader("Content-Type"), m.FirstHeader("Content-Transfer-Encoding"), "", body, 0)
	return stripInvisibleFormatting(content.VisibleText)
}
