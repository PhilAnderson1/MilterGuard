package message

import (
	"bytes"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

type Message struct {
	headers                 map[string][]string
	decodedHeaders          map[string][]string
	headerOccurrences       map[string]int
	analysisTime            time.Time
	body                    bytes.Buffer
	Truncated               bool
	BodyTruncated           bool
	MIMEHeadersTruncated    bool
	SavedArchiveTruncated   bool
	maxBytes                int64
	bodySize                int64
	headerBytesByName       map[string]int64
	fromHeaderCount         int
	toHeaderSeen            bool
	archiveHeaders          bytes.Buffer
	archiveHeaderBytes      int64
	archiveHeadersTruncated bool
}

// AnalysisContext contains evidence gathered by MilterGuard rather than data
// parsed from the message itself.
type AnalysisContext struct {
	Connection              ConnectionInfo
	AuthenticatedSubmission bool
	Correspondent           CorrespondentInfo
	DomainRegistration      DomainRegistrationInfo
	Authentication          mailauth.Evidence
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
	Prompt                                string
	Images                                []Image
	BodyTruncated                         bool
	BodyExtractionIncomplete              bool
	ConcealedContentRemoved               bool
	HasConcealedContent                   bool
	UsedConcealedTag                      bool
	UsedVisibilityVariesByViewportSizeTag bool
	UsedVisibilityUncertainTag            bool
	UsedHiddenContentStrippedTag          bool
}

const (
	maxRetainedHeaderBytesPerName = 16 << 10
	maxAuthenticationHeaderBytes  = 32 << 10
	maxHeaderValueBytes           = 8 << 10
	maxMIMEHeaderValueBytes       = 64 << 10
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
		headers:           make(map[string][]string),
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
	m.headers[name] = append(m.headers[name], value)
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
// including occurrences omitted from retained header values by the byte limit.
func (m *Message) HeaderOccurrences(name string) int {
	return m.headerOccurrences[strings.ToLower(strings.TrimSpace(name))]
}

// FromHeaderCount includes fields omitted by retention limits, so sender
// ambiguity cannot be hidden by an oversized earlier From field.
func (m *Message) FromHeaderCount() int { return m.fromHeaderCount }

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
	return strings.Join(m.headers[strings.ToLower(name)], ", ")
}

// FirstHeader returns the first retained field value. Structural MIME fields
// cannot be comma-joined without changing their syntax, and Go's MIME parser
// likewise uses the first occurrence for nested message parts.
func (m *Message) FirstHeader(name string) string {
	values := m.headers[strings.ToLower(name)]
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
	return strings.Join(m.headers[name], ", ")
}

// HeaderValues returns a copy of all retained values for a header field.
func (m *Message) HeaderValues(name string) []string {
	return append([]string(nil), m.headers[strings.ToLower(strings.TrimSpace(name))]...)
}

func (m *Message) decodedHeaderValues(name string) []string {
	if values, ok := m.decodedHeaders[name]; ok {
		return values
	}
	return m.headers[name]
}

// BodyBytes returns the retained message body without copying it. Callers must
// treat the returned bytes as read-only and must not retain them after Message
// processing completes.
func (m *Message) BodyBytes() []byte { return m.body.Bytes() }

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
