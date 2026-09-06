package message

import (
	"strings"
)

type Message struct {
	Headers            map[string][]string
	Body               strings.Builder
	Connection         ConnectionInfo
	Correspondent      CorrespondentInfo
	TrustedAuthservIDs []string
	Truncated          bool
	BodyTruncated      bool
	MaxBytes           int64
	bodySize           int64
	headerSize         int64
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
	maxRetainedHeaderBytes = 32 << 10
	maxHeaderValueBytes    = 8 << 10
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
	"x-milterguard-score":          true,
	"x-milterguard-internal":       true,
	"received-spf":                 true,
	"reply-to":                     true,
	"return-path":                  true,
	"subject":                      true,
	"to":                           true,
}

func New(maxBytes int64) *Message {
	return &Message{Headers: make(map[string][]string), MaxBytes: maxBytes}
}
func (m *Message) AddHeader(name, value string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !retainedHeaders[name] {
		return
	}
	value = strings.TrimSpace(value)
	if len(value) > maxHeaderValueBytes {
		value = value[:maxHeaderValueBytes]
		m.Truncated = true
	}
	entrySize := int64(len(name) + len(value) + 2)
	if m.headerSize+entrySize > maxRetainedHeaderBytes {
		m.Truncated = true
		return
	}
	m.headerSize += entrySize
	m.Headers[name] = append(m.Headers[name], value)
}
func (m *Message) AddBody(p []byte) {
	remaining := m.MaxBytes - m.bodySize
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

// RetainedBytes reports the bounded header and body bytes kept by the Milter.
func (m *Message) RetainedBytes() int64 { return m.headerSize + m.bodySize }

// CommandText returns decoded visible MIME text for the authenticated command
// mailbox. Callers separately constrain the accepted top-level MIME types.
func (m *Message) CommandText() string {
	content := extractMIME(m.Header("Content-Type"), m.Header("Content-Transfer-Encoding"), "", []byte(m.Body.String()), 0)
	return stripInvisibleFormatting(content.VisibleText)
}
