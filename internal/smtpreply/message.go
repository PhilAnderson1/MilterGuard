package smtpreply

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

type Header struct {
	Name  string
	Value string
}

type Attachment struct {
	Filename  string
	MediaType string
	Contents  []byte
}

type Message struct {
	From        string
	To          string
	Subject     string
	Date        string
	Text        string
	Headers     []Header
	Attachments []Attachment
}

// Build renders a plain-text or multipart command reply with CRLF line endings,
// automatic-response suppression headers, and deterministic MIME framing.
func Build(message Message) ([]byte, error) {
	var payload bytes.Buffer
	for _, header := range []Header{
		{Name: "From", Value: "MilterGuard <" + message.From + ">"},
		{Name: "To", Value: message.To},
		{Name: "Subject", Value: message.Subject},
		{Name: "Date", Value: message.Date},
		{Name: "Auto-Submitted", Value: "auto-replied"},
		{Name: "X-Auto-Response-Suppress", Value: "All"},
	} {
		if err := writeHeader(&payload, header); err != nil {
			return nil, err
		}
	}
	for _, header := range message.Headers {
		if err := writeHeader(&payload, header); err != nil {
			return nil, err
		}
	}
	if len(message.Attachments) == 0 {
		payload.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		payload.WriteString(message.Text)
		return payload.Bytes(), nil
	}

	var multipartBody bytes.Buffer
	writer := multipart.NewWriter(&multipartBody)
	fmt.Fprintf(&payload, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", writer.Boundary())
	textHeader := make(textproto.MIMEHeader)
	textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
	textHeader.Set("Content-Transfer-Encoding", "8bit")
	part, err := writer.CreatePart(textHeader)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(part, message.Text); err != nil {
		return nil, err
	}
	for _, attachment := range message.Attachments {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType(attachment.MediaType, map[string]string{"name": attachment.Filename}))
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Filename}))
		header.Set("Content-Transfer-Encoding", "base64")
		part, err = writer.CreatePart(header)
		if err != nil {
			return nil, err
		}
		if err := writeBase64(part, attachment.Contents); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if _, err := multipartBody.WriteTo(&payload); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

func writeHeader(writer io.Writer, header Header) error {
	name := strings.TrimSpace(header.Name)
	if name == "" || strings.ContainsAny(name, ":\r\n") || strings.ContainsAny(header.Value, "\r\n") {
		return fmt.Errorf("invalid message header %q", name)
	}
	_, err := fmt.Fprintf(writer, "%s: %s\r\n", name, header.Value)
	return err
}

func writeBase64(writer io.Writer, contents []byte) error {
	encoded := base64.StdEncoding.EncodeToString(contents)
	for len(encoded) > 76 {
		if _, err := io.WriteString(writer, encoded[:76]+"\r\n"); err != nil {
			return err
		}
		encoded = encoded[76:]
	}
	_, err := io.WriteString(writer, encoded+"\r\n")
	return err
}
