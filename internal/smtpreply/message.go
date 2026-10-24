package smtpreply

import (
	"bytes"
	"encoding/base64"
	"errors"
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
	// MaxBytes bounds the encoded message; zero preserves unlimited callers.
	MaxBytes    int64
	From        string
	To          string
	Subject     string
	Date        string
	Text        string
	Headers     []Header
	Attachments []Attachment
}

var ErrMessageTooLarge = errors.New("SMTP reply exceeds message size limit")

// Build renders a plain-text or multipart command reply with CRLF line endings,
// automatic-response suppression headers, and deterministic MIME framing.
// When MaxBytes is positive, writes exceeding it fail before buffer growth.
func Build(message Message) ([]byte, error) {
	var payload bytes.Buffer
	output := &boundedWriter{writer: &payload, remaining: message.MaxBytes, limited: message.MaxBytes > 0}
	if err := render(output, message); err != nil {
		return nil, err
	}
	return payload.Bytes(), nil
}

// Size measures the encoded message without storing its payload. Multipart
// boundaries have fixed length, so a later Build produces the same byte count.
func Size(message Message) (int64, error) {
	var count countingWriter
	err := render(&count, message)
	return count.bytes, err
}

type countingWriter struct{ bytes int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.bytes += int64(len(p))
	return len(p), nil
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
	limited   bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if w.limited && int64(len(p)) > w.remaining {
		return 0, ErrMessageTooLarge
	}
	n, err := w.writer.Write(p)
	if w.limited {
		w.remaining -= int64(n)
	}
	return n, err
}

func render(output io.Writer, message Message) error {
	for _, header := range []Header{
		{Name: "From", Value: "MilterGuard <" + message.From + ">"},
		{Name: "To", Value: message.To},
		{Name: "Subject", Value: message.Subject},
		{Name: "Date", Value: message.Date},
		{Name: "Auto-Submitted", Value: "auto-replied"},
		{Name: "X-Auto-Response-Suppress", Value: "All"},
	} {
		if err := writeHeader(output, header); err != nil {
			return err
		}
	}
	for _, header := range message.Headers {
		if err := writeHeader(output, header); err != nil {
			return err
		}
	}
	if len(message.Attachments) == 0 {
		if _, err := io.WriteString(output, "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"); err != nil {
			return err
		}
		if err := writeCRLFText(output, message.Text); err != nil {
			return err
		}
		return nil
	}

	writer := multipart.NewWriter(output)
	if _, err := fmt.Fprintf(output, "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", writer.Boundary()); err != nil {
		return err
	}
	textHeader := make(textproto.MIMEHeader)
	textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
	textHeader.Set("Content-Transfer-Encoding", "8bit")
	part, err := writer.CreatePart(textHeader)
	if err != nil {
		return err
	}
	if err := writeCRLFText(part, message.Text); err != nil {
		return err
	}
	for _, attachment := range message.Attachments {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Type", mime.FormatMediaType(attachment.MediaType, map[string]string{"name": attachment.Filename}))
		header.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Filename}))
		header.Set("Content-Transfer-Encoding", "base64")
		part, err = writer.CreatePart(header)
		if err != nil {
			return err
		}
		if count, ok := output.(*countingWriter); ok {
			encoded := int64(base64.StdEncoding.EncodedLen(len(attachment.Contents)))
			count.bytes += encoded + 2*max(1, (encoded+75)/76)
		} else if err := writeBase64(part, attachment.Contents); err != nil {
			return err
		}
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return nil
}

// writeCRLFText canonicalizes LF, CRLF, and lone CR line endings without
// otherwise changing the UTF-8 message text.
func writeCRLFText(writer io.Writer, text string) error {
	start := 0
	for index := 0; index < len(text); index++ {
		if text[index] != '\r' && text[index] != '\n' {
			continue
		}
		if _, err := io.WriteString(writer, text[start:index]); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, "\r\n"); err != nil {
			return err
		}
		if text[index] == '\r' && index+1 < len(text) && text[index+1] == '\n' {
			index++
		}
		start = index + 1
	}
	_, err := io.WriteString(writer, text[start:])
	return err
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
	// Encode one MIME line at a time; never allocate a complete base64 copy.
	var line [78]byte
	for len(contents) > 57 {
		base64.StdEncoding.Encode(line[:76], contents[:57])
		line[76], line[77] = '\r', '\n'
		if _, err := writer.Write(line[:]); err != nil {
			return err
		}
		contents = contents[57:]
	}
	n := base64.StdEncoding.EncodedLen(len(contents))
	base64.StdEncoding.Encode(line[:n], contents)
	line[n], line[n+1] = '\r', '\n'
	_, err := writer.Write(line[:n+2])
	return err
}
