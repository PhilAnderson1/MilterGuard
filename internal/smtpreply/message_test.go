package smtpreply

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestEncodedSizeAndBuildLimit(t *testing.T) {
	for _, length := range []int{-1, 0, 1, 56, 57, 58, 114, 115, 4096} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			message := Message{From: "from@example.com", To: "to@example.com", Text: "café\nline\rline\r\nlast"}
			if length >= 0 {
				message.Attachments = []Attachment{
					{Filename: "message.eml", MediaType: "application/octet-stream", Contents: bytes.Repeat([]byte("x"), length)},
					{Filename: "second.eml", MediaType: "application/octet-stream", Contents: []byte("second")},
				}
			}
			size, err := Size(message)
			if err != nil {
				t.Fatal(err)
			}
			message.MaxBytes = size
			payload, err := Build(message)
			if err != nil || int64(len(payload)) != size {
				t.Fatalf("size=%d actual=%d error=%v", size, len(payload), err)
			}
			message.MaxBytes--
			if payload, err = Build(message); !errors.Is(err, ErrMessageTooLarge) || payload != nil {
				t.Fatalf("oversized message escaped limit: bytes=%d error=%v", len(payload), err)
			}
		})
	}
}

func TestBuildPlainReplyHeaders(t *testing.T) {
	payload, err := Build(Message{
		From: "milterguard@example.com", To: "local@example.com", Subject: "Results",
		Date: "Sun, 13 Sep 2026 07:00:00 +0000", Text: "Result café\nsecond\r\nthird\rfourth",
		Headers: []Header{{Name: "X-MilterGuard-Internal", Value: "token"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"From": "MilterGuard <milterguard@example.com>", "To": "local@example.com",
		"Subject": "Results", "Auto-Submitted": "auto-replied",
		"X-Auto-Response-Suppress": "All", "X-MilterGuard-Internal": "token",
		"MIME-Version": "1.0", "Content-Type": "text/plain; charset=UTF-8",
		"Content-Transfer-Encoding": "8bit",
	} {
		if got := message.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	body, err := io.ReadAll(message.Body)
	if err != nil || string(body) != "Result café\r\nsecond\r\nthird\r\nfourth" {
		t.Fatalf("body = %q, err=%v", body, err)
	}
}

func TestBuildReplyWithAttachment(t *testing.T) {
	original := []byte("From: sender@example.net\r\n\r\nOriginal body\r\n")
	payload, err := Build(Message{
		From: "milterguard@example.com", To: "local@example.com", Subject: "Results", Date: "date",
		Text: "Rejection café\nsecond\rthird", Attachments: []Attachment{{
			Filename: "rejection-12.eml", MediaType: "application/octet-stream", Contents: original,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("Content-Type = %q, params=%v, err=%v", mediaType, params, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	textPart, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	textBody, err := io.ReadAll(textPart)
	if err != nil || string(textBody) != "Rejection café\r\nsecond\r\nthird" {
		t.Fatalf("text part = %q, err=%v", textBody, err)
	}
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FileName() != "rejection-12.eml" || part.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatalf("attachment headers = %#v", part.Header)
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
	if err != nil || !bytes.Equal(decoded, original) {
		t.Fatalf("decoded attachment = %q, err=%v", decoded, err)
	}
}

func TestBuildRejectsInjectedHeaders(t *testing.T) {
	_, err := Build(Message{From: "sender@example.com\r\nBcc: victim@example.com"})
	if err == nil {
		t.Fatal("header injection was accepted")
	}
}

func TestAttachmentBase64LinesAreBounded(t *testing.T) {
	payload, err := Build(Message{
		From: "m@example.com", To: "r@example.com", Subject: "x", Date: "date", Text: "x",
		Attachments: []Attachment{{Filename: "x.bin", MediaType: "application/octet-stream", Contents: bytes.Repeat([]byte("x"), 1024)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(message.Header.Get("Content-Type"))
	reader := multipart.NewReader(message.Body, params["boundary"])
	_, _ = reader.NextPart()
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(encoded)), "\r\n") {
		if len(line) > 76 {
			t.Fatalf("base64 line length = %d", len(line))
		}
	}
}
