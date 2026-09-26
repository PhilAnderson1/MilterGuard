//go:build ignore

// Usage: go run fixture.go
// Generates a simple/simple signed fixture and the matching mock-DNS TXT value.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"

	"github.com/mjl-/mox/dkim"
	"github.com/mjl-/mox/dns"
)

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	check(err)
	message := []byte("From:  Alice  <alice@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: first line\r\n\tsecond line with a tab\r\n" +
		"X-Repeated: first\r\n" +
		"X-Repeated:  second  value \r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n" +
		"\r\n" +
		"first line  \r\nsecond\tline\r\n\r\n\r\n")
	domain := dns.Domain{ASCII: "example.test"}
	selector := dns.Domain{ASCII: "probe"}
	selectors := []dkim.Selector{}
	for _, modes := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		selectors = append(selectors, dkim.Selector{
			Hash: "sha256", Headers: []string{"From", "To", "Subject", "X-Repeated", "X-Repeated", "Content-Type", "Content-Transfer-Encoding"},
			HeaderRelaxed: modes[0], BodyRelaxed: modes[1], PrivateKey: key, Domain: selector,
		})
	}
	headers, err := dkim.Sign(context.Background(), slog.New(slog.DiscardHandler), "alice", domain, selectors, false, bytes.NewReader(message))
	check(err)
	check(os.WriteFile("signed-canonicalizations.eml", append([]byte(headers), message...), 0600))
	check(os.WriteFile("signed-body-length.eml", signBodyLength(key, message), 0600))

	empty := []byte("From: Alice <alice@example.test>\r\n" +
		"To: Bob <bob@example.test>\r\n" +
		"Subject: empty body\r\n\r\n")
	check(os.WriteFile("signed-empty.eml", signMox(key, domain, selector, empty), 0600))

	// This is intentionally opaque MIME data with lines and octet patterns that
	// make accidental text treatment obvious while remaining valid SMTP DATA.
	binaryPayload := make([]byte, 4096)
	for i := range binaryPayload {
		binaryPayload[i] = byte((i*131 + 17) & 0xff)
	}
	encoded := base64.StdEncoding.EncodeToString(binaryPayload)
	var encodedLines bytes.Buffer
	for len(encoded) > 76 {
		encodedLines.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	encodedLines.WriteString(encoded + "\r\n")
	binaryMessage := append([]byte("From: Alice <alice@example.test>\r\n"+
		"To: Bob <bob@example.test>\r\n"+
		"Subject: binary-looking MIME payload\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: application/octet-stream; name=payload.bin\r\n"+
		"Content-Transfer-Encoding: base64\r\n\r\n"), encodedLines.Bytes()...)
	check(os.WriteFile("signed-binary.eml", signMox(key, domain, selector, binaryMessage), 0600))
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	check(err)
	record := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pub)
	check(os.WriteFile("dkim-record.txt", []byte(record+"\n"), 0600))
	fmt.Println("generated canonicalization, body-length, empty-body and binary fixtures")
}

func signMox(key *rsa.PrivateKey, domain, selector dns.Domain, message []byte) []byte {
	headers, err := dkim.Sign(context.Background(), slog.New(slog.DiscardHandler), "alice", domain, []dkim.Selector{{
		Hash: "sha256", Headers: []string{"From", "To", "Subject", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"},
		PrivateKey: key, Domain: selector,
	}}, false, bytes.NewReader(message))
	check(err)
	return append([]byte(headers), message...)
}

// signBodyLength creates the deliberately narrow l= fixture needed by the
// feasibility corpus. Its signed header set is fixed to From and Subject.
func signBodyLength(key *rsa.PrivateKey, message []byte) []byte {
	separator := bytes.Index(message, []byte("\r\n\r\n"))
	if separator < 0 {
		panic("message has no header/body separator")
	}
	headerBlock, body := message[:separator+2], message[separator+4:]
	canonicalBody := bytes.TrimRight(body, "\r\n")
	canonicalBody = append(canonicalBody, '\r', '\n')
	const bodyLength = 12
	bodyDigest := sha256.Sum256(canonicalBody[:bodyLength])
	dkimBase := "DKIM-Signature: v=1; a=rsa-sha256; c=simple/simple; d=example.test; s=probe; h=from:subject; l=12; bh=" + base64.StdEncoding.EncodeToString(bodyDigest[:]) + "; b="
	lines := bytes.Split(headerBlock, []byte("\r\n"))
	fields := [][]byte{}
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1] = append(fields[len(fields)-1], append([]byte("\r\n"), line...)...)
		} else if len(line) > 0 {
			fields = append(fields, append([]byte(nil), line...))
		}
	}
	var from, subject []byte
	for _, field := range fields {
		lower := bytes.ToLower(field)
		switch {
		case bytes.HasPrefix(lower, []byte("from:")):
			from = append(append([]byte(nil), field...), '\r', '\n')
		case bytes.HasPrefix(lower, []byte("subject:")):
			subject = append(append([]byte(nil), field...), '\r', '\n')
		}
	}
	signed := append(append(append([]byte(nil), from...), subject...), dkimBase...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	check(err)
	header := dkimBase + base64.StdEncoding.EncodeToString(signature) + "\r\n"
	return append([]byte(header), message...)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
