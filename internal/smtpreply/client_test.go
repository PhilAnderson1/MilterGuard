package smtpreply

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTLSDecision(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		host       string
		advertised bool
		wantTLS    bool
		wantError  bool
	}{
		{name: "required advertised", mode: "required", host: "mail.example.com", advertised: true, wantTLS: true},
		{name: "required unavailable", mode: "required", host: "mail.example.com", wantError: true},
		{name: "opportunistic remote", mode: "opportunistic", host: "mail.example.com", advertised: true, wantTLS: true},
		{name: "opportunistic loopback", mode: "opportunistic", host: "127.0.0.1", advertised: true},
		{name: "opportunistic unavailable", mode: "opportunistic", host: "mail.example.com"},
		{name: "off", mode: "off", host: "mail.example.com", advertised: true},
		{name: "invalid", mode: "optional", host: "mail.example.com", advertised: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := tlsDecision(test.mode, test.host, test.advertised)
			if (err != nil) != test.wantError || got != test.wantTLS {
				t.Fatalf("tlsDecision = %v, %v; want %v, error=%v", got, err, test.wantTLS, test.wantError)
			}
		})
	}
}

func TestHostIsLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost", "LOCALHOST."} {
		if !hostIsLoopback(host) {
			t.Errorf("%q was not recognized as loopback", host)
		}
	}
	for _, host := range []string{"192.0.2.1", "mail.example.com"} {
		if hostIsLoopback(host) {
			t.Errorf("%q was incorrectly recognized as loopback", host)
		}
	}
}

func TestClientSubmitsEmptyEnvelopeSender(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	commands := make(chan []string, 1)
	payloads := make(chan string, 1)
	go serveTestSMTP(serverConn, commands, payloads)
	client := New(Options{Address: "127.0.0.1:25", TLSMode: "off", Timeout: time.Second})
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	err := client.Send(context.Background(), Message{
		From: "milterguard@example.com", To: "recipient@example.com", Subject: "Result", Date: "date", Text: "body",
	})
	if err != nil {
		t.Fatal(err)
	}
	gotCommands := <-commands
	joined := strings.Join(gotCommands, "\n")
	if !strings.Contains(joined, "MAIL FROM:<>") || !strings.Contains(joined, "RCPT TO:<recipient@example.com>") {
		t.Fatalf("SMTP commands:\n%s", joined)
	}
	if payload := <-payloads; !strings.Contains(payload, "Subject: Result\r\n") || !strings.Contains(payload, "\r\n\r\nbody") {
		t.Fatalf("SMTP payload = %q", payload)
	}
}

func TestClientHonorsTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	client := New(Options{Address: "127.0.0.1:25", TLSMode: "off", Timeout: 25 * time.Millisecond})
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	started := time.Now()
	err := client.Send(context.Background(), Message{To: "recipient@example.com"})
	if err == nil {
		t.Fatal("unresponsive SMTP server did not time out")
	}
	var netErr net.Error
	timedOut := errors.As(err, &netErr) && netErr.Timeout()
	closedAtDeadline := errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
	if !timedOut && !closedAtDeadline {
		t.Fatalf("unresponsive SMTP server error = %v, want deadline or timeout-triggered close", err)
	}
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("SMTP timeout elapsed after %s, want 10ms through 1s", elapsed)
	}
}

func TestClientReportsRecipientRejection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		writer := bufio.NewWriter(serverConn)
		_, _ = writer.WriteString("220 localhost test SMTP\r\n")
		_ = writer.Flush()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				_, _ = writer.WriteString("250 localhost\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"):
				_, _ = writer.WriteString("250 ok\r\n")
			case strings.HasPrefix(line, "RCPT TO:"):
				_, _ = writer.WriteString("550 rejected\r\n")
				_ = writer.Flush()
				return
			}
			_ = writer.Flush()
		}
	}()
	client := New(Options{Address: "127.0.0.1:25", TLSMode: "off", Timeout: time.Second})
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	err := client.Send(context.Background(), Message{To: "recipient@example.com"})
	if err == nil || !strings.Contains(err.Error(), "send SMTP recipient") {
		t.Fatalf("recipient rejection error = %v", err)
	}
}

func TestClientRequiredTLSFailsWhenUnavailable(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		writer := bufio.NewWriter(serverConn)
		_, _ = writer.WriteString("220 localhost test SMTP\r\n")
		_ = writer.Flush()
		if _, err := reader.ReadString('\n'); err == nil {
			_, _ = writer.WriteString("250 localhost\r\n")
			_ = writer.Flush()
		}
	}()
	client := New(Options{Address: "127.0.0.1:25", TLSMode: "required", Timeout: time.Second})
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
	err := client.Send(context.Background(), Message{To: "recipient@example.com"})
	if err == nil || !strings.Contains(err.Error(), "does not advertise STARTTLS") {
		t.Fatalf("required TLS error = %v", err)
	}
}

func serveTestSMTP(conn net.Conn, commands chan<- []string, payloads chan<- string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	_, _ = writer.WriteString("220 localhost test SMTP\r\n")
	_ = writer.Flush()
	var seen []string
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		seen = append(seen, line)
		switch {
		case strings.HasPrefix(line, "EHLO"):
			_, _ = writer.WriteString("250 localhost\r\n")
		case strings.HasPrefix(line, "MAIL FROM:") || strings.HasPrefix(line, "RCPT TO:"):
			_, _ = writer.WriteString("250 ok\r\n")
		case line == "DATA":
			_, _ = writer.WriteString("354 send data\r\n")
			_ = writer.Flush()
			var data strings.Builder
			for {
				dataLine, dataErr := reader.ReadString('\n')
				if dataErr != nil {
					return
				}
				if dataLine == ".\r\n" {
					break
				}
				_, _ = io.WriteString(&data, dataLine)
			}
			payloads <- data.String()
			_, _ = writer.WriteString("250 queued\r\n")
		case line == "QUIT":
			_, _ = writer.WriteString("221 bye\r\n")
			_ = writer.Flush()
			commands <- seen
			return
		default:
			_, _ = fmt.Fprintf(writer, "500 unsupported %s\r\n", line)
		}
		_ = writer.Flush()
	}
}

// recordingSMTPConn records what the client sends on the wire, including any
// accidental plaintext delivery following a failed TLS upgrade.
type recordingSMTPConn struct {
	net.Conn
	wire bytes.Buffer
}

func (c *recordingSMTPConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.wire.Write(p[:n])
	return n, err
}

func smtpTestExchange(conn net.Conn, reader *bufio.Reader, prefix, response string) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("got command %q, want %q", line, prefix)
	}
	_, err = io.WriteString(conn, response)
	return err
}

func TestClientDoesNotSubmitPlaintextAfterTLSFailure(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"mail.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	for _, mode := range []string{"required", "opportunistic"} {
		for _, failure := range []string{"upgrade rejected", "untrusted certificate"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()
				defer serverConn.Close()
				if err := serverConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				type result struct {
					wire string
					err  error
				}
				done := make(chan result, 1)
				go func() {
					conn := &recordingSMTPConn{Conn: serverConn}
					defer conn.Close()
					serve := func() error {
						reader := bufio.NewReader(conn)
						if _, err := io.WriteString(conn, "220 test SMTP\r\n"); err != nil {
							return err
						}
						if err := smtpTestExchange(conn, reader, "EHLO ", "250-test\r\n250 STARTTLS\r\n"); err != nil {
							return err
						}
						response := "454 TLS unavailable\r\n"
						if failure == "untrusted certificate" {
							response = "220 begin TLS\r\n"
						}
						if err := smtpTestExchange(conn, reader, "STARTTLS\r\n", response); err != nil {
							return err
						}
						if failure == "untrusted certificate" {
							secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
							if err := secure.Handshake(); err == nil {
								return errors.New("client trusted self-signed certificate")
							}
						}
						_, err := io.Copy(io.Discard, conn)
						return err
					}
					err := serve()
					done <- result{conn.wire.String(), err}
				}()
				client := New(Options{Address: "mail.example.com:25", TLSMode: mode, Timeout: 2 * time.Second})
				client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
				err := client.Send(context.Background(), Message{To: "recipient@example.com", Text: "private reply"})
				if err == nil || !strings.Contains(err.Error(), "start SMTP TLS") {
					t.Fatalf("TLS error = %v", err)
				}
				if failure == "untrusted certificate" {
					var certificateErr *tls.CertificateVerificationError
					if !errors.As(err, &certificateErr) {
						t.Fatalf("error = %v, want certificate verification failure", err)
					}
				}
				got := <-done
				if got.err != nil {
					t.Fatal(got.err)
				}
				for _, forbidden := range []string{"MAIL FROM:", "RCPT TO:", "private reply"} {
					if strings.Contains(got.wire, forbidden) {
						t.Fatalf("sent plaintext %q after TLS failure", forbidden)
					}
				}
			})
		}
	}
}

func TestClientReportsDataFailureAndCancellation(t *testing.T) {
	for _, scenario := range []string{"rejected after DATA", "cancelled during DATA"} {
		t.Run(scenario, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			if err := serverConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				defer serverConn.Close()
				serve := func() error {
					reader := bufio.NewReader(serverConn)
					if _, err := io.WriteString(serverConn, "220 test SMTP\r\n"); err != nil {
						return err
					}
					for _, step := range []struct{ command, response string }{
						{"EHLO ", "250 test\r\n"}, {"MAIL FROM:<>", "250 ok\r\n"},
						{"RCPT TO:", "250 ok\r\n"}, {"DATA\r\n", "354 send data\r\n"},
					} {
						if err := smtpTestExchange(serverConn, reader, step.command, step.response); err != nil {
							return err
						}
					}
					if scenario == "cancelled during DATA" {
						// Observe actual payload transmission before cancellation.
						if _, err := reader.ReadByte(); err != nil {
							return err
						}
						cancel()
						_, err := io.Copy(io.Discard, reader)
						return err
					}
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							return err
						}
						if line == ".\r\n" {
							break
						}
					}
					_, err := io.WriteString(serverConn, "550 message rejected\r\n")
					return err
				}
				done <- serve()
			}()
			client := New(Options{Address: "127.0.0.1:25", TLSMode: "off", Timeout: 2 * time.Second})
			client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }
			started := time.Now()
			err := client.Send(ctx, Message{To: "recipient@example.com", Text: strings.Repeat("reply body\n", 8192)})
			if err == nil {
				t.Fatal("failed delivery reported success")
			}
			if scenario == "rejected after DATA" && (!strings.Contains(err.Error(), "finish SMTP message data") || !strings.Contains(err.Error(), "550")) {
				t.Fatalf("DATA rejection error = %v", err)
			}
			if scenario == "cancelled during DATA" && (ctx.Err() != context.Canceled || time.Since(started) >= time.Second) {
				t.Fatalf("cancellation did not promptly stop submission: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
