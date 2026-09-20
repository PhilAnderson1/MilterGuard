package smtpreply

import (
	"bufio"
	"context"
	"fmt"
	"io"
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
	err := client.Send(context.Background(), Message{To: "recipient@example.com"})
	if err == nil {
		t.Fatal("unresponsive SMTP server did not time out")
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
