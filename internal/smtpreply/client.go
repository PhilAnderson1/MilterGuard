package smtpreply

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const defaultTimeout = 15 * time.Second

type Sender interface {
	Send(context.Context, Message) error
}

type Options struct {
	Address string
	TLSMode string
	Timeout time.Duration
}

type Client struct {
	options Options
	dial    func(context.Context, string, string) (net.Conn, error)
}

// New constructs a concurrent-safe SMTP reply client with immutable delivery
// options and no persistent connection state.
func New(options Options) *Client {
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}
	return &Client{options: options, dial: (&net.Dialer{}).DialContext}
}

// Send builds a message and submits one SMTP transaction using an empty envelope
// sender and the configured off, opportunistic, or required STARTTLS policy.
func (c *Client) Send(parent context.Context, message Message) error {
	payload, err := Build(message)
	if err != nil {
		return fmt.Errorf("build SMTP reply: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, c.options.Timeout)
	defer cancel()
	host, _, err := net.SplitHostPort(c.options.Address)
	if err != nil {
		return fmt.Errorf("parse SMTP address: %w", err)
	}
	conn, err := c.dial(ctx, "tcp", c.options.Address)
	if err != nil {
		return fmt.Errorf("connect to SMTP server: %w", err)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set SMTP deadline: %w", err)
		}
	}
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("start SMTP client: %w", err)
	}
	defer client.Close()
	startTLS, _ := client.Extension("STARTTLS")
	useTLS, err := tlsDecision(c.options.TLSMode, host, startTLS)
	if err != nil {
		return err
	}
	if useTLS {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if err := client.Mail(""); err != nil {
		return fmt.Errorf("send SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(message.To); err != nil {
		return fmt.Errorf("send SMTP recipient: %w", err)
	}
	data, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP message data: %w", err)
	}
	if _, err := data.Write(payload); err != nil {
		_ = data.Close()
		return fmt.Errorf("write SMTP message data: %w", err)
	}
	if err := data.Close(); err != nil {
		return fmt.Errorf("finish SMTP message data: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("finish SMTP session: %w", err)
	}
	return nil
}

func tlsDecision(mode, host string, advertised bool) (bool, error) {
	switch mode {
	case "off":
		return false, nil
	case "opportunistic":
		return advertised && !hostIsLoopback(host), nil
	case "required":
		if !advertised {
			return false, errors.New("SMTP server does not advertise STARTTLS")
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported SMTP TLS mode %q", mode)
	}
}

func hostIsLoopback(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
