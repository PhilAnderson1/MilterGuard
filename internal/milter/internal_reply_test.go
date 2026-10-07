package milter

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random source failed") }

func TestGenerateInternalToken(t *testing.T) {
	token, err := generateInternalToken(bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d", len(token))
	}
	if _, err := generateInternalToken(failingReader{}); !errors.Is(err, ErrInternalTokenGeneration) {
		t.Fatalf("random-source error = %v", err)
	}
}

func TestInternalCommandReplyHeaderIsRemoved(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.commands.cfg.Enabled = true
	server.sessions.commands.cfg.SendReplies = true
	server.sessions.commands.internalToken = "test-token"
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithExpectedActions(t, conn, actionChangeHeaders, actionChangeHeaders)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "milterguard@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(internalMessageHeader, "test-token"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(internalMessageHeader)))
	expectFrame(t, conn, string([]byte{responseAccept}))
}

func TestInternalCommandReplyTempfailsWithoutHeaderRemoval(t *testing.T) {
	server, conn, done := testServer(t, fixedAnalyzer{})
	server.sessions.commands.cfg.Enabled = true
	server.sessions.commands.cfg.SendReplies = true
	server.sessions.commands.internalToken = "test-token"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		envelopeFrame(commandMail, "milterguard@example.com"),
		envelopeFrame(commandRecipient, "recipient@example.net"),
		headerFrame(internalMessageHeader, "test-token"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseTempfail}))
}

func TestMilterPeerAuthorizationUsesSocketPeerAddress(t *testing.T) {
	server := &Server{allowedPeerIPs: peerPrefixes([]string{"127.0.0.1", "192.0.2.0/24", "::ffff:198.51.100.0/120", "2001:db8::1"})}
	tests := []struct {
		name    string
		address net.Addr
		allowed bool
	}{
		{name: "loopback", address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}, allowed: true},
		{name: "allowed prefix", address: &net.TCPAddr{IP: net.ParseIP("192.0.2.45"), Port: 1234}, allowed: true},
		{name: "allowed mapped prefix", address: &net.TCPAddr{IP: net.ParseIP("198.51.100.45"), Port: 1234}, allowed: true},
		{name: "allowed IPv6", address: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1234}, allowed: true},
		{name: "unauthorized", address: &net.TCPAddr{IP: net.ParseIP("203.0.113.4"), Port: 1234}, allowed: false},
		{name: "missing", address: nil, allowed: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := server.peerAllowed(test.address); got != test.allowed {
				t.Fatalf("peerAllowed(%v) = %v, want %v", test.address, got, test.allowed)
			}
		})
	}
}
