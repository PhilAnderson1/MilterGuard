package milter

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
)

func TestUnauthenticatedProtectedSenderDomainRejectedBeforeAI(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	ipCfg := config.IPReputationConfig{BlockDuration: config.Duration(time.Hour), MaxEntries: 100}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "Support <support@mail.invades.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
}

func TestProtectedSenderDomainRejectionHonorsIPAllowlist(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	ipCfg := config.IPReputationConfig{
		BlockDuration: config.Duration(time.Hour), MaxEntries: 100,
		IPAllowlist: []string{"192.0.2.0/24"},
	}
	setTestIPReputation(server, newTestIPReputationStore(t, ipCfg, server.log))
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "Support <support@invades.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if err := writeFrame(conn, []byte{commandMail}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseContinue}))
}

func TestProtectedSenderDomainRejectionIsRecordedAndArchived(t *testing.T) {
	analyzer := &countingAnalyzer{}
	root := filepath.Join(t.TempDir(), "rejected-mail")
	cfg := config.Config{
		Mode: "enforce",
		Milter: config.MilterConfig{
			Timeout: config.Duration(200 * time.Millisecond), MaxMessageSize: 1024, MaxConnections: 1,
		},
		AI: config.AIConfig{Timeout: config.Duration(time.Second), MaxConcurrent: 1, MaxBodyChars: 1024},
		Filtering: config.FilteringConfig{
			RejectScore: 0.9, LegitimateLowConfidenceScore: 0.8, AIErrorAction: "accept", RejectMessage: "blocked",
			AuthenticatedOnlySenderDomains: []string{"invades.net"},
		},
		Persistence: config.PersistenceConfig{DatabaseFile: filepath.Join(t.TempDir(), "milterguard.db")},
		RejectionHistory: config.RejectionHistoryConfig{
			Expiry: config.Duration(24 * time.Hour), MaxEntries: 10, SaveMessages: true,
			MessageDirectory: root, MessageMaxTotalBytes: 1 << 20,
		},
	}
	server, conn, done := testServerWithConfig(t, cfg, analyzer)
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close configured test server: %v", err)
		}
	})
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		envelopeFrame(commandRecipient, "local@example.net"),
		headerFrame("From", "Support <support@invades.net>"),
		headerFrame("Subject", "Forged local sender"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")

	if files := archivedMessages(t, root); len(files) != 1 {
		t.Fatalf("archived files = %v", files)
	}
	entries := rejectionEntries(t, server.sessions.policy.rejectionHistory, "local@example.net")
	if len(entries) != 1 || entries[0].Sender != "support@invades.net" || entries[0].Subject != "Forged local sender" {
		t.Fatalf("rejection history = %#v", entries)
	}
}

func TestAuthenticatedProtectedSenderDomainIsPermitted(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "192.0.2.10"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "philip")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		headerFrame("From", "Philip <philip@invades.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestProtectedDomainInDisplayNameDoesNotTriggerPolicy(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", `"support@invades.net" <criminal@example.org>`),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestProtectedDomainPolicyChecksEveryFromMailbox(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "Criminal <criminal@example.org>, Support <support@invades.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestProtectedDomainPolicyRecoversMailboxFromMalformedList(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "support@invades.net, (("),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 blocked\x00")
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestMalformedFromListDoesNotTreatDisplayTextAsProtectedMailbox(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", `"support@invades.net" <criminal@example.org>, ((`),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestProtectedSenderDomainAcceptModeAddsHeadersWithoutAI(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	setTestMode(server, "accept")
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "Support <support@invades.net>"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unwanted")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-accept-mode")))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestProtectedSenderDomainAcceptModeWithoutHeadersOnlyRemovesSpoofedResults(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	setTestMode(server, "accept")
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = false })
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AuthenticatedOnlySenderDomains = []string{"invades.net"} })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "192.0.2.10"),
		[]byte{commandMail},
		headerFrame("From", "Support <support@invades.net>"),
		headerFrame(classificationHeader, "legitimate"),
		[]byte{commandEndHeaders},
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string(deleteHeaderResponse(classificationHeader)))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}
