package milter

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

func enableTestAttachments(server *Server) {
	cfg := config.AttachmentsConfig{
		BlockExecutables: true, BlockedExtensions: []string{"exe"}, InspectSignatures: true,
		InspectArchives: true, MaxAttachmentBytes: 1 << 20, MaxArchiveDepth: 2,
		MaxArchiveFiles: 10, MaxArchiveUncompressedBytes: 2 << 20,
		EncryptedArchiveAction: "reject", UnscannableAction: "accept", InvalidMIMEAction: "reject",
		RejectMessage: "executable attachment blocked",
	}
	server.sessions.attachments.cfg = cfg
	server.sessions.attachments.scanner = attachment.New(attachment.Options{
		BlockedExtensions: []string{"exe"}, InspectSignatures: true, InspectArchives: true,
		MaxAttachmentBytes: 1 << 20, MaxArchiveDepth: 2, MaxArchiveFiles: 10, MaxArchiveUncompressedBytes: 2 << 20,
	})
}

func expectAttachmentProgress(t *testing.T, conn net.Conn) {
	t.Helper()
	expectFrame(t, conn, string([]byte{responseProgress}))
}

func TestAttachmentScanWaitingForAttachmentSlotStopsWithContext(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	slots := make(chan struct{}, 1)
	deps := &sessionDependencies{log: log, attachments: &attachmentPolicyService{
		cfg: config.AttachmentsConfig{BlockExecutables: true}, slots: slots,
		scanner: attachment.New(attachment.Options{
			BlockedExtensions: []string{"exe"},
		}),
	}}
	slots <- struct{}{}
	ss := &session{deps: deps, message: message.New(1024)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	handled, keepConnection := ss.applyAttachments(ctx)
	if !handled || keepConnection {
		t.Fatalf("cancelled attachment scan = handled %v, keep connection %v", handled, keepConnection)
	}
}

func TestAttachmentScanDoesNotWaitForAISlot(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	deps := &sessionDependencies{log: log, attachments: &attachmentPolicyService{
		cfg: config.AttachmentsConfig{BlockExecutables: true}, slots: make(chan struct{}, 1),
		scanner: attachment.New(attachment.Options{
			BlockedExtensions: []string{"exe"},
		}),
	}}
	ss := &session{deps: deps, message: message.New(1024)}

	handled, keepConnection := ss.applyAttachments(context.Background())
	if handled || !keepConnection {
		t.Fatalf("clean attachment scan = handled %v, keep connection %v", handled, keepConnection)
	}
}

func TestExecutableAttachmentRejectedBeforeAI(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, "y550 5.7.1 executable attachment blocked\x00")
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestAttachmentsMonitorModeAddsHeadersWhenEnabled(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	setTestMode(server, "monitor")
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.AddEmailHeaders = true })
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unwanted")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-monitor-mode")))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestExecutableAttachmentRejectionIsArchived(t *testing.T) {
	server, conn, done := testServer(t, &countingAnalyzer{})
	enableTestAttachments(server)
	root := enableTestRejectedMail(t, server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("executable payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, "y550 5.7.1 executable attachment blocked\x00")
	if files := archivedMessages(t, root); len(files) != 1 {
		t.Fatalf("archived files = %v", files)
	}
}

func TestAttachmentsMonitorModeAcceptsWithoutAI(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	setTestMode(server, "monitor")
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestAttachmentsTagModeAcceptsAndAddsHeaders(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	setTestMode(server, "tag")
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string(addHeaderResponse(classificationHeader, "unwanted")))
	expectFrame(t, conn, string(addHeaderResponse(confidenceHeader, "unavailable")))
	expectFrame(t, conn, string(addHeaderResponse(actionHeader, "accepted-tag-mode")))
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestSafeAttachmentContinuesToAI(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/pdf"),
		headerFrame("Content-Disposition", `attachment; filename="report.pdf"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("%PDF-1.7")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestUnscannableAttachmentCanTempfail(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.sessions.attachments.cfg.UnscannableAction = "tempfail"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", "application/zip"),
		headerFrame("Content-Disposition", `attachment; filename="broken.zip"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("not a ZIP archive")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string([]byte{responseTempfail}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestMalformedMIMEIsPermanentlyRejected(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", `multipart/mixed; boundary=first; boundary=second`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("message")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, "y550 5.7.1 "+invalidMIMERejectMessage+"\x00")
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestMalformedMIMECanContinueToAIAnalysis(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.sessions.attachments.cfg.InvalidMIMEAction = "accept"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		connectFrame('4', "127.0.0.1"),
		[]byte{commandMail},
		headerFrame("Content-Type", `multipart/mixed; boundary=first; boundary=second`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("message")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectAttachmentProgress(t, conn)
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestAuthenticatedBypassSkipsAttachmentInspection(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	setTestFiltering(server, func(cfg *config.FilteringConfig) { cfg.ScanAuthenticated = false })
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn, connectFrame('4', "127.0.0.1"))
	if err := writeFrame(conn, macroFrame(commandMail, "{auth_authen}", "local-user")); err != nil {
		t.Fatal(err)
	}
	expectNoFrame(t, conn)
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}
