package milter

import (
	"testing"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
)

func enableTestAttachments(server *Server) {
	server.cfg.Attachments.BlockExecutables = true
	server.cfg.Attachments.BlockedExtensions = []string{"exe"}
	server.cfg.Attachments.InspectSignatures = true
	server.cfg.Attachments.InspectArchives = true
	server.cfg.Attachments.MaxAttachmentBytes = 1 << 20
	server.cfg.Attachments.MaxArchiveDepth = 2
	server.cfg.Attachments.MaxArchiveFiles = 10
	server.cfg.Attachments.MaxArchiveUncompressedBytes = 2 << 20
	server.cfg.Attachments.EncryptedArchiveAction = "reject"
	server.cfg.Attachments.UnscannableAction = "accept"
	server.cfg.Attachments.RejectMessage = "executable attachment blocked"
	server.attachments = attachment.New(attachment.Options{
		BlockedExtensions: []string{"exe"}, InspectSignatures: true, InspectArchives: true,
		MaxAttachmentBytes: 1 << 20, MaxArchiveDepth: 2, MaxArchiveFiles: 10, MaxArchiveUncompressedBytes: 2 << 20,
	})
}

func TestExecutableAttachmentRejectedBeforeAI(t *testing.T) {
	analyzer := &countingAnalyzer{decision: ai.Decision{Classification: "legitimate", Score: 1}}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
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
	expectFrame(t, conn, "y550 5.7.1 executable attachment blocked\x00")
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
		[]byte{commandMail},
		headerFrame("Content-Type", "application/octet-stream"),
		headerFrame("Content-Disposition", `attachment; filename="invoice.exe"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("executable payload")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, "y550 5.7.1 executable attachment blocked\x00")
	if files := archivedMessages(t, root); len(files) != 1 {
		t.Fatalf("archived files = %v", files)
	}
}

func TestAttachmentsMonitorModeAcceptsWithoutAI(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.cfg.Mode = "monitor"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
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

func TestAttachmentsTagModeAcceptsAndAddsHeaders(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.cfg.Mode = "tag"
	defer func() { _ = conn.Close(); <-done }()

	negotiateWithActions(t, conn, resultHeaderActions)
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
		[]byte{commandMail},
		headerFrame("Content-Type", "application/pdf"),
		headerFrame("Content-Disposition", `attachment; filename="report.pdf"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("%PDF-1.7")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseAccept}))
	if got := analyzer.calls.Load(); got != 1 {
		t.Fatalf("AI analysis calls = %d, want 1", got)
	}
}

func TestUnscannableAttachmentCanTempfail(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.cfg.Attachments.UnscannableAction = "tempfail"
	defer func() { _ = conn.Close(); <-done }()

	negotiate(t, conn)
	sendContinueFrames(t, conn,
		[]byte{commandMail},
		headerFrame("Content-Type", "application/zip"),
		headerFrame("Content-Disposition", `attachment; filename="broken.zip"`),
		[]byte{commandEndHeaders},
		append([]byte{commandBody}, []byte("not a ZIP archive")...),
	)
	if err := writeFrame(conn, []byte{commandEndBody}); err != nil {
		t.Fatal(err)
	}
	expectFrame(t, conn, string([]byte{responseTempfail}))
	if got := analyzer.calls.Load(); got != 0 {
		t.Fatalf("AI analysis calls = %d, want 0", got)
	}
}

func TestAuthenticatedBypassSkipsAttachmentInspection(t *testing.T) {
	analyzer := &countingAnalyzer{}
	server, conn, done := testServer(t, analyzer)
	enableTestAttachments(server)
	server.cfg.Filtering.ScanAuthenticated = false
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
