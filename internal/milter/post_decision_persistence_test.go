package milter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
	"github.com/PhilAnderson1/MilterGuard/internal/stores"
)

type contextObservingRejectionRepository struct {
	stores.RejectionHistoryRepository
	contextErrors chan error
}

func (r *contextObservingRejectionRepository) AddRejection(ctx context.Context, _ stores.NewRejection) (uint64, error) {
	r.contextErrors <- ctx.Err()
	return 1, nil
}

type contextObservingIPRepository struct {
	stores.IPReputationRepository
	contextErrors chan error
}

type failingRejectionRepository struct {
	stores.RejectionHistoryRepository
}

func (failingRejectionRepository) AddRejection(context.Context, stores.NewRejection) (uint64, error) {
	return 0, errors.New("database unavailable")
}

func TestArchivedRejectionWithoutDatabaseRecordLogsFilePath(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	root := t.TempDir()
	policy := &messagePolicyService{
		log: logger, rejectionHistory: failingRejectionRepository{},
		archive: rejectedmail.New(rejectedmail.Options{
			Directory: root, Retention: 24 * time.Hour, MaxTotalBytes: 1 << 20,
		}, logger),
	}
	msg := message.New(1024)
	msg.AddHeader("Message-ID", "<orphan@example.com>")
	policy.recordRejection(context.Background(), msg, "sender@example.com", "", []string{"owner@example.com"}, []string{"unwanted"}, "ai")
	paths, err := filepath.Glob(filepath.Join(root, "*", "*", "*", "*.eml"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("archived files = %v, error = %v", paths, err)
	}
	if _, err := os.Stat(paths[0]); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "rejected message copy saved without rejection history record") || !strings.Contains(logs.String(), paths[0]) {
		t.Fatalf("archive path missing from warning: %s", logs.String())
	}
}

func (r *contextObservingIPRepository) RecordRejection(ctx context.Context, address netip.Addr) (stores.IPBlock, error) {
	r.contextErrors <- ctx.Err()
	return stores.IPBlock{Address: address, Level: stores.IPBlockLevelShort, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestAttachmentRejectionPersistsAfterMessageContextCancellation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rejections := &contextObservingRejectionRepository{contextErrors: make(chan error, 1)}
	policy := &messagePolicyService{rejectionHistory: rejections, log: log}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	ss := newSession(&sessionDependencies{
		log: log, analysis: &analysisService{}, protocol: protocolOptions{maxMessageSize: 1024},
		attachments: &attachmentPolicyService{mode: "enforce", cfg: config.AttachmentsConfig{RejectMessage: "blocked"}, policy: policy},
	}, serverConn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan bool, 1)
	go func() { done <- ss.finishAttachmentDecision(ctx, actionReject, "invoice.exe", "executable", nil, "") }()
	expectFrame(t, clientConn, "y550 5.7.1 blocked\x00")
	if !<-done {
		t.Fatal("attachment rejection failed after response")
	}
	if err := <-rejections.contextErrors; err != nil {
		t.Fatalf("rejection persistence context error = %v", err)
	}
}

func TestSenderDomainRejectionPersistsAfterMessageContextCancellation(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rejections := &contextObservingRejectionRepository{contextErrors: make(chan error, 1)}
	ipRecords := &contextObservingIPRepository{contextErrors: make(chan error, 1)}
	policy := &messagePolicyService{
		mode: "enforce", filtering: config.FilteringConfig{RejectMessage: "blocked"}, log: log,
		rejectionHistory: rejections,
		ipReputation:     &ipReputationStore{repository: ipRecords, enabledFeature: true, log: log},
	}
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	ss := newSession(&sessionDependencies{
		log: log, analysis: &analysisService{}, protocol: protocolOptions{maxMessageSize: 1024}, policy: policy,
	}, serverConn)
	ss.peerIP = netip.MustParseAddr("192.0.2.10")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan bool, 1)
	go func() { done <- ss.finishAuthenticatedOnlySenderDomain(ctx, "example.com") }()
	expectFrame(t, clientConn, "y550 5.7.1 blocked\x00")
	if !<-done {
		t.Fatal("sender-domain rejection failed after response")
	}
	if err := <-rejections.contextErrors; err != nil {
		t.Fatalf("rejection persistence context error = %v", err)
	}
	if err := <-ipRecords.contextErrors; err != nil {
		t.Fatalf("IP strike persistence context error = %v", err)
	}
}
