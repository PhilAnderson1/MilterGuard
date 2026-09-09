package milter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/attachment"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/jsonstore"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/rejectedmail"
)

const analysisResponseMargin = 5 * time.Second
const rejectedMailCleanupInterval = 24 * time.Hour
const milterIdleTimeout = 5 * time.Minute
const initialAcceptRetryDelay = 5 * time.Millisecond
const maximumAcceptRetryDelay = time.Second

var ErrInternalTokenGeneration = errors.New("cannot generate internal reply token")

type Analyzer interface {
	Analyze(context.Context, ai.Input) (ai.Decision, error)
}

type evaluationResult struct {
	proposed       action
	selected       action
	classification string
	score          float64
	reasons        []string
	visionImages   int
	err            error
	latency        time.Duration
}

type Server struct {
	cfg                config.Config
	analyzer           Analyzer
	log                *slog.Logger
	slots              chan struct{}
	sessionSlots       chan struct{}
	allowedPeerIPs     []netip.Prefix
	ipReputation       *ipReputationStore
	correspondents     *correspondentStore
	rejectionHistory   *rejectionHistoryStore
	domainRegistration *domainRegistrationStore
	rejectedMail       *rejectedmail.Archive
	resolver           dnsResolver
	attachments        *attachment.Scanner
	internalToken      string
	replySlots         chan struct{}
	persistence        *jsonstore.Manager
	wg                 sync.WaitGroup
	startupErr         error
}

func NewServer(cfg config.Config, analyzer Analyzer, log *slog.Logger) *Server {
	internalToken := ""
	var tokenErr error
	if cfg.EmailCommands.Enabled && cfg.EmailCommands.SendReplies {
		internalToken, tokenErr = generateInternalToken(rand.Reader)
	}
	server := &Server{cfg: cfg, analyzer: analyzer, log: log, slots: make(chan struct{}, cfg.AI.MaxConcurrent), sessionSlots: make(chan struct{}, cfg.Milter.MaxConnections), ipReputation: newIPReputationStore(cfg.IPReputation, log), correspondents: newCorrespondentStore(cfg.Correspondents, log), rejectionHistory: newRejectionHistoryStore(cfg.RejectionHistory, log), domainRegistration: newDomainRegistrationStore(cfg.DomainRegistration, log), resolver: net.DefaultResolver, internalToken: internalToken, replySlots: make(chan struct{}, 4)}
	server.allowedPeerIPs = peerPrefixes(cfg.Milter.AllowedPeerIPs)
	server.startupErr = errors.Join(
		tokenErr,
		persistenceLoadError("IP reputation", cfg.IPReputation.StateFile, server.ipReputation.loadErr),
		persistenceLoadError("correspondent", cfg.Correspondents.File, server.correspondents.loadErr),
		persistenceLoadError("rejection history", cfg.RejectionHistory.File, server.rejectionHistory.loadErr),
		persistenceLoadError("domain registration", cfg.DomainRegistration.StateFile, server.domainRegistration.loadErr),
	)
	server.persistence = jsonstore.NewManager(log)
	server.persistence.Add(server.ipReputation.db, server.correspondents.db, server.rejectionHistory.db, server.domainRegistration.db)
	if cfg.RejectedMail.Enabled {
		server.rejectedMail = rejectedmail.New(rejectedmail.Options{
			Directory: cfg.RejectedMail.Directory, Retention: cfg.RejectedMail.Retention.Value(),
			MaxMessages: cfg.RejectedMail.MaxMessages, MaxTotalBytes: cfg.RejectedMail.MaxTotalBytes,
		}, log)
	}
	if cfg.Attachments.BlockExecutables {
		server.attachments = attachment.New(attachment.Options{
			BlockedExtensions: cfg.Attachments.BlockedExtensions, InspectSignatures: cfg.Attachments.InspectSignatures,
			InspectArchives: cfg.Attachments.InspectArchives, MaxAttachmentBytes: cfg.Attachments.MaxAttachmentBytes,
			MaxArchiveDepth: cfg.Attachments.MaxArchiveDepth, MaxArchiveFiles: cfg.Attachments.MaxArchiveFiles,
			MaxArchiveUncompressedBytes: cfg.Attachments.MaxArchiveUncompressedBytes,
		})
	}
	return server
}

func generateInternalToken(random io.Reader) (string, error) {
	var tokenBytes [32]byte
	if _, err := io.ReadFull(random, tokenBytes[:]); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInternalTokenGeneration, err)
	}
	return hex.EncodeToString(tokenBytes[:]), nil
}

func persistenceLoadError(name, path string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s file %s: %w", name, path, err)
}

// StartupError reports persistent state that could not be loaded safely.
func (s *Server) StartupError() error { return s.startupErr }

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.startupErr != nil {
		return s.startupErr
	}
	s.persistence.Flush("startup")
	defer s.persistence.Flush("shutdown")
	s.startRejectedMailCleanup(ctx)
	if flushInterval := s.cfg.Persistence.FlushInterval.Value(); flushInterval > 0 {
		s.persistence.SetDeferred(true)
		flushCtx, stopFlush := context.WithCancel(ctx)
		flushDone := make(chan struct{})
		go func() {
			defer close(flushDone)
			ticker := time.NewTicker(flushInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					s.runMaintenance("persistence flush", func() {
						s.persistence.Flush("timer")
					})
				case <-flushCtx.Done():
					return
				}
			}
		}()
		defer func() {
			stopFlush()
			<-flushDone
		}()
	}
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := s.acceptConnection(ctx, ln)
		if err != nil {
			s.wg.Wait()
			return err
		}
		if !s.peerAllowed(conn.RemoteAddr()) {
			s.log.Warn("rejected unauthorized Milter connection", "remote_addr", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		select {
		case s.sessionSlots <- struct{}{}:
		default:
			s.log.Warn("maximum simultaneous Milter connections reached", "max_connections", s.cfg.Milter.MaxConnections, "remote_addr", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sessionSlots }()
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) acceptConnection(ctx context.Context, ln net.Listener) (net.Conn, error) {
	delay := time.Duration(0)
	for {
		conn, err := ln.Accept()
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		networkError, temporary := err.(net.Error)
		if !temporary || !networkError.Temporary() {
			return nil, err
		}
		if delay == 0 {
			delay = initialAcceptRetryDelay
		} else {
			delay *= 2
			if delay > maximumAcceptRetryDelay {
				delay = maximumAcceptRetryDelay
			}
		}
		s.log.Warn("temporary Milter listener error; retrying", "error", err, "retry_delay", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		}
	}
}

func peerPrefixes(entries []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(entry); err == nil {
			addr = addr.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return prefixes
}

func (s *Server) peerAllowed(remote net.Addr) bool {
	if remote == nil {
		return false
	}
	if remote.Network() == "unix" {
		return true
	}
	tcpAddress, ok := remote.(*net.TCPAddr)
	if !ok {
		return false
	}
	addr, ok := netip.AddrFromSlice(tcpAddress.IP)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.allowedPeerIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) startRejectedMailCleanup(ctx context.Context) {
	if s.rejectedMail == nil {
		return
	}
	s.runRejectedMailCleanup()
	go func() {
		ticker := time.NewTicker(rejectedMailCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.runRejectedMailCleanup()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) runRejectedMailCleanup() {
	s.runMaintenance("rejected-mail cleanup", func() {
		if err := s.rejectedMail.Cleanup(); err != nil {
			s.log.Warn("cannot clean rejected mail archive", "error", err)
		}
	})
}

func (s *Server) runMaintenance(name string, operation func()) {
	defer func() {
		if panicValue := recover(); panicValue != nil {
			s.logRecoveredWorkerPanic(context.Background(), name, panicValue)
		}
	}()
	operation()
}

func (s *Server) recordRejection(ctx context.Context, msg *message.Message, envelopeSender string, recipients, reasons []string, source string) {
	if msg == nil {
		return
	}
	recordID, err := s.rejectionHistory.addWithID(msg.Header("From"), envelopeSender, msg.Header("Subject"), recipients, reasons)
	if err != nil {
		s.log.ErrorContext(ctx, "cannot save rejection history", "message_id", msg.Header("Message-ID"), "error", err)
		recordID = 0
	}
	if s.rejectedMail == nil {
		return
	}
	contents := msg.ArchiveBytes()
	s.saveRejectedMailCopy(ctx, msg, contents, source, recordID)
}

func (s *Server) saveRejectedMailCopy(ctx context.Context, msg *message.Message, contents []byte, source string, recordID uint64) {
	var path string
	var err error
	if recordID == 0 {
		path, err = s.rejectedMail.Save(contents)
	} else {
		path, err = s.rejectedMail.SaveWithRecordID(contents, recordID)
	}
	if err != nil {
		s.log.WarnContext(ctx, "cannot save rejected message copy", "message_id", msg.Header("Message-ID"), "source", source, "rejection_id", recordID, "error", err)
		return
	}
	s.log.DebugContext(ctx, "rejected message copy saved", "message_id", msg.Header("Message-ID"), "source", source, "rejection_id", recordID, "file", path)
}

// handle is retained as the single-connection entry point used by tests.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer s.recoverSessionPanic(ctx, conn)
	newSession(s, conn).run(ctx)
}

func (s *Server) recoverSessionPanic(ctx context.Context, conn net.Conn) {
	panicValue := recover()
	if panicValue == nil {
		return
	}
	err := writeFrame(conn, []byte{responseTempfail})
	attrs := []any{
		"panic", fmt.Sprint(panicValue),
		"stack", string(debug.Stack()),
		"response_sent", err == nil,
	}
	if err != nil {
		attrs = append(attrs, "response_error", err)
	}
	s.logRecoveredWorkerPanic(ctx, "milter session", panicValue, attrs...)
}

func (s *Server) logRecoveredWorkerPanic(ctx context.Context, worker string, panicValue any, attrs ...any) {
	fields := []any{"worker", worker, "panic", fmt.Sprint(panicValue), "stack", string(debug.Stack())}
	fields = append(fields, attrs...)
	s.log.ErrorContext(ctx, "MilterGuard worker recovered from panic", fields...)
}

func (s *Server) analysisTimeout() time.Duration {
	timeout := s.cfg.AI.Timeout.Value()*time.Duration(s.cfg.AI.Retries+1) + analysisResponseMargin
	if s.cfg.DomainRegistration.Enabled {
		timeout += s.cfg.DomainRegistration.Timeout.Value()
	}
	if milterTimeout := s.cfg.Milter.Timeout.Value(); milterTimeout > timeout {
		return milterTimeout
	}
	return timeout
}

func (s *Server) evaluate(parent context.Context, msg *message.Message) evaluationResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, s.cfg.AI.Timeout.Value()*time.Duration(s.cfg.AI.Retries+1))
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.analysisFailure(ctx.Err(), started)
	}

	analysis := msg.BuildAnalysis(s.cfg.AI.MaxBodyChars, message.VisionOptions{
		Mode:         s.cfg.AI.VisionMode,
		MinTextChars: s.cfg.AI.VisionMinTextChars,
		MaxImages:    s.cfg.AI.MaxImages,
		MaxBytes:     s.cfg.AI.MaxImageBytes,
		MaxPixels:    s.cfg.AI.MaxImagePixels,
	})
	input := ai.Input{Text: analysis.Prompt, Images: make([]ai.Image, 0, len(analysis.Images))}
	for _, image := range analysis.Images {
		input.Images = append(input.Images, ai.Image{MediaType: image.MediaType, Data: image.Data})
	}
	s.logAIInput(msg, input)
	decision, err := s.analyzer.Analyze(ctx, input)
	if err != nil {
		failure := s.analysisFailure(err, started)
		failure.visionImages = len(input.Images)
		return failure
	}

	proposed, selected := s.applyPolicy(decision)
	return evaluationResult{
		proposed:       proposed,
		selected:       selected,
		classification: decision.Classification,
		score:          decision.Score,
		reasons:        decision.Reasons,
		visionImages:   len(input.Images),
		latency:        time.Since(started),
	}
}

func (s *Server) logAIInput(msg *message.Message, input ai.Input) {
	if !s.cfg.Logging.IncludeAIInput {
		return
	}
	images := make([]map[string]any, 0, len(input.Images))
	for _, image := range input.Images {
		images = append(images, map[string]any{
			"media_type": image.MediaType,
			"bytes":      len(image.Data),
		})
	}
	s.log.Debug("AI analysis input",
		"message_id", msg.Header("Message-ID"),
		"ai_input", input.Text,
		"image_count", len(input.Images),
		"images", images)
}

func (s *Server) applyPolicy(decision ai.Decision) (action, action) {
	proposed := actionAccept
	if decision.Classification == "unwanted" && decision.Score >= s.cfg.Filtering.RejectScore {
		proposed = actionReject
	}
	selected := proposed
	if s.cfg.Mode != "enforce" {
		selected = actionAccept
	}
	return proposed, selected
}

func (s *Server) analysisFailure(err error, started time.Time) evaluationResult {
	selected := actionAccept
	if s.cfg.Mode == "enforce" && s.cfg.Filtering.AIErrorAction == "tempfail" {
		selected = actionTempfail
	}
	return evaluationResult{proposed: selected, selected: selected, err: err, latency: time.Since(started)}
}

func (s *Server) encodeAction(selected action) []byte {
	switch selected {
	case actionReject:
		return replyCode("550", "5.7.1", s.cfg.Filtering.RejectMessage)
	case actionTempfail:
		return []byte{responseTempfail}
	default:
		return []byte{responseAccept}
	}
}

func (s *Server) logOutcome(ctx context.Context, msg *message.Message, result evaluationResult, sent bool, responseErr error) {
	if result.err != nil {
		attrs := []any{
			"message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode,
			"actual_action", result.selected.String(), "error", result.err,
			"latency_ms", result.latency.Milliseconds(), "response_sent", sent,
			"vision_images", result.visionImages,
		}
		if responseErr != nil {
			attrs = append(attrs, "response_error", responseErr)
		}
		s.log.Log(ctx, slog.LevelError, "message analysis failed", attrs...)
		return
	}

	attrs := []any{
		"message_id", msg.Header("Message-ID"), "mode", s.cfg.Mode,
		"classification", result.classification, "score", result.score,
		"reasons", result.reasons, "proposed_action", result.proposed.String(),
		"actual_action", result.selected.String(), "model", s.cfg.AI.Model,
		"latency_ms", result.latency.Milliseconds(), "truncated", msg.Truncated,
		"response_sent", sent, "vision_images", result.visionImages,
	}
	if s.cfg.Logging.IncludeSubject {
		attrs = append(attrs, "subject", msg.DecodedHeader("Subject"))
	}
	if responseErr != nil {
		attrs = append(attrs, "response_error", responseErr)
	}
	level := slog.LevelInfo
	if responseErr != nil {
		level = slog.LevelError
	}
	s.log.Log(ctx, level, "message classified", attrs...)
}
