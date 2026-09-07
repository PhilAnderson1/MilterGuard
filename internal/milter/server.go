package milter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	cfg              config.Config
	analyzer         Analyzer
	log              *slog.Logger
	slots            chan struct{}
	ipReputation     *ipReputationStore
	correspondents   *correspondentStore
	rejectionHistory *rejectionHistoryStore
	rejectedMail     *rejectedmail.Archive
	resolver         dnsResolver
	attachments      *attachment.Scanner
	internalToken    string
	replySlots       chan struct{}
	persistence      *jsonstore.Manager
	wg               sync.WaitGroup
	startupErr       error
}

func NewServer(cfg config.Config, analyzer Analyzer, log *slog.Logger) *Server {
	var tokenBytes [32]byte
	_, _ = rand.Read(tokenBytes[:])
	server := &Server{cfg: cfg, analyzer: analyzer, log: log, slots: make(chan struct{}, cfg.AI.MaxConcurrent), ipReputation: newIPReputationStore(cfg.IPReputation, log), correspondents: newCorrespondentStore(cfg.Correspondents, log), rejectionHistory: newRejectionHistoryStore(cfg.RejectionHistory, log), resolver: net.DefaultResolver, internalToken: hex.EncodeToString(tokenBytes[:]), replySlots: make(chan struct{}, 4)}
	server.startupErr = errors.Join(
		persistenceLoadError("IP reputation", cfg.IPReputation.StateFile, server.ipReputation.loadErr),
		persistenceLoadError("correspondent", cfg.Correspondents.File, server.correspondents.loadErr),
		persistenceLoadError("rejection history", cfg.RejectionHistory.File, server.rejectionHistory.loadErr),
	)
	server.persistence = jsonstore.NewManager(log)
	server.persistence.Add(server.ipReputation.db, server.correspondents.db, server.rejectionHistory.db)
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
					s.persistence.Flush("timer")
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
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return ctx.Err()
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			newSession(s, conn).run(ctx)
		}()
	}
}

func (s *Server) startRejectedMailCleanup(ctx context.Context) {
	if s.rejectedMail == nil {
		return
	}
	if err := s.rejectedMail.Cleanup(); err != nil {
		s.log.Warn("cannot clean rejected mail archive", "error", err)
	}
	go func() {
		ticker := time.NewTicker(rejectedMailCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := s.rejectedMail.Cleanup(); err != nil {
					s.log.Warn("cannot clean rejected mail archive", "error", err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Server) recordRejection(ctx context.Context, msg *message.Message, envelopeSender string, recipients, reasons []string, source string) {
	if msg == nil {
		return
	}
	recordID, err := s.rejectionHistory.addWithID(msg.Header("From"), envelopeSender, recipients, reasons)
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
	newSession(s, conn).run(ctx)
}

func (s *Server) analysisTimeout() time.Duration {
	timeout := s.cfg.AI.Timeout.Value()*time.Duration(s.cfg.AI.Retries+1) + analysisResponseMargin
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
		attrs = append(attrs, "subject", msg.Header("Subject"))
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
