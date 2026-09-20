package milter

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const analysisResponseMargin = 5 * time.Second

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

func (s *analysisService) analysisTimeout() time.Duration {
	timeout := ai.MaximumAnalysisDuration(s.ai) + analysisResponseMargin
	if s.domainLookupTimeout > 0 {
		timeout += s.domainLookupTimeout
	}
	if s.milterTimeout > timeout {
		return s.milterTimeout
	}
	return timeout
}

// evaluate submits a prepared message to the analyzer and applies configured
// mode and confidence thresholds to produce the final Milter action.
func (s *analysisService) evaluate(parent context.Context, msg *message.Message) evaluationResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, ai.MaximumAnalysisDuration(s.ai))
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.analysisFailure(ctx.Err(), started)
	}

	analysis := msg.BuildAnalysis(s.ai.MaxBodyChars, message.VisionOptions{
		Mode:         s.ai.VisionMode,
		MinTextChars: s.ai.VisionMinTextChars,
		MaxImages:    s.ai.MaxImages,
		MaxBytes:     s.ai.MaxImageBytes,
		MaxPixels:    s.ai.MaxImagePixels,
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

func (s *analysisService) logAIInput(msg *message.Message, input ai.Input) {
	if !s.logging.IncludeAIInput {
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

func (s *analysisService) applyPolicy(decision ai.Decision) (action, action) {
	proposed := actionAccept
	if decision.Classification == "unwanted" && decision.Score >= s.filtering.RejectScore {
		proposed = actionReject
	}
	selected := proposed
	if s.mode != "enforce" {
		selected = actionAccept
	}
	return proposed, selected
}

func (s *analysisService) analysisFailure(err error, started time.Time) evaluationResult {
	selected := actionAccept
	if s.mode == "enforce" && s.filtering.AIErrorAction == "tempfail" {
		selected = actionTempfail
	}
	return evaluationResult{proposed: selected, selected: selected, err: err, latency: time.Since(started)}
}

func (s *analysisService) encodeAction(selected action) []byte {
	switch selected {
	case actionReject:
		return replyCode("550", "5.7.1", s.filtering.RejectMessage)
	case actionTempfail:
		return []byte{responseTempfail}
	default:
		return []byte{responseAccept}
	}
}

func (s *analysisService) logOutcome(ctx context.Context, msg *message.Message, result evaluationResult, sent bool, responseErr error) {
	if result.err != nil {
		logMessage := "message analysis failed"
		attrs := []any{
			"message_id", msg.Header("Message-ID"), "mode", s.mode,
			"actual_action", result.selected.String(), "error", result.err,
			"latency_ms", result.latency.Milliseconds(), "response_sent", sent,
			"vision_images", result.visionImages,
		}
		if responseErr != nil {
			attrs = append(attrs, "response_error", responseErr)
		}
		var endpointErr *ai.EndpointError
		if errors.As(result.err, &endpointErr) {
			attrs = append(attrs, "endpoint_error_kind", endpointErr.Kind.String())
			if endpointErr.StatusCode > 0 {
				attrs = append(attrs, "endpoint_status_code", endpointErr.StatusCode)
			}
			switch endpointErr.Kind {
			case ai.ErrorCredentials:
				logMessage = "AI endpoint credentials rejected"
			case ai.ErrorPaymentRequired:
				logMessage = "AI endpoint credit unavailable"
			}
		}
		s.log.Log(ctx, slog.LevelError, logMessage, attrs...)
		return
	}

	attrs := []any{
		"message_id", msg.Header("Message-ID"), "mode", s.mode,
		"classification", result.classification, "score", result.score,
		"reasons", result.reasons, "proposed_action", result.proposed.String(),
		"actual_action", result.selected.String(), "model", s.ai.Model,
		"latency_ms", result.latency.Milliseconds(), "truncated", msg.Truncated,
		"response_sent", sent, "vision_images", result.visionImages,
	}
	if s.logging.IncludeSubject {
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
