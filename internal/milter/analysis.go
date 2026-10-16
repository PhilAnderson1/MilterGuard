package milter

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
	"github.com/PhilAnderson1/MilterGuard/internal/threadcpu"
)

const analysisResponseMargin = 5 * time.Second

type Analyzer interface {
	Analyze(context.Context, ai.Input) (ai.Analysis, error)
}

type evaluationResult struct {
	proposed        action
	selected        action
	classification  ai.Classification
	score           float64
	reasons         []string
	visionImages    int
	tokenCost       float64
	htmlCPUTime     time.Duration
	htmlCPUExceeded bool
	htmlCPUAction   string
	rejectMessage   string
	err             error
	latency         time.Duration
}

func (s *analysisService) analysisTimeout() time.Duration {
	timeout := ai.MaximumAnalysisDuration(s.ai) + analysisResponseMargin
	if s.domainLookupTimeout > 0 {
		timeout += s.domainLookupTimeout
	}
	if s.authenticationTimeout > 0 {
		timeout += s.authenticationTimeout
	}
	if s.milterTimeout > timeout {
		return s.milterTimeout
	}
	return timeout
}

// evaluate submits a prepared message to the analyzer and applies configured
// mode and confidence thresholds to produce the final Milter action.
func (s *analysisService) evaluate(parent context.Context, msg *message.Message, analysisContext message.AnalysisContext, mode string, rejectScore float64, aiErrorAction string, includeAIInput bool) evaluationResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, ai.MaximumAnalysisDuration(s.ai))
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.analysisFailure(ctx.Err(), started, mode, aiErrorAction)
	}

	prepared, htmlCPUTime, cpuMeasured, htmlCPUExceeded := s.buildAnalysis(ctx, msg, analysisContext)
	if err := ctx.Err(); err != nil {
		failure := s.analysisFailure(err, started, mode, aiErrorAction)
		failure.htmlCPUTime = htmlCPUTime
		return failure
	}
	maximumHTMLCPU := time.Duration(s.ai.MaxHTMLParseCPUMilliseconds) * time.Millisecond
	actionOnHTMLLimit := s.ai.HTMLParseCPULimitAction
	if actionOnHTMLLimit == "" {
		// Preserve the historical behaviour for programmatic configurations
		// which predate the explicit action setting.
		actionOnHTMLLimit = "dos-reject"
	}
	if cpuMeasured && (htmlCPUExceeded || htmlCPUTime > maximumHTMLCPU) && actionOnHTMLLimit != "fallback" {
		proposed := actionReject
		rejectMessage := ""
		classification := ai.Classification("")
		score := float64(0)
		if actionOnHTMLLimit == "dos-reject" {
			rejectMessage = s.ai.HTMLDoSRejectMessage
			classification = ai.ClassificationUnwanted
			score = 1
		}
		return evaluationResult{
			proposed: proposed, selected: selectActionForMode(proposed, mode),
			classification: classification, score: score,
			reasons:     []string{"Message content processing exceeded the configured CPU-time limit"},
			htmlCPUTime: htmlCPUTime, htmlCPUExceeded: true, htmlCPUAction: actionOnHTMLLimit, rejectMessage: rejectMessage,
			latency: time.Since(started),
		}
	}
	if s.ai.IncompleteBodyAction == "reject" && (prepared.BodyTruncated || prepared.BodyExtractionIncomplete) {
		proposed := actionReject
		return evaluationResult{
			proposed: proposed, selected: selectActionForMode(proposed, mode),
			classification: ai.ClassificationUnwanted, score: 1,
			reasons: []string{"message body extraction was incomplete"}, latency: time.Since(started),
			htmlCPUTime: htmlCPUTime,
		}
	}
	input := ai.Input{Text: prepared.Prompt, Images: make([]ai.Image, 0, len(prepared.Images))}
	for _, image := range prepared.Images {
		input.Images = append(input.Images, ai.Image{MediaType: image.MediaType, Data: image.Data})
	}
	s.logAIInput(msg, input, includeAIInput)
	aiResult, err := s.analyzer.Analyze(ctx, input)
	tokenCost := tokenCost(aiResult.Usage, s.ai)
	if err != nil {
		failure := s.analysisFailure(err, started, mode, aiErrorAction)
		failure.visionImages = len(input.Images)
		failure.tokenCost = tokenCost
		failure.htmlCPUTime = htmlCPUTime
		failure.htmlCPUExceeded = htmlCPUExceeded
		failure.htmlCPUAction = actionOnHTMLLimit
		return failure
	}

	decision := aiResult.Decision
	proposed, selected := s.applyPolicy(decision, mode, rejectScore)
	return evaluationResult{
		proposed:        proposed,
		selected:        selected,
		classification:  decision.Classification,
		score:           decision.Score,
		reasons:         decision.Reasons,
		visionImages:    len(input.Images),
		tokenCost:       tokenCost,
		htmlCPUTime:     htmlCPUTime,
		htmlCPUExceeded: htmlCPUExceeded,
		htmlCPUAction:   actionOnHTMLLimit,
		latency:         time.Since(started),
	}
}

func (s *analysisService) buildAnalysis(ctx context.Context, msg *message.Message, analysisContext message.AnalysisContext) (message.Analysis, time.Duration, bool, bool) {
	vision := message.VisionOptions{
		Mode:         s.ai.VisionMode,
		MinTextChars: s.ai.VisionMinTextChars,
		MaxImages:    s.ai.MaxImages,
		MaxBytes:     s.ai.MaxImageBytes,
		MaxPixels:    s.ai.MaxImagePixels,
	}
	control := message.HTMLProcessingControl{DisableURLCompaction: !s.ai.CompactPromptURLs}
	contextStopped := func() bool { return ctx.Err() != nil }
	if s.ai.MaxHTMLParseCPUMilliseconds == 0 {
		control.ShouldFallback = contextStopped
		control.FallbackShouldStop = contextStopped
		return msg.BuildAnalysisWithHTMLControl(analysisContext, s.ai.MaxBodyChars, vision, control), 0, false, false
	}
	clock := threadcpu.Now
	if s.threadCPUTime != nil {
		clock = s.threadCPUTime
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	started, startedOK := clock()
	maximum := time.Duration(s.ai.MaxHTMLParseCPUMilliseconds) * time.Millisecond
	exceeded := false
	shouldFallback := func() bool {
		if contextStopped() {
			return true
		}
		if exceeded || !startedOK {
			return exceeded
		}
		current, ok := clock()
		if ok && current >= started && current-started > maximum {
			exceeded = true
		}
		return exceeded
	}
	control.ShouldFallback = shouldFallback
	fallbackStarted := time.Duration(0)
	fallbackStartedOK := false
	fallbackExceeded := false
	control.FallbackShouldStop = func() bool {
		if contextStopped() {
			return true
		}
		if fallbackExceeded {
			return true
		}
		current, ok := clock()
		if !ok {
			return false
		}
		if !fallbackStartedOK {
			fallbackStarted = current
			fallbackStartedOK = true
			return false
		}
		if current >= fallbackStarted && current-fallbackStarted > maximum {
			fallbackExceeded = true
		}
		return fallbackExceeded
	}
	prepared := msg.BuildAnalysisWithHTMLControl(analysisContext, s.ai.MaxBodyChars, vision, control)
	finished, finishedOK := clock()
	if !startedOK || !finishedOK || finished < started {
		return prepared, 0, false, prepared.HTMLCPULimitExceeded
	}
	duration := finished - started
	exceeded = exceeded || prepared.HTMLCPULimitExceeded || duration > maximum
	if exceeded && prepared.HasHTML && s.ai.HTMLParseCPULimitAction == "fallback" && !prepared.HTMLCPULimitExceeded {
		// The final prompt-building phase crossed the limit after the last HTML
		// checkpoint. Rebuild cheaply so fallback mode never submits a fully
		// processed over-budget representation.
		control.ShouldFallback = nil
		control.ForceFallback = true
		prepared = msg.BuildAnalysisWithHTMLControl(analysisContext, s.ai.MaxBodyChars, vision, control)
		last, ok := clock()
		if ok && last >= started {
			duration = last - started
		}
	}
	return prepared, duration, true, exceeded
}

func tokenCost(usage ai.Usage, cfg config.AIConfig) float64 {
	return float64(usage.InputTokens)/1_000_000*cfg.InputCostPerMillionTokens +
		float64(usage.OutputTokens)/1_000_000*cfg.OutputCostPerMillionTokens
}

func (s *analysisService) logAIInput(msg *message.Message, input ai.Input, enabled bool) {
	if !enabled {
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

func (s *analysisService) applyPolicy(decision ai.Decision, mode string, rejectScore float64) (action, action) {
	proposed := actionAccept
	if decision.Classification == ai.ClassificationUnwanted && decision.Score >= rejectScore {
		proposed = actionReject
	}
	return proposed, selectActionForMode(proposed, mode)
}

func (s *analysisService) analysisFailure(err error, started time.Time, mode, aiErrorAction string) evaluationResult {
	selected := actionAccept
	if mode == "enforce" && aiErrorAction == "tempfail" {
		selected = actionTempfail
	}
	return evaluationResult{proposed: selected, selected: selected, err: err, latency: time.Since(started)}
}

func (s *analysisService) logOutcome(ctx context.Context, msg *message.Message, result evaluationResult, mode string, includeSubject, sent bool, responseErr error) {
	if result.err != nil {
		logMessage := "message analysis failed"
		attrs := []any{
			"message_id", msg.Header("Message-ID"), "mode", mode,
			"actual_action", result.selected.String(), "error", result.err,
			"latency_ms", result.latency.Milliseconds(), "response_sent", sent,
			"vision_images", result.visionImages,
			"html_processing_cpu_ms", result.htmlCPUTime.Milliseconds(),
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
		"message_id", msg.Header("Message-ID"), "mode", mode,
		"classification", result.classification, "score", result.score,
		"reasons", result.reasons, "proposed_action", result.proposed.String(),
		"actual_action", result.selected.String(), "model", s.ai.Model,
		"latency_ms", result.latency.Milliseconds(), "truncated", msg.Truncated,
		"response_sent", sent, "vision_images", result.visionImages,
		"html_processing_cpu_ms", result.htmlCPUTime.Milliseconds(),
		"html_cpu_limit_exceeded", result.htmlCPUExceeded,
	}
	if includeSubject {
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
