package milter

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PhilAnderson1/MilterGuard/internal/ai"
	"github.com/PhilAnderson1/MilterGuard/internal/config"
	"github.com/PhilAnderson1/MilterGuard/internal/message"
)

const analysisResponseMargin = 5 * time.Second
const resourceLimitRejectMessage = "Message rejected because content processing exceeded server resource limits"
const incompleteInspectionPolicy = "incomplete-inspection"
const incompleteInspectionRejectMessage = "Message rejected because its content could not be fully inspected"

type Analyzer interface {
	Analyze(context.Context, ai.Input) (ai.Analysis, error)
}

type evaluationResult struct {
	incompleteInspection       bool
	proposed                   action
	selected                   action
	classification             ai.Classification
	score                      float64
	reasons                    []string
	visionImages               int
	tokenCost                  float64
	htmlPrimaryCPUExceeded     bool
	htmlFallbackCPUExceeded    bool
	htmlMemoryExceeded         bool
	htmlPrimaryMemoryExceeded  bool
	htmlFallbackMemoryExceeded bool
	htmlPrimaryMemoryBytes     int64
	htmlFallbackMemoryBytes    int64
	htmlCPUExceeded            bool
	htmlCPUAction              string
	rejectMessage              string
	err                        error
	latency                    time.Duration
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
func (s *analysisService) evaluate(parent context.Context, msg *message.Message, analysisContext message.AnalysisContext, mode string, rejectScore float64, aiErrorAction string, includeAIInput bool) (result evaluationResult) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, ai.MaximumAnalysisDuration(s.ai))
	defer cancel()

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
		return s.analysisFailure(ctx.Err(), started, mode, aiErrorAction)
	}

	prepared, usage := s.buildAnalysis(ctx, msg, analysisContext)
	htmlCPUExceeded := usage.CPUExceeded()
	defer func() {
		result.htmlPrimaryCPUExceeded = usage.PrimaryCPUExceeded
		result.htmlFallbackCPUExceeded = usage.FallbackCPUExceeded
		result.htmlMemoryExceeded = usage.MemoryExceeded
		result.htmlPrimaryMemoryExceeded = usage.PrimaryMemoryExceeded
		result.htmlFallbackMemoryExceeded = usage.FallbackMemoryExceeded
		result.htmlPrimaryMemoryBytes = usage.PrimaryMemoryBytes
		result.htmlFallbackMemoryBytes = usage.FallbackMemoryBytes
		result.htmlCPUExceeded = htmlCPUExceeded
		result.htmlCPUAction = s.ai.HTMLResourceLimitAction
		if result.htmlCPUAction == "" {
			result.htmlCPUAction = "reject"
		}
	}()
	if err := ctx.Err(); err != nil {
		return s.analysisFailure(err, started, mode, aiErrorAction)
	}
	actionOnHTMLLimit := s.ai.HTMLResourceLimitAction
	if actionOnHTMLLimit == "" {
		// Match the configured default for programmatic configurations too.
		actionOnHTMLLimit = "reject"
	}
	if (htmlCPUExceeded || usage.MemoryExceeded) && actionOnHTMLLimit != "fallback" {
		proposed := actionReject
		rejectMessage := resourceLimitRejectMessage
		classification := ai.Classification("")
		score := float64(0)
		if actionOnHTMLLimit == "dos-reject" {
			classification = ai.ClassificationUnwanted
			score = 1
		}
		reason := "Message content processing exceeded the configured CPU-time limit"
		if usage.MemoryExceeded {
			reason = "Message content processing exceeded the configured memory limit"
		}
		return evaluationResult{
			proposed: proposed, selected: selectActionForMode(proposed, mode),
			classification: classification, score: score,
			reasons:       []string{reason},
			rejectMessage: rejectMessage,
			latency:       time.Since(started),
		}
	}
	if s.ai.IncompleteBodyAction == "reject" && (prepared.BodyTruncated || prepared.BodyExtractionIncomplete) {
		proposed := actionReject
		return evaluationResult{
			proposed: proposed, selected: selectActionForMode(proposed, mode),
			incompleteInspection: true,
			rejectMessage:        incompleteInspectionRejectMessage,
			reasons:              []string{"message body extraction was incomplete"}, latency: time.Since(started),
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
		return failure
	}

	decision := aiResult.Decision
	proposed, selected := s.applyPolicy(decision, mode, rejectScore)
	return evaluationResult{
		proposed:       proposed,
		selected:       selected,
		classification: decision.Classification,
		score:          decision.Score,
		reasons:        decision.Reasons,
		visionImages:   len(input.Images),
		tokenCost:      tokenCost,
		latency:        time.Since(started),
	}
}

func (s *analysisService) buildAnalysis(ctx context.Context, msg *message.Message, analysisContext message.AnalysisContext) (message.Analysis, message.ProcessingUsage) {
	vision := message.VisionOptions{
		Mode:         s.ai.VisionMode,
		MinTextChars: s.ai.VisionMinTextChars,
		MaxImages:    s.ai.MaxImages,
		MaxBytes:     s.ai.MaxImageBytes,
		MaxPixels:    s.ai.MaxImagePixels,
	}
	return message.WithProcessingLimits(ctx, message.ProcessingLimits{
		AllowFallbackAfterLimit: s.ai.HTMLResourceLimitAction == "fallback",
		MemoryBytes:             s.ai.MaxHTMLParseMemoryBytes,
		MaxCPUMilliseconds:      s.ai.MaxHTMLParseCPUMilliseconds,
		DisableURLCompaction:    !s.ai.CompactPromptURLs,
		OnHTMLParserPanic: func() {
			if s.log != nil {
				s.log.ErrorContext(ctx, "HTML parser panic; using fallback extraction", "message_id", msg.Header("Message-ID"))
			}
		},
	}, func(control message.HTMLProcessingControl) message.Analysis {
		return msg.BuildAnalysisWithHTMLControl(analysisContext, s.ai.MaxBodyChars, vision, control)
	})
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
			"html_primary_cpu_limit_exceeded", result.htmlPrimaryCPUExceeded,
			"html_fallback_cpu_limit_exceeded", result.htmlFallbackCPUExceeded,
			"html_memory_limit_exceeded", result.htmlMemoryExceeded,
			"html_primary_memory_limit_exceeded", result.htmlPrimaryMemoryExceeded,
			"html_fallback_memory_limit_exceeded", result.htmlFallbackMemoryExceeded,
			"html_primary_memory_bytes", result.htmlPrimaryMemoryBytes,
			"html_fallback_memory_bytes", result.htmlFallbackMemoryBytes,
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
		"reasons", result.reasons, "proposed_action", result.proposed.String(),
		"actual_action", result.selected.String(),
		"latency_ms", result.latency.Milliseconds(), "truncated", msg.Truncated,
		"response_sent", sent, "vision_images", result.visionImages,
		"html_primary_cpu_limit_exceeded", result.htmlPrimaryCPUExceeded,
		"html_fallback_cpu_limit_exceeded", result.htmlFallbackCPUExceeded,
		"html_memory_limit_exceeded", result.htmlMemoryExceeded,
		"html_primary_memory_limit_exceeded", result.htmlPrimaryMemoryExceeded,
		"html_fallback_memory_limit_exceeded", result.htmlFallbackMemoryExceeded,
		"html_primary_memory_bytes", result.htmlPrimaryMemoryBytes,
		"html_fallback_memory_bytes", result.htmlFallbackMemoryBytes,
		"html_cpu_limit_exceeded", result.htmlCPUExceeded,
	}
	logMessage := "message classified"
	if result.incompleteInspection {
		logMessage = "message inspection policy decision"
		attrs = append(attrs, "policy", incompleteInspectionPolicy)
	} else {
		attrs = append(attrs, "classification", result.classification, "score", result.score, "model", s.ai.Model)
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
	s.log.Log(ctx, level, logMessage, attrs...)
}
