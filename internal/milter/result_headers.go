package milter

import (
	"strconv"
	"strings"
)

const (
	classificationHeader = "X-MilterGuard-Classification"
	scoreHeader          = "X-MilterGuard-Score"
	actionHeader         = "X-MilterGuard-Action"
)

var resultHeaderNames = []string{classificationHeader, scoreHeader, actionHeader}

// writeAcceptedResultHeaders removes sender-supplied result headers from every
// accepted message. Genuine values are then added only for an AI classification
// of unwanted whose confidence is below the configured rejection threshold.
func (ss *session) writeAcceptedResultHeaders(result *evaluationResult) error {
	if !ss.server.cfg.Filtering.AddUnwantedHeaders {
		return nil
	}
	if ss.negotiatedActions&resultHeaderActions != resultHeaderActions {
		return nil
	}
	for _, name := range resultHeaderNames {
		for range ss.message.Headers[strings.ToLower(name)] {
			if err := writeFrame(ss.conn, deleteHeaderResponse(name)); err != nil {
				return err
			}
		}
	}
	if result == nil || result.classification != "unwanted" || result.score >= ss.server.cfg.Filtering.RejectScore {
		return nil
	}
	headers := [][2]string{
		{classificationHeader, "unwanted"},
		{scoreHeader, strconv.FormatFloat(result.score, 'f', -1, 64)},
		{actionHeader, "accepted-below-threshold"},
	}
	for _, header := range headers {
		if err := writeFrame(ss.conn, addHeaderResponse(header[0], header[1])); err != nil {
			return err
		}
	}
	return nil
}
