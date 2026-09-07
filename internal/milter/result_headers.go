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
// accepted message. Genuine values are then added for tag mode, an AI
// classification of unwanted below the rejection threshold, or an AI failure.
func (ss *session) writeAcceptedResultHeaders(result *evaluationResult) error {
	if !ss.server.cfg.Filtering.AddUnwantedHeaders && ss.server.cfg.Mode != "tag" {
		return nil
	}
	if result == nil {
		return ss.replaceResultHeaders(nil)
	}
	var headers [][2]string
	if result.err != nil && result.selected == actionAccept {
		headers = [][2]string{
			{classificationHeader, "unavailable"},
			{actionHeader, "accepted-ai-error"},
		}
	} else if ss.server.cfg.Mode == "tag" {
		headers = [][2]string{
			{classificationHeader, result.classification},
			{scoreHeader, strconv.FormatFloat(result.score, 'f', -1, 64)},
			{actionHeader, "accepted-tag-mode"},
		}
	} else if result.classification == "unwanted" && result.score < ss.server.cfg.Filtering.RejectScore {
		headers = [][2]string{
			{classificationHeader, "unwanted"},
			{scoreHeader, strconv.FormatFloat(result.score, 'f', -1, 64)},
			{actionHeader, "accepted-below-threshold"},
		}
	} else {
		return ss.replaceResultHeaders(nil)
	}
	return ss.replaceResultHeaders(headers)
}

func (ss *session) writeAcceptedBypassHeaders() error {
	if ss.server.cfg.Mode == "tag" {
		return ss.writeTagHeaders("not-scanned", nil, "accepted-bypass")
	}
	return ss.writeAcceptedResultHeaders(nil)
}

func (ss *session) writeTagHeaders(classification string, score *float64, action string) error {
	headers := [][2]string{{classificationHeader, classification}}
	if score != nil {
		headers = append(headers, [2]string{scoreHeader, strconv.FormatFloat(*score, 'f', -1, 64)})
	}
	headers = append(headers, [2]string{actionHeader, action})
	return ss.replaceResultHeaders(headers)
}

func (ss *session) replaceResultHeaders(headers [][2]string) error {
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
	for _, header := range headers {
		if err := writeFrame(ss.conn, addHeaderResponse(header[0], header[1])); err != nil {
			return err
		}
	}
	return nil
}
