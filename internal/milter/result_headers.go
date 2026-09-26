package milter

import "strconv"

const (
	classificationHeader = "X-MilterGuard-Classification"
	scoreHeader          = "X-MilterGuard-Score"
	confidenceHeader     = "X-MilterGuard-Confidence"
	actionHeader         = "X-MilterGuard-Action"
)

var resultHeaderNames = []string{classificationHeader, scoreHeader, confidenceHeader, actionHeader}

// writeAcceptedResultHeaders removes sender-supplied result headers from every
// accepted message. When configured to add headers, it replaces them with the
// AI result, AI failure, or bypass outcome.
func (ss *session) writeAcceptedResultHeaders(result *evaluationResult) error {
	if err := ss.writeAcceptedAuthenticationHeaders(); err != nil {
		return err
	}
	return ss.writeAcceptedResultHeadersOnly(result)
}

func (ss *session) writeAcceptedResultHeadersOnly(result *evaluationResult) error {
	if !ss.deps.filtering.AddEmailHeaders && ss.deps.mode != "tag" {
		return ss.replaceResultHeaders(nil)
	}
	if result == nil {
		return ss.writeTagHeadersOnly("not-scanned", nil, "accepted-bypass")
	}
	var headers [][2]string
	if result.err != nil && result.selected == actionAccept {
		headers = [][2]string{
			{classificationHeader, "unavailable"},
			{confidenceHeader, "unavailable"},
			{actionHeader, "accepted-ai-error"},
		}
	} else {
		action := "accepted"
		if ss.deps.mode == "tag" || result.proposed == actionReject {
			action = acceptedModeLabel(ss.deps.mode)
		} else if result.classification == "unwanted" {
			action = "accepted-below-threshold"
		}
		headers = [][2]string{
			{classificationHeader, result.classification},
			{scoreHeader, strconv.FormatFloat(result.score, 'f', -1, 64)},
			{confidenceHeader, ss.confidenceLabel(result.classification, result.score)},
			{actionHeader, action},
		}
	}
	return ss.replaceResultHeaders(headers)
}

func (ss *session) writeAcceptedBypassHeaders() error {
	if ss.deps.mode == "tag" {
		return ss.writeTagHeaders("not-scanned", nil, "accepted-bypass")
	}
	return ss.writeAcceptedResultHeaders(nil)
}

func (ss *session) writeTagHeaders(classification string, score *float64, action string) error {
	if err := ss.writeAcceptedAuthenticationHeaders(); err != nil {
		return err
	}
	return ss.writeTagHeadersOnly(classification, score, action)
}

func (ss *session) writeTagHeadersOnly(classification string, score *float64, action string) error {
	headers := [][2]string{{classificationHeader, classification}}
	if score != nil {
		headers = append(headers, [2]string{scoreHeader, strconv.FormatFloat(*score, 'f', -1, 64)})
		headers = append(headers, [2]string{confidenceHeader, ss.confidenceLabel(classification, *score)})
	} else {
		headers = append(headers, [2]string{confidenceHeader, "unavailable"})
	}
	headers = append(headers, [2]string{actionHeader, action})
	return ss.replaceResultHeaders(headers)
}

func (ss *session) confidenceLabel(classification string, score float64) string {
	threshold := ss.deps.filtering.RejectScore
	if classification == "legitimate" {
		threshold = ss.deps.filtering.LegitimateLowConfidenceScore
	}
	if score < threshold {
		return "low"
	}
	return "high"
}

func (ss *session) replaceResultHeaders(headers [][2]string) error {
	received := make([]string, 0, len(resultHeaderNames))
	for _, name := range resultHeaderNames {
		if ss.message.HeaderOccurrences(name) > 0 {
			received = append(received, name)
		}
	}
	if ss.negotiatedActions&actionChangeHeaders != 0 {
		for _, name := range received {
			for range ss.message.HeaderOccurrences(name) {
				if err := writeFrame(ss.conn, deleteHeaderResponse(name)); err != nil {
					return err
				}
			}
		}
	} else if len(received) > 0 {
		ss.deps.log.Warn("sender-supplied MilterGuard result headers could not be removed because the MTA did not offer change-header support",
			"message_id", ss.message.Header("Message-ID"), "headers", received)
		// Do not add genuine values alongside counterfeit values that could not be
		// removed; the conflicting result set would be ambiguous downstream.
		return nil
	}
	if ss.negotiatedActions&actionAddHeaders == 0 {
		return nil
	}
	for _, header := range headers {
		if err := writeFrame(ss.conn, addHeaderResponse(header[0], header[1])); err != nil {
			return err
		}
	}
	return nil
}
