package milter

// selectActionForMode converts a proposed policy action into the action that
// may actually be enforced under the configured operating mode.
func selectActionForMode(proposed action, mode string) action {
	if mode != "enforce" {
		return actionAccept
	}
	return proposed
}

// responseForAction encodes one final Milter response. rejectMessage is used
// only when the selected action is rejection.
func responseForAction(selected action, rejectMessage string) []byte {
	switch selected {
	case actionReject:
		return replyCode("550", "5.7.1", rejectMessage)
	case actionTempfail:
		return []byte{responseTempfail}
	default:
		return []byte{responseAccept}
	}
}

// acceptedModeLabel identifies why a proposed rejection was accepted in a
// non-enforcing mode.
func acceptedModeLabel(mode string) string {
	if mode == "tag" {
		return "accepted-tag-mode"
	}
	return "accepted-monitor-mode"
}

// appendDecisionSubject adds the decoded subject to a completed-message
// decision log when subject logging is enabled.
func (ss *session) appendDecisionSubject(attrs []any) []any {
	if ss.deps.logging.IncludeSubject {
		return append(attrs, "subject", ss.message.DecodedHeader("Subject"))
	}
	return attrs
}
