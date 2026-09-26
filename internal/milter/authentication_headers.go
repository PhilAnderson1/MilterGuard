package milter

import (
	"context"
	"errors"
	"fmt"

	"github.com/PhilAnderson1/MilterGuard/internal/mailauth"
)

var ErrAuthenticationHeaderCapabilities = errors.New("MTA did not offer required authentication header capabilities")

var authenticationHeaderNames = []string{"Authentication-Results", "Received-SPF"}

func (ss *session) writeAcceptedAuthenticationHeaders() error {
	if !ss.internalAuthentication() {
		return nil
	}
	if ss.negotiatedActions&resultHeaderActions != resultHeaderActions {
		return fmt.Errorf("%w: internal mode requires add-header and change-header", ErrAuthenticationHeaderCapabilities)
	}
	var headers [][2]string
	// Authenticated submissions are not evaluated as inbound mail. Supplied
	// result fields are still removed, but no SPF/DKIM/DMARC claim replaces them.
	if !ss.authentication.Authenticated {
		value, err := mailauth.RenderAuthenticationResults(ss.mtaHostname, ss.message.Authentication)
		if err != nil {
			return fmt.Errorf("render local Authentication-Results: %w", err)
		}
		headers = [][2]string{{"Authentication-Results", value}}
	}
	return ss.replaceAuthenticationHeaders(headers, true)
}

// handleAuthenticationHeaderSafetyError converts a preflight failure into a
// temporary Milter failure. It is called before an accept response is written,
// so counterfeit or ambiguous authentication fields are never delivered.
func (ss *session) handleAuthenticationHeaderSafetyError(ctx context.Context, err error) (handled, keepConnection bool) {
	if !errors.Is(err, ErrAuthenticationHeaderCapabilities) && !errors.Is(err, mailauth.ErrInvalidAuthservID) {
		return false, false
	}
	ss.deps.log.ErrorContext(ctx, "cannot safely replace authentication result headers; check Postfix Milter macros and add/change-header capabilities",
		"message_id", ss.message.Header("Message-ID"), "error", err)
	if writeErr := writeFrame(ss.conn, []byte{responseTempfail}); writeErr != nil {
		ss.deps.log.ErrorContext(ctx, "cannot send temporary failure for authentication header safety error", "error", writeErr)
		return true, false
	}
	ss.resetMessage(phaseConnection)
	return true, true
}

// replaceAuthenticationHeaders is the sole path for deleting externally
// supplied authentication fields and adding locally generated replacements.
// Stage 1's compatibility provider does not invoke it because those trusted
// local fields remain the source of truth; internal verification will require
// capabilities and invoke this helper in Stage 2.
func (ss *session) replaceAuthenticationHeaders(headers [][2]string, requireCapabilities bool) error {
	received := 0
	for _, name := range authenticationHeaderNames {
		received += ss.message.HeaderOccurrences(name)
	}
	if received > 0 && ss.negotiatedActions&actionChangeHeaders == 0 {
		if requireCapabilities {
			return fmt.Errorf("%w: change-header", ErrAuthenticationHeaderCapabilities)
		}
		return nil
	}
	if len(headers) > 0 && ss.negotiatedActions&actionAddHeaders == 0 {
		if requireCapabilities {
			return fmt.Errorf("%w: add-header", ErrAuthenticationHeaderCapabilities)
		}
		return nil
	}
	for _, name := range authenticationHeaderNames {
		for range ss.message.HeaderOccurrences(name) {
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
