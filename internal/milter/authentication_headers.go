package milter

import (
	"errors"
	"fmt"
)

var ErrAuthenticationHeaderCapabilities = errors.New("MTA did not offer required authentication header capabilities")

var authenticationHeaderNames = []string{"Authentication-Results", "Received-SPF"}

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
