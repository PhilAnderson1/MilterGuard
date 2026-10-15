package htmlextract

import "fmt"

// For caller-set attribute limits below this value, let the context-aware
// tokenizer enforce the exact limit. Allocating this many spans is small, and
// the floor prevents tag-shaped raw text from being rejected by the deliberately
// context-independent source scan.
const sourceAttributeGuardFloor = 4096

// preflightStartTagAttributes bounds attribute storage before x/net/html sees
// the input. The tokenizer retains every attribute span for a start tag before
// Next returns, so the ordinary lexical attribute check runs too late to guard
// that allocation.
//
// Every byte that can begin an HTML start tag is checked independently. This
// deliberately includes tag-shaped text in comments and raw-text elements: it
// can only cause a conservative rejection, while ensuring malformed lexical
// context cannot hide a real oversized tag from this allocation guard.
func preflightStartTagAttributes(input []byte, limit int, shouldStop func() bool) error {
	// Independently scanning overlapping tag-shaped ranges needs its own work
	// ceiling. Ordinary HTML costs approximately one additional pass; hostile
	// overlapping candidates are rejected instead of creating quadratic work.
	workLimit := int64(len(input))*4 + 1024
	var work int64
	for i := 0; i+1 < len(input); i++ {
		if input[i] != '<' || !asciiLetter(input[i+1]) {
			continue
		}
		attributes, err := sourceStartTagAttributes(input, i+1, &work, workLimit, shouldStop)
		if err != nil {
			return err
		}
		if attributes > limit {
			return fmt.Errorf("limit: source tag attributes > %d", limit)
		}
	}
	return nil
}

func asciiLetter(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func htmlSpace(c byte) bool {
	switch c {
	case ' ', '\n', '\r', '\t', '\f':
		return true
	}
	return false
}

func sourceStartTagAttributes(input []byte, i int, work *int64, workLimit int64, shouldStop func() bool) (int, error) {
	step := func() error {
		(*work)++
		if *work > workLimit {
			return fmt.Errorf("limit: HTML source preflight work > %d", workLimit)
		}
		if shouldStop != nil && *work&4095 == 0 && shouldStop() {
			return errStopped
		}
		return nil
	}

	// Tag name. The caller has already established that its first byte is an
	// ASCII letter, matching x/net/html's data-state start-tag transition.
	for i < len(input) {
		if err := step(); err != nil {
			return 0, err
		}
		c := input[i]
		if htmlSpace(c) || c == '/' || c == '>' {
			break
		}
		i++
	}

	attributes := 0
	for i < len(input) {
		for i < len(input) && htmlSpace(input[i]) {
			if err := step(); err != nil {
				return 0, err
			}
			i++
		}
		if i >= len(input) {
			return attributes, nil
		}
		if input[i] == '>' {
			if err := step(); err != nil {
				return 0, err
			}
			return attributes, nil
		}

		keyStart := i
		for i < len(input) {
			if err := step(); err != nil {
				return 0, err
			}
			c := input[i]
			i++
			// WHATWG's attribute-name state treats a leading '=' as part of
			// the name; a later '=' begins the value.
			if c == '=' && i == keyStart+1 {
				continue
			}
			if c == '=' || htmlSpace(c) || c == '/' || c == '>' {
				i--
				break
			}
		}
		if i > keyStart {
			attributes++
		}

		for i < len(input) && htmlSpace(input[i]) {
			if err := step(); err != nil {
				return 0, err
			}
			i++
		}
		if i >= len(input) {
			return attributes, nil
		}
		if err := step(); err != nil {
			return 0, err
		}
		c := input[i]
		i++
		if c == '/' {
			continue
		}
		if c != '=' {
			i--
			continue
		}

		for i < len(input) && htmlSpace(input[i]) {
			if err := step(); err != nil {
				return 0, err
			}
			i++
		}
		if i >= len(input) {
			return attributes, nil
		}
		if err := step(); err != nil {
			return 0, err
		}
		quote := input[i]
		i++
		if quote == '\'' || quote == '"' {
			for i < len(input) {
				if err := step(); err != nil {
					return 0, err
				}
				c = input[i]
				i++
				if c == quote {
					break
				}
			}
			continue
		}

		// Reconsume the first unquoted value byte. Only whitespace and '>'
		// terminate an unquoted HTML attribute value.
		i--
		for i < len(input) {
			if err := step(); err != nil {
				return 0, err
			}
			c = input[i]
			if htmlSpace(c) || c == '>' {
				break
			}
			i++
		}
	}
	return attributes, nil
}
