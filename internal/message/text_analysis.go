package message

import (
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func prepareVisibleText(value string, memory *resourceguard.Memory, stop func() bool) (string, bool) {
	if memory.Exhausted() || stop != nil && stop() {
		return "", false
	}
	value, ok := sanitizeSenderTextWithResources(value, memory, stop)
	if !ok || stop != nil && stop() {
		return "", false
	}
	return compactFormattingPaddingWithResources(value, memory, stop)
}

func confidentTextCharacters(value string) int {
	count, _ := confidentTextCharactersWithResources(value, nil, nil)
	return count
}
func confidentTextCharactersWithResources(value string, memory *resourceguard.Memory, stop func() bool) (int, bool) {
	value, ok := prepareVisibleText(value, memory, stop)
	if !ok {
		return 0, false
	}
	// Count normalized text directly: constructing a normalized copy solely to
	// count it wastes both memory and processing time.
	count, trimmed, meaningful := 0, 0, false
	space, newlines := false, 0
	nextCheck := 0
	for offset := 0; offset < len(value); {
		if offset >= nextCheck {
			if stop != nil && stop() {
				return 0, false
			}
			nextCheck = offset + resourceguard.WorkChunk
		}
		r, size := utf8.DecodeRuneInString(value[offset:])
		offset += size
		if r == utf8.RuneError && size == 1 {
			for offset < len(value) {
				if offset >= nextCheck {
					if stop != nil && stop() {
						return 0, false
					}
					nextCheck = offset + resourceguard.WorkChunk
				}
				next, n := utf8.DecodeRuneInString(value[offset:])
				if next != utf8.RuneError || n != 1 {
					break
				}
				offset++
			}
		}
		switch r {
		case ' ', '\t', '\f':
			space = true
		case '\r', '\n':
			space = false
			if count > 0 && newlines < 2 {
				count++
				newlines++
			}
		default:
			if space && count > 0 && newlines == 0 {
				count++
			}
			space, newlines = false, 0
			count++
			trimmed = count
			meaningful = meaningful || !preheaderPaddingRune(r)
		}
	}
	if !meaningful {
		return 0, true
	}
	return trimmed, true
}

// Count optional evidence using the active stage's ledger. A stage transition
// stops this optional work rather than continuing against the retired ledger.
func (b *extractionBudget) confidentCharacters(value string) (int, bool) {
	if b.outputShouldStop() {
		return 0, false
	}
	stage := b.fallback
	memory := b.fallbackMemory()
	if memory == nil {
		memory = resourceguard.NewMemory(b.memoryBytesRemaining)
		defer b.consumeMemory(memory)
	}
	count, ok := confidentTextCharactersWithResources(value, memory, func() bool { return b.outputShouldStop() || b.fallback != stage })
	b.observeFallback()
	return count, ok
}

// Detect long formatting runs without allocating a rune array. Ordinary text
// borrows the input; compacted output owns one guarded backing buffer.
func compactFormattingPaddingWithResources(value string, memory *resourceguard.Memory, stop func() bool) (string, bool) {
	const threshold, retained = 32, 8
	runLength, hasFormat, needsCompaction := 0, false, false
	nextCheck := 0
	check := func(offset int) bool {
		if offset < nextCheck {
			return false
		}
		nextCheck = offset + resourceguard.WorkChunk
		return memory.Exhausted() || stop != nil && stop()
	}
	for offset, r := range value {
		if check(offset) {
			return "", false
		}
		if !preheaderPaddingRune(r) {
			runLength = 0
			hasFormat = false
			continue
		}
		runLength++
		hasFormat = hasFormat || !unicode.IsSpace(r)
		if runLength >= threshold && hasFormat {
			needsCompaction = true
			break
		}
	}
	if !needsCompaction {
		return value, true
	}
	var out strings.Builder
	if !resourceguard.GrowText(memory, &out, len(value), stop) {
		return "", false
	}
	nextCheck = 0
	for start := 0; start < len(value); {
		if check(start) {
			return "", false
		}
		r, size := utf8.DecodeRuneInString(value[start:])
		if !preheaderPaddingRune(r) {
			if r == utf8.RuneError && size == 1 {
				if !resourceguard.WriteString(memory, &out, "�", stop) {
					return "", false
				}
				start++
				continue
			}
			end := start + size
			for end < len(value) {
				if check(end) {
					return "", false
				}
				r, size = utf8.DecodeRuneInString(value[end:])
				if preheaderPaddingRune(r) || r == utf8.RuneError && size == 1 {
					break
				}
				end += size
			}
			if !resourceguard.WriteString(memory, &out, value[start:end], stop) {
				return "", false
			}
			start = end
			continue
		}
		end, keepEnd, count, format := start, start, 0, false
		for end < len(value) {
			if check(end) {
				return "", false
			}
			r, size = utf8.DecodeRuneInString(value[end:])
			if !preheaderPaddingRune(r) {
				break
			}
			format = format || !unicode.IsSpace(r)
			end += size
			count++
			if count <= retained {
				keepEnd = end
			}
		}
		if !format || count < threshold {
			keepEnd = end
		}
		// Padding runes are valid UTF-8; invalid bytes took the replacement path,
		// preserving the previous []rune conversion's replacement semantics.
		if !resourceguard.WriteString(memory, &out, value[start:keepEnd], stop) {
			return "", false
		}
		start = end
	}
	return out.String(), true
}

// The regexp can read a long unmatched annotation. Sample its input as well as
// output copies so malformed sender text cannot hide work inside the library.
type annotationReader struct {
	reader            strings.Reader
	stop              func() bool
	nextCheck, offset int
	stopped           bool
}

func (r *annotationReader) ReadRune() (rune, int, error) {
	if r.offset >= r.nextCheck {
		r.nextCheck = r.offset + resourceguard.WorkChunk
		if r.stop != nil && r.stop() {
			r.stopped = true
			return 0, 0, io.EOF
		}
	}
	c, n, err := r.reader.ReadRune()
	r.offset += n
	return c, n, err
}
func sanitizeSenderTextWithResources(value string, memory *resourceguard.Memory, stop func() bool) (string, bool) {
	if memory.Exhausted() || stop != nil && stop() {
		return "", false
	}
	if !strings.Contains(value, "<") {
		return value, true
	}
	var out strings.Builder
	offset := 0
	for {
		reader, ok := resourceguard.New(memory, annotationReader{reader: *strings.NewReader(value[offset:]), stop: stop})
		if !ok {
			return "", false
		}
		match, ok := resourceguard.RegexpFindReaderIndex(memory, reservedAnnotation, reader)
		if !ok || reader.stopped {
			return "", false
		}
		if match == nil {
			if offset == 0 {
				return value, true
			}
			if !resourceguard.WriteString(memory, &out, value[offset:], stop) {
				return "", false
			}
			return out.String(), true
		}
		if offset == 0 && !resourceguard.GrowText(memory, &out, len(value), stop) {
			return "", false
		}
		if !resourceguard.WriteString(memory, &out, value[offset:offset+match[0]], stop) {
			return "", false
		}
		offset += match[1]
	}
}
