package message

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

func prepareVisibleText(value string, memory *resourceguard.Memory, stop func()) string {
	if stop != nil {
		stop()
	}
	value = sanitizeSenderTextWithResources(value, memory, stop)
	if stop != nil {
		stop()
	}
	return compactFormattingPaddingWithResources(value, memory, stop)
}

func confidentTextCharactersWithResources(value string, memory *resourceguard.Memory, stop func()) int {
	value = prepareVisibleText(value, memory, stop)
	return confidentPreparedTextCharacters(value, stop)
}

// confidentPreparedTextCharacters counts text already processed by
// prepareVisibleText, without repeating sanitization or padding compaction.
func confidentPreparedTextCharacters(value string, stop func()) int {
	// Count normalized text directly: constructing a normalized copy solely to
	// count it wastes both memory and processing time.
	count, trimmed, meaningful := 0, 0, false
	space, newlines := false, 0
	nextCheck := 0
	for offset := 0; offset < len(value); {
		if offset >= nextCheck {
			if stop != nil {
				stop()
			}

			nextCheck = offset + resourceguard.WorkChunk
		}
		r, size := utf8.DecodeRuneInString(value[offset:])
		offset += size
		if r == utf8.RuneError && size == 1 {
			for offset < len(value) {
				if offset >= nextCheck {
					if stop != nil {
						stop()
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
		return 0
	}
	return trimmed
}

// Every text node consults the same extraction state. Bind its callback once
// instead of allocating an escaping method value for each node and pass.
func (e *htmlExtraction) textStopCallback() func() {
	if e.textClockCheck == nil {
		e.textClockCheck = resourceguard.BindCheckpoint(e.memory, e, func(e *htmlExtraction) { e.stopNow() })
	}
	if e.textShouldStop == nil {
		e.textStopSampler = resourceguard.NewStopSampler(10, e.textClockCheck)
		e.textShouldStop = resourceguard.BindCheckpoint(e.memory, e, func(e *htmlExtraction) {
			e.textStopSampler.Check()
		})
	}
	return e.textShouldStop
}

// Count optional evidence using the active stage's ledger. A stage transition
// stops this optional work rather than continuing against the retired ledger.
func (b *extractionBudget) confidentCharacters(value string) int {
	b.checkStage()
	if b.countingStop == nil {
		b.countingSampler = resourceguard.NewStopSampler(10, b.stageStop)
		b.countingStop = resourceguard.BindCheckpoint(b.allocationMemory(), b, func(b *extractionBudget) {
			b.countingSampler.Check()
		})
	}
	return confidentTextCharactersWithResources(value, b.allocationMemory(), b.countingStop)
}

// Detect long formatting runs without allocating a rune array. Ordinary text
// borrows the input; compacted output owns one guarded backing buffer.
func compactFormattingPaddingWithResources(value string, memory *resourceguard.Memory, stop func()) string {
	const threshold, retained = 32, 8
	runLength, hasFormat, needsCompaction := 0, false, false
	nextCheck := 0
	check := func(offset int) {
		if offset < nextCheck {
			return
		}
		nextCheck = offset + resourceguard.WorkChunk
		if stop != nil {
			stop()
		}
	}
	for offset, r := range value {
		check(offset)
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
		return value
	}
	var out strings.Builder

	resourceguard.GrowText(memory, &out, len(value), stop)

	nextCheck = 0
	for start := 0; start < len(value); {
		check(start)
		r, size := utf8.DecodeRuneInString(value[start:])
		if !preheaderPaddingRune(r) {
			if r == utf8.RuneError && size == 1 {
				resourceguard.WriteString(memory, &out, "�", stop)

				start++
				continue
			}
			end := start + size
			for end < len(value) {
				check(end)
				r, size = utf8.DecodeRuneInString(value[end:])
				if preheaderPaddingRune(r) || r == utf8.RuneError && size == 1 {
					break
				}
				end += size
			}

			resourceguard.WriteString(memory, &out, value[start:end], stop)

			start = end
			continue
		}
		end, keepEnd, count, format := start, start, 0, false
		for end < len(value) {
			check(end)
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
		resourceguard.WriteString(memory, &out, value[start:keepEnd], stop)

		start = end
	}
	return out.String()
}

// annotationScanner borrows the input and checks cancellation between bounded
// scans. Match state survives chunk boundaries; no carry buffer is needed.
type annotationScanner struct {
	value     string
	memory    *resourceguard.Memory
	stop      func()
	nextCheck int
}

func (s *annotationScanner) check(offset int) {
	if offset >= s.nextCheck {
		s.nextCheck = offset + resourceguard.WorkChunk
		if s.stop != nil {
			s.stop()
		}
	}
}
func (s *annotationScanner) find(start int, want byte) int {
	for start < len(s.value) {
		s.check(start)
		end := min(s.nextCheck, len(s.value))

		if i := strings.IndexByte(s.value[start:end], want); i >= 0 {
			return start + i
		}

		start = end
	}
	return -1
}
func annotationSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}
func annotationWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// The old regexp used Unicode simple folding. Long s is the only non-ASCII
// equivalent appearing in these fixed names; retain that spelling as well.
func annotationNameEnd(value string, start int) int {
	for _, name := range [...]string{"invisible", "visibility-varies-by-viewport-size", "visibility-uncertain", "hidden-content-stripped", "quoted-content", "attached-email", "attached-file"} {
		pos := start
		matched := true
		for i := 0; i < len(name); i++ {
			if pos == len(value) {
				matched = false
				break
			}
			c := value[pos]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c == name[i] {
				pos++
				continue
			}
			if name[i] == 's' && strings.HasPrefix(value[pos:], "ſ") {
				pos += len("ſ")
				continue
			}
			matched = false
			break
		}
		if matched && (pos == len(value) || !annotationWord(value[pos])) {
			return pos
		}
	}
	return -1
}
func sanitizeSenderTextWithResources(value string, memory *resourceguard.Memory, stop func()) string {
	scanner := annotationScanner{value: value, memory: memory, stop: stop}
	scanner.check(0)
	var out strings.Builder
	copied, search := 0, 0
	for search < len(value) {
		start := scanner.find(search, '<')
		if start < 0 {
			break
		}
		pos := start + 1
		if pos < len(value) && value[pos] == '/' {
			pos++
		}
		for pos < len(value) && annotationSpace(value[pos]) {
			scanner.check(pos)
			pos++
		}
		nameEnd := annotationNameEnd(value, pos)
		if nameEnd < 0 {
			// No '<' can occur in the whitespace just scanned. Do not rescan it.
			search = pos
			continue
		}
		end := scanner.find(nameEnd, '>')
		if end < 0 {
			break
		}

		if copied == 0 {
			resourceguard.GrowText(memory, &out, len(value), stop)
		}

		resourceguard.WriteString(memory, &out, value[copied:start], stop)

		copied = end + 1
		search = copied
	}
	if copied == 0 {
		return value
	}

	resourceguard.WriteString(memory, &out, value[copied:], stop)

	return out.String()
}
