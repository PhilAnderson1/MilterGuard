package htmlextract

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// A condition is a disjunction of alternatives; nested conditions are ANDed.
// Unknown is deliberately not false, including in partially supported queries.
type widthBound struct {
	min   bool
	value float64
}
type mediaAlternative struct {
	bounds         []widthBound
	schemes        uint8
	unknown, never bool
}
type mediaCondition []mediaAlternative

// conditionFrame is an immutable persistent stack. Rules in the same at-rule
// scope share the complete chain instead of copying one slice header per
// enclosing condition into every rule.
type conditionFrame struct {
	condition mediaCondition
	parent    *conditionFrame
}

func newConditionFrame(condition mediaCondition, parent *conditionFrame, memory *resourceguard.Memory) *conditionFrame {
	frame := resourceguard.New(memory, conditionFrame{condition: condition, parent: parent})
	return frame
}

const (
	mediaNo = iota
	mediaYes
	mediaUnknown
	mediaYesColourScheme
	mediaAlternateColourScheme
)

const (
	colourSchemeLight uint8 = 1 << iota
	colourSchemeDark
	colourSchemeBoth = colourSchemeLight | colourSchemeDark
)

var widthFeature = regexp.MustCompile(`^\(\s*(min|max)-(?:device-)?width\s*:\s*([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(px)?\s*\)$`)

func parseMediaWithBudget(src string, budget *cpuGuard) mediaCondition {
	memory := budget.allocationMemory()
	unknown := func() mediaCondition {
		out := resourceguard.MakeSlice[mediaAlternative](memory, 1, 1)

		out[0] = mediaAlternative{schemes: colourSchemeBoth, unknown: true}
		return out
	}
	if len(src) > 4096 || strings.Count(src, ",") > 31 {
		return unknown()
	}
	var result mediaCondition
	for raw := range strings.SplitSeq(asciiLowerWithBudget(src, budget), ",") {
		budget.check()

		a := mediaAlternative{schemes: colourSchemeBoth}
		raw = trimCSSWhitespace(strings.TrimPrefix(trimCSSWhitespace(raw), "only "))
		// The supported subset has no functions or nested query parentheses.
		parts := []string{raw}
		if strings.Contains(raw, "and") {
			// At most 17 results and bounded regexp match-index scratch. The extra
			// result detects excessive clauses without splitting the entire query.
			parts = resourceguard.RegexpSplit(memory, regexpAnd, raw, 17)
		}
		if len(parts) > 16 {
			return unknown()
		}
		for _, part := range parts {
			budget.check()

			part = trimCSSWhitespace(part)
			switch part {
			case "screen", "all":
			case "print":
				a.never = true
			case "(prefers-color-scheme:light)", "(prefers-color-scheme: light)":
				a.schemes &= colourSchemeLight
			case "(prefers-color-scheme:dark)", "(prefers-color-scheme: dark)":
				a.schemes &= colourSchemeDark
			default:
				m := resourceguard.RegexpSubmatch(memory, widthFeature, part)

				if m == nil {
					a.unknown = true
					continue
				}
				// Preserve the media grammar's acceptance of a trailing decimal point.
				v, valid := numberWithBudget(strings.TrimSuffix(m[2], "."), budget)
				if !valid || m[3] == "" && v != 0 {
					a.unknown = true
					continue
				}
				a.bounds = growSlice(a.bounds, 1, memory, budget.allocationStop)

				a.bounds = append(a.bounds, widthBound{m[1] == "min", v})
			}
		}
		if a.schemes == 0 {
			a.never = true
		}
		result = growSlice(result, 1, memory, budget.allocationStop)

		result = append(result, a)
	}
	return result
}

var regexpAnd = regexp.MustCompile(`\s+and\s+`)

func (c mediaCondition) states(width float64, fallback bool) (light, dark int) {
	light, dark = mediaNo, mediaNo
	for _, a := range c {
		ok := !a.never
		for _, b := range a.bounds {
			if !fallback && (b.min && width < b.value || !b.min && width > b.value) {
				ok = false
			}
		}
		if !ok {
			continue
		}
		unknown := a.unknown
		if fallback && len(a.bounds) > 0 {
			unknown = true
		}
		state := mediaYes
		if unknown {
			state = mediaUnknown
		}
		if a.schemes&colourSchemeLight != 0 {
			if state == mediaYes {
				light = mediaYes
			} else if light != mediaYes {
				light = mediaUnknown
			}
		}
		if a.schemes&colourSchemeDark != 0 {
			if state == mediaYes {
				dark = mediaYes
			} else if dark != mediaYes {
				dark = mediaUnknown
			}
		}
	}
	return light, dark
}

type conditionFrameState struct {
	light, dark int
}

// evaluateConditionFrame derives a frame from its parent. A cache shared by
// all rules at one width evaluates every immutable frame at most once.
func evaluateConditionFrame(frame *conditionFrame, width float64, fallback bool, cache map[*conditionFrame]conditionFrameState, budget *cpuGuard) (light, dark int) {
	budget.check()

	if frame == nil {
		return mediaYes, mediaYes
	}

	if state, ok := cache[frame]; ok {
		return state.light, state.dark
	}

	light, dark = evaluateConditionFrame(frame.parent, width, fallback, cache, budget)
	frameLight, frameDark := frame.condition.states(width, fallback)
	light = intersectMediaState(light, frameLight)
	dark = intersectMediaState(dark, frameDark)
	if cache != nil {
		cache[frame] = conditionFrameState{light: light, dark: dark}
	}
	return light, dark
}

func combinedMediaState(light, dark int) int {
	if light == mediaUnknown {
		return mediaUnknown
	}
	if light == mediaYes {
		if dark == mediaYes {
			return mediaYes
		}
		return mediaYesColourScheme
	}
	if dark != mediaNo {
		return mediaAlternateColourScheme
	}
	return mediaNo
}

func intersectMediaState(left, right int) int {
	if left == mediaNo || right == mediaNo {
		return mediaNo
	}
	if left == mediaUnknown || right == mediaUnknown {
		return mediaUnknown
	}
	return mediaYes
}

// Width-independent property values make activation vectors sufficient. Exact
// endpoints are separate from open intervals, so a one-point rule is covered.
// The fallback width is immutable and shared; callers only iterate it.
var defaultViewingWidths = [...]float64{1024}

func (s *sheet) viewingCases() ([]float64, bool) {
	fallback := func() ([]float64, bool) { return defaultViewingWidths[:], true }

	if s.cascadeIncomplete {
		return fallback()
	}
	s.prepareMediaGroups()

	var bounds []float64
	var unique resourceguard.Table[float64, bool]
	var seenFrames resourceguard.Table[*conditionFrame, bool]
	for _, group := range s.runtime.mediaGroups {
		s.checkCPU()

		for frame := group; frame != nil; frame = frame.parent {
			s.checkCPU()

			if _, seen := seenFrames.Get(frame); seen {
				break
			}

			seenFrames.Set(s.memory, frame, true)

			for _, a := range frame.condition {
				for _, b := range a.bounds {

					if _, seen := unique.Get(b.value); !seen {
						unique.Set(s.memory, b.value, true)

						bounds = resourceguard.Append(s.memory, bounds, s.shouldStop, b.value)
					}

				}
			}
		}
	}
	frameStates := resourceguard.MakeMap[*conditionFrame, conditionFrameState](s.memory, seenFrames.Len())

	scratch := makeBudgetedBytes(len(s.runtime.mediaGroups), s.memory)

	evaluate := func(width float64) []byte {
		// All possible keys were counted in seenFrames; this map is bounded scratch.
		clear(frameStates)
		states := scratch
		for i, group := range s.runtime.mediaGroups {
			s.checkCPU()

			light, dark := evaluateConditionFrame(group, width, false, frameStates, s.cpu)
			states[i] = uint8(combinedMediaState(light, dark))
		}
		return states
	}
	if len(bounds) == 0 {
		states := evaluate(1024)

		s.runtime.mediaCache.Set(s.memory, mediaCacheKey{width: 1024}, states)

		return defaultViewingWidths[:], false
	}
	candidates := resourceguard.MakeSlice[float64](s.memory, 1, len(bounds)*2+2)

	sort.Float64s(bounds)
	prev := 0.0
	for _, b := range bounds {
		if b > prev {
			candidates = append(candidates, prev+(b-prev)/2, b)
			prev = b
		}
	}

	if after := math.Nextafter(prev, math.Inf(1)); !math.IsInf(after, 0) {
		candidates = append(candidates, after)
	}

	var seen resourceguard.Table[string, bool]
	var widths []float64
	s.runtime.mediaCache.Release()
	work := s.resourceBudget()
	for _, width := range candidates {
		states := evaluate(width)

		// Lookup borrows scratch only for this expression. Retained signatures
		// and cached vectors get independent ownership before the next evaluation.
		if seen.View()[string(states[1:])] {
			continue
		}
		key := ownedString(states[1:], work)

		states = resourceguard.CloneBytes(s.memory, states, s.shouldStop)

		seen.Set(s.memory, key, true)
		s.runtime.mediaCache.Set(s.memory, mediaCacheKey{width: width}, states)

		widths = resourceguard.Append(s.memory, widths, s.shouldStop, width)
	}
	return widths, false
}

// Rules sharing a persistent condition chain always have identical media
// states. Group zero is the unconditional state and is omitted from signatures.
func (s *sheet) prepareMediaGroups() {
	if s.runtime.mediaGroups != nil {
		return
	}
	var ids resourceguard.Table[*conditionFrame, int]

	ids.Set(s.memory, nil, 0)

	groups := []*conditionFrame(nil)
	groups = growSlice(groups, 1, s.memory, s.shouldStop)

	groups = append(groups, nil)
	for i := range s.rules {
		s.checkCPU()

		frame := s.rules[i].conditions
		id, found := ids.Get(frame)
		if !found {
			id = len(groups)

			ids.Set(s.memory, frame, id)

			groups = growSlice(groups, 1, s.memory, s.shouldStop)

			groups = append(groups, frame)
		}
		s.rules[i].mediaGroup = id
	}
	s.runtime.mediaGroups = groups
	return
}

var neverMedia = [...]mediaAlternative{{schemes: colourSchemeBoth, never: true}}
var unknownMedia = [...]mediaAlternative{{schemes: colourSchemeBoth, unknown: true}}
