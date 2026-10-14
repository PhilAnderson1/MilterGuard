package htmlextract

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxMediaBreakpoints           = 512
	mediaPlanningWorkLimitDivisor = 4
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
	condition                    mediaCondition
	parent                       *conditionFrame
	mediaWork, fallbackMediaWork int64
}

func newConditionFrame(condition mediaCondition, parent *conditionFrame) *conditionFrame {
	frame := &conditionFrame{condition: condition, parent: parent}
	frame.mediaWork = conditionFrameWork(frame, false)
	frame.fallbackMediaWork = conditionFrameWork(frame, true)
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

func parseMedia(src string) mediaCondition {
	if len(src) > 4096 || strings.Count(src, ",") > 31 {
		return mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
	}
	var result mediaCondition
	for _, raw := range strings.Split(asciiLower(src), ",") {
		a := mediaAlternative{schemes: colourSchemeBoth}
		raw = trimCSSWhitespace(strings.TrimPrefix(trimCSSWhitespace(raw), "only "))
		// The supported subset has no functions or nested query parentheses.
		parts := regexpAnd.Split(raw, -1)
		if len(parts) > 16 {
			return mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
		}
		for _, part := range parts {
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
				m := widthFeature.FindStringSubmatch(part)
				if m == nil {
					a.unknown = true
					continue
				}
				v, err := strconv.ParseFloat(m[2], 64)
				if err != nil || math.IsInf(v, 0) || (m[3] == "" && v != 0) {
					a.unknown = true
					continue
				}
				a.bounds = append(a.bounds, widthBound{m[1] == "min", v})
			}
		}
		if a.schemes == 0 {
			a.never = true
		}
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

func (r rule) mediaState(width float64, fallback bool) int {
	light, dark := evaluateConditionFrame(r.conditions, width, fallback, nil)
	return combinedMediaState(light, dark)
}

type conditionFrameState struct {
	light, dark int
}

// evaluateConditionFrame derives a frame from its parent. A cache shared by
// all rules at one width evaluates every immutable frame at most once.
func evaluateConditionFrame(frame *conditionFrame, width float64, fallback bool, cache map[*conditionFrame]conditionFrameState) (light, dark int) {
	if frame == nil {
		return mediaYes, mediaYes
	}
	if state, ok := cache[frame]; ok {
		return state.light, state.dark
	}
	light, dark = evaluateConditionFrame(frame.parent, width, fallback, cache)
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

// mediaStateWork is a conservative structural cost for one mediaState call.
// It reflects the rule, condition, alternative and bound loops rather than a
// fixed multiplier that can underestimate a dense comma-separated query.
func calculatedMediaStateWork(r rule, fallback bool) int64 {
	return 1 + conditionFrameWork(r.conditions, fallback)
}

func conditionFrameWork(frame *conditionFrame, fallback bool) int64 {
	if frame == nil {
		return 0
	}
	if fallback && frame.fallbackMediaWork != 0 {
		return frame.fallbackMediaWork
	}
	if !fallback && frame.mediaWork != 0 {
		return frame.mediaWork
	}
	work := int64(1)
	for _, alternative := range frame.condition {
		work += 1 + int64(len(alternative.bounds))
	}
	if fallback {
		work += int64(len(frame.condition))
	}
	return work + conditionFrameWork(frame.parent, fallback)
}

func (r *rule) prepareMediaWork() {
	r.mediaWork = calculatedMediaStateWork(*r, false)
	r.fallbackMediaWork = calculatedMediaStateWork(*r, true)
}

func (r rule) mediaStateWork(fallback bool) int64 {
	if fallback {
		if r.fallbackMediaWork != 0 {
			return r.fallbackMediaWork
		}
	} else if r.mediaWork != 0 {
		return r.mediaWork
	}
	// Tests and other internal callers may construct a rule literal directly.
	return calculatedMediaStateWork(r, fallback)
}

// Width-independent property values make activation vectors sufficient. Exact
// endpoints are separate from open intervals, so a one-point rule is covered.
func (s *sheet) viewingCases(cap int) ([]float64, bool) {
	// No media decision can make an unusable cascade trustworthy. Retain one
	// traversal so text and elements are still extracted and labelled unknown,
	// but do not spend more work constructing activation vectors.
	if s.cascadeIncomplete || s.workIncomplete {
		return []float64{1024}, true
	}
	var bounds []float64
	unique := map[float64]bool{}
	seenFrames := map[*conditionFrame]bool{}
	var planningWork int64
	charge := func(cost int64) bool {
		// Breakpoint discovery is admission-control work, so reserve at most a
		// fixed fraction of the total selector/matching budget for it. Check
		// this phase-local allowance before the shared ceiling: reaching the
		// former selects conservative media fallback, while reaching the latter
		// makes all subsequent style evaluation unresolved.
		limit := s.limits.MatchWork / mediaPlanningWorkLimitDivisor
		if cost < 1 || planningWork > limit || cost > limit-planningWork {
			return false
		}
		if !s.chargePlanningCost(cost) {
			return false
		}
		planningWork += cost
		return true
	}
	for _, r := range s.rules {
		// Gathering breakpoints traverses the same condition structure once.
		if !charge(r.mediaStateWork(false)) {
			return []float64{1024}, true
		}
		for frame := r.conditions; frame != nil; frame = frame.parent {
			if seenFrames[frame] {
				continue
			}
			seenFrames[frame] = true
			c := frame.condition
			for _, a := range c {
				for _, b := range a.bounds {
					if !unique[b.value] {
						unique[b.value] = true
						bounds = append(bounds, b.value)
						if len(bounds) > maxMediaBreakpoints {
							return []float64{1024}, true
						}
					}
				}
			}
		}
	}
	var candidates []float64
	if len(bounds) == 0 {
		states := make([]uint8, 0, len(s.rules))
		var frameStates map[*conditionFrame]conditionFrameState
		if len(seenFrames) > 0 {
			frameStates = make(map[*conditionFrame]conditionFrameState, len(seenFrames))
		}
		for _, r := range s.rules {
			if !charge(r.mediaStateWork(false)) {
				return []float64{1024}, true
			}
			light, dark := evaluateConditionFrame(r.conditions, 1024, false, frameStates)
			states = append(states, uint8(combinedMediaState(light, dark)))
		}
		s.runtime.mediaCache = map[mediaCacheKey][]uint8{{width: 1024}: states}
		return []float64{1024}, false
	} else {
		sort.Float64s(bounds)
		candidates = []float64{0}
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
	}
	// Each activation vector becomes one string key. Candidate generation is
	// bounded by maxMediaBreakpoints, so these short-lived allocations cannot
	// grow with an unbounded number of media-query endpoints.
	seen := map[string]bool{}
	var widths []float64
	s.runtime.mediaCache = make(map[mediaCacheKey][]uint8)
	var frameStates map[*conditionFrame]conditionFrameState
	if len(seenFrames) > 0 {
		frameStates = make(map[*conditionFrame]conditionFrameState, len(seenFrames))
	}
	for _, w := range candidates {
		clear(frameStates)
		states := make([]uint8, 0, len(s.rules))
		for _, r := range s.rules {
			if !charge(r.mediaStateWork(false)) {
				return []float64{1024}, true
			}
			light, dark := evaluateConditionFrame(r.conditions, w, false, frameStates)
			states = append(states, uint8(combinedMediaState(light, dark)))
		}
		k := string(states)
		if seen[k] {
			continue
		}
		seen[k] = true
		widths = append(widths, w)
		if len(widths) > cap {
			return []float64{1024}, true
		}
		s.runtime.mediaCache[mediaCacheKey{width: w}] = states
	}
	return widths, false
}
