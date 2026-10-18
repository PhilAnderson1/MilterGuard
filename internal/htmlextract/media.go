package htmlextract

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// Conservative estimates for the temporary and retained maps built while
// reducing media-query widths to distinct activation vectors.
const (
	mediaFrameSetEntryBytes      int64 = 32
	mediaBoundSetEntryBytes      int64 = 24
	mediaFrameStateMapBytes      int64 = 128
	mediaViewingCaseMapsBytes    int64 = 256
	mediaActivationOverheadBytes int64 = 48
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
	if !memory.Reserve(int64(unsafe.Sizeof(conditionFrame{}))) {
		return nil
	}
	return &conditionFrame{condition: condition, parent: parent}
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

func parseMedia(src string) mediaCondition { return parseMediaBudgeted(src, nil) }

// Both retained conditions and temporary applicability parsing consume the
// monotonic allocation budget. Per-query bounds also limit regexp scratch.
func parseMediaBudgeted(src string, memory *resourceguard.Memory) mediaCondition {
	return parseMediaWithBudget(src, &cpuGuard{memory: memory})
}
func parseMediaWithBudget(src string, budget *cpuGuard) mediaCondition {
	memory := budget.allocationMemory()
	unknown := func() mediaCondition {
		if !memory.Reserve(int64(unsafe.Sizeof(mediaAlternative{}))) {
			return nil
		}
		return mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
	}
	if len(src) > 4096 || strings.Count(src, ",") > 31 {
		return unknown()
	}
	if !budget.reserve(int64(strings.Count(src, ",")+1) * 16) {
		return nil
	}
	var result mediaCondition
	for _, raw := range strings.Split(asciiLowerWithBudget(src, budget), ",") {
		if !budget.check() {
			return nil
		}
		a := mediaAlternative{schemes: colourSchemeBoth}
		raw = trimCSSWhitespace(strings.TrimPrefix(trimCSSWhitespace(raw), "only "))
		// The supported subset has no functions or nested query parentheses.
		parts := []string{raw}
		if strings.Contains(raw, "and") {
			// At most 17 results and bounded regexp match-index scratch. The extra
			// result detects excessive clauses without splitting the entire query.
			if !budget.reserve(17 * 128) {
				return nil
			}
			parts = regexpAnd.Split(raw, 17)
		}
		if len(parts) > 16 {
			return unknown()
		}
		for _, part := range parts {
			if !budget.check() {
				return nil
			}
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
				if !budget.reserve(256) {
					return nil
				}
				m := widthFeature.FindStringSubmatch(part)
				if m == nil {
					a.unknown = true
					continue
				}
				// Preserve the media grammar's acceptance of a trailing decimal point.
				v, valid := numberWithBudget(strings.TrimSuffix(m[2], "."), budget)
				if !valid || (m[3] == "" && v != 0) {
					a.unknown = true
					continue
				}
				var ok bool
				a.bounds, ok = growSlice(a.bounds, 1, memory)
				if !ok {
					return nil
				}
				a.bounds = append(a.bounds, widthBound{m[1] == "min", v})
			}
		}
		if a.schemes == 0 {
			a.never = true
		}
		var ok bool
		result, ok = growSlice(result, 1, memory)
		if !ok {
			return nil
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

type conditionFrameState struct {
	light, dark int
}

// evaluateConditionFrame derives a frame from its parent. A cache shared by
// all rules at one width evaluates every immutable frame at most once.
func evaluateConditionFrame(frame *conditionFrame, width float64, fallback bool, cache map[*conditionFrame]conditionFrameState, budget *cpuGuard) (light, dark int) {
	if !budget.check() {
		return mediaUnknown, mediaUnknown
	}
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
func (s *sheet) viewingCases() ([]float64, bool) {
	// No media decision can make an unusable cascade trustworthy. Retain one
	// traversal so text and elements are still extracted and labelled unknown,
	// but do not spend more work constructing activation vectors.
	if s.cascadeIncomplete || s.stopped || !s.prepareMediaGroups() {
		return []float64{1024}, true
	}
	var bounds []float64
	unique := map[float64]bool{}
	seenFrames := map[*conditionFrame]bool{}
	charge := func() bool { return s.checkCPU() }
	for _, group := range s.runtime.mediaGroups {
		if !charge() {
			return []float64{1024}, true
		}
		for frame := group; frame != nil; frame = frame.parent {
			if !s.checkCPU() {
				return []float64{1024}, true
			}
			if seenFrames[frame] {
				break
			}
			if !s.memory.Reserve(mediaFrameSetEntryBytes) {
				return []float64{1024}, true
			}
			seenFrames[frame] = true
			c := frame.condition
			for _, a := range c {
				for _, b := range a.bounds {
					if !unique[b.value] {
						if !s.memory.Reserve(mediaBoundSetEntryBytes) {
							return []float64{1024}, true
						}
						unique[b.value] = true
						var ok bool
						bounds, ok = growSlice(bounds, 1, s.memory)
						if !ok {
							return []float64{1024}, true
						}
						bounds = append(bounds, b.value)
					}
				}
			}
		}
	}
	var candidates []float64
	if len(bounds) == 0 {
		if !s.memory.Reserve(int64(len(s.runtime.mediaGroups)) + int64(len(seenFrames))*mediaFrameSetEntryBytes + mediaFrameStateMapBytes) {
			return []float64{1024}, true
		}
		states := make([]uint8, 0, len(s.runtime.mediaGroups))
		var frameStates map[*conditionFrame]conditionFrameState
		if len(seenFrames) > 0 {
			frameStates = make(map[*conditionFrame]conditionFrameState, len(seenFrames))
		}
		for _, group := range s.runtime.mediaGroups {
			if !charge() {
				return []float64{1024}, true
			}
			light, dark := evaluateConditionFrame(group, 1024, false, frameStates, s.cpu)
			states = append(states, uint8(combinedMediaState(light, dark)))
		}
		s.runtime.mediaCache = map[mediaCacheKey][]uint8{{width: 1024}: states}
		return []float64{1024}, false
	} else {
		if !s.memory.Reserve(int64(len(bounds)*2+2) * int64(unsafe.Sizeof(float64(0)))) {
			return []float64{1024}, true
		}
		sort.Float64s(bounds)
		candidates = make([]float64, 1, len(bounds)*2+2)
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
	// Each activation vector becomes one string key. The shared memory budget
	// accounts for candidates, state vectors, and retained cache entries.
	if !s.memory.Reserve(int64(len(seenFrames))*mediaFrameSetEntryBytes + mediaViewingCaseMapsBytes) {
		return []float64{1024}, true
	}
	seen := map[string]bool{}
	var widths []float64
	s.runtime.mediaCache = make(map[mediaCacheKey][]uint8)
	var frameStates map[*conditionFrame]conditionFrameState
	if len(seenFrames) > 0 {
		frameStates = make(map[*conditionFrame]conditionFrameState, len(seenFrames))
	}
	for _, w := range candidates {
		clear(frameStates)
		if !s.memory.Reserve(int64(len(s.runtime.mediaGroups))*2 + mediaActivationOverheadBytes) {
			return []float64{1024}, true
		}
		states := make([]uint8, 0, len(s.runtime.mediaGroups))
		for _, group := range s.runtime.mediaGroups {
			if !charge() {
				return []float64{1024}, true
			}
			light, dark := evaluateConditionFrame(group, w, false, frameStates, s.cpu)
			states = append(states, uint8(combinedMediaState(light, dark)))
		}
		k := string(states[1:])
		if seen[k] {
			continue
		}
		seen[k] = true
		var ok bool
		widths, ok = growSlice(widths, 1, s.memory)
		if !ok {
			return []float64{1024}, true
		}
		widths = append(widths, w)
		s.runtime.mediaCache[mediaCacheKey{width: w}] = states
	}
	return widths, false
}

// Rules sharing a persistent condition chain always have identical media
// states. Group zero is the unconditional state and is omitted from signatures.
func (s *sheet) prepareMediaGroups() bool {
	if s.runtime.mediaGroups != nil {
		return true
	}
	if !s.memory.Reserve(mediaFrameStateMapBytes) {
		return false
	}
	ids := map[*conditionFrame]int{nil: 0}
	groups := []*conditionFrame(nil)
	var ok bool
	groups, ok = growSlice(groups, 1, s.memory)
	if !ok {
		return false
	}
	groups = append(groups, nil)
	for i := range s.rules {
		if !s.checkCPU() {
			return false
		}
		frame := s.rules[i].conditions
		id, found := ids[frame]
		if !found {
			if !s.memory.Reserve(mediaFrameSetEntryBytes) {
				return false
			}
			id = len(groups)
			ids[frame] = id
			groups, ok = growSlice(groups, 1, s.memory)
			if !ok {
				return false
			}
			groups = append(groups, frame)
		}
		s.rules[i].mediaGroup = id
	}
	s.runtime.mediaGroups = groups
	return true
}
