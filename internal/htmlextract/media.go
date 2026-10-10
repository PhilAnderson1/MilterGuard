package htmlextract

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// A condition is a disjunction of alternatives; nested conditions are ANDed.
// Unknown is deliberately not false, including in partially supported queries.
type widthBound struct {
	min   bool
	value float64
}
type mediaAlternative struct {
	bounds         []widthBound
	unknown, never bool
}
type mediaCondition []mediaAlternative

const (
	mediaNo = iota
	mediaYes
	mediaUnknown
)

var widthFeature = regexp.MustCompile(`^\(\s*(min|max)-(?:device-)?width\s*:\s*([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(px)?\s*\)$`)

func parseMedia(src string) mediaCondition {
	if len(src) > 4096 || strings.Count(src, ",") > 31 {
		return mediaCondition{{unknown: true}}
	}
	var result mediaCondition
	for _, raw := range strings.Split(strings.ToLower(src), ",") {
		a := mediaAlternative{}
		raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "only "))
		// The supported subset has no functions or nested query parentheses.
		parts := regexpAnd.Split(raw, -1)
		if len(parts) > 16 {
			return mediaCondition{{unknown: true}}
		}
		for _, part := range parts {
			part = strings.TrimSpace(part)
			switch part {
			case "screen", "all":
			case "print":
				a.never = true
			case "(prefers-color-scheme:light)", "(prefers-color-scheme: light)":
				// The extractor's agreed canvas is explicitly light mode.
			case "(prefers-color-scheme:dark)", "(prefers-color-scheme: dark)":
				a.never = true
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
		result = append(result, a)
	}
	return result
}

var regexpAnd = regexp.MustCompile(`\s+and\s+`)

func (c mediaCondition) state(width float64) int {
	result := mediaNo
	for _, a := range c {
		ok := !a.never
		for _, b := range a.bounds {
			if b.min && width < b.value || !b.min && width > b.value {
				ok = false
			}
		}
		if !ok {
			continue
		}
		if !a.unknown {
			return mediaYes
		}
		result = mediaUnknown
	}
	return result
}
func (r rule) mediaState(width float64, fallback bool) int {
	result := mediaYes
	for _, c := range r.conditions {
		x := c.state(width)
		if fallback { // Only invariant, unconditional conditions can be certain.
			variable := false
			for _, a := range c {
				variable = variable || len(a.bounds) > 0
			}
			if variable {
				x = mediaUnknown
			}
		}
		if x == mediaNo {
			return mediaNo
		}
		if x == mediaUnknown {
			result = mediaUnknown
		}
	}
	return result
}

// Width-independent property values make activation vectors sufficient. Exact
// endpoints are separate from open intervals, so a one-point rule is covered.
func (s *sheet) viewingCases(cap int) ([]float64, bool) {
	var bounds []float64
	unique := map[float64]bool{}
	for _, r := range s.rules {
		for _, c := range r.conditions {
			for _, a := range c {
				for _, b := range a.bounds {
					if !unique[b.value] {
						unique[b.value] = true
						bounds = append(bounds, b.value)
						if len(bounds) > 512 {
							return []float64{1024}, true
						}
					}
				}
			}
		}
	}
	if len(bounds) == 0 {
		return []float64{1024}, false
	}
	sort.Float64s(bounds)
	candidates := []float64{0}
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
	seen := map[string]bool{}
	var widths []float64
	var planningWork int64
	for _, w := range candidates {
		var key strings.Builder
		for _, r := range s.rules {
			planningWork += int64(1 + len(r.conditions)*32)
			s.planningWork = planningWork
			if planningWork > s.limits.MatchWork/4 {
				return []float64{1024}, true
			}
			key.WriteByte(byte(r.mediaState(w, false)))
		}
		k := key.String()
		if seen[k] {
			continue
		}
		seen[k] = true
		widths = append(widths, w)
		if len(widths) > cap {
			return []float64{1024}, true
		}
	}
	return widths, false
}

func aggregateLabel(bits uint8) string {
	if bits&4 != 0 {
		return "unknown"
	}
	if bits&3 == 3 {
		return "client-dependent"
	}
	if bits&2 != 0 {
		return "concealed"
	}
	return "visible"
}
