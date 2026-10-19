package htmlextract

import (
	"strings"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
)

// animationValue is immutable declaration preparation. Names retain CSS case;
// unresolved means the declaration cannot safely establish inactivity. No
// animation timeline or keyframe property values are simulated.
type animationValue struct {
	names      []string
	unresolved bool
}

func animationName(kind css.TokenType, raw string, budget *cpuGuard) (string, bool) {
	if kind == css.StringToken && len(raw) >= 2 && raw[0] == raw[len(raw)-1] {
		return cssUnescapeWithBudget(raw[1:len(raw)-1], budget), true
	}
	if kind != css.IdentToken && kind != css.CustomPropertyNameToken {
		return "", false
	}
	name := cssUnescapeWithBudget(raw, budget)
	switch asciiLowerWithBudget(name, budget) {
	case "none", "initial", "inherit", "unset", "revert", "revert-layer", "default":
		return "", false
	}
	return name, true
}

func (s *sheet) recordKeyframeName(tokens []css.Token) {
	var name string
	found := false
	for _, token := range tokens {
		if !s.checkCPU() {
			return
		}
		if token.TokenType == css.WhitespaceToken || token.TokenType == css.CommentToken {
			continue
		}
		if found {
			return // A keyframes prelude contains exactly one name.
		}
		var ok bool
		name, ok = animationName(token.TokenType, ownedString(token.Data, s.cpu), s.cpu)
		if !ok {
			return
		}
		found = true
	}
	if found {
		s.keyframeNames.Set(s.memory, name, struct{}{})
	}
}

func parseAnimationValue(value string, shorthand bool, budget *cpuGuard) animationValue {
	tokens, status := lexValue(value, budget)
	if status != valueResolved {
		return animationValue{unresolved: true}
	}
	tokens = significant(tokens, budget)
	if len(tokens) == 0 {
		return animationValue{unresolved: true}
	}
	if len(tokens) == 1 && tokens[0].kind == css.IdentToken {
		switch asciiLowerWithBudget(cssUnescapeWithBudget(tokens[0].raw, budget), budget) {
		case "initial", "unset":
			return animationValue{}
		case "inherit", "revert", "revert-layer":
			return animationValue{unresolved: true}
		}
	}
	var result animationValue
	for start := 0; start < len(tokens); {
		end := start
		depth := 0
		for end < len(tokens) {
			if !budget.check() {
				return animationValue{unresolved: true}
			}
			token := tokens[end]
			if token.kind == css.CommaToken && depth == 0 {
				break
			}
			if token.kind == css.FunctionToken || token.kind == css.LeftParenthesisToken {
				depth++
			} else if token.kind == css.RightParenthesisToken {
				depth--
				if depth < 0 {
					return animationValue{unresolved: true}
				}
			}
			end++
		}
		if depth != 0 || start == end {
			return animationValue{unresolved: true}
		}
		name, named, ok := singleAnimationName(tokens[start:end], shorthand, budget)
		if !ok {
			return animationValue{unresolved: true}
		}
		if named {
			var admitted bool
			result.names, admitted = growSlice(result.names, 1, budget.allocationMemory(), budget.allocationStop)
			if !admitted {
				return animationValue{unresolved: true}
			}
			result.names = append(result.names, name)
		}
		if end == len(tokens) {
			return result
		}
		start = end + 1
		if start == len(tokens) {
			return animationValue{unresolved: true}
		}
	}
	return result
}

func singleAnimationName(tokens []valueToken, shorthand bool, budget *cpuGuard) (name string, named, ok bool) {
	if !shorthand {
		if len(tokens) != 1 {
			return "", false, false
		}
		if tokens[0].kind == css.IdentToken && asciiLowerWithBudget(cssUnescapeWithBudget(tokens[0].raw, budget), budget) == "none" {
			return "", false, true
		}
		name, ok = animationName(tokens[0].kind, tokens[0].raw, budget)
		return name, ok, ok
	}
	// Shorthand keywords fill their other longhand slots before animation-name.
	// A repeated keyword may then be a case-sensitive keyframe name (ease ease).
	var timing, iteration, direction, fill, play, nameSet bool
	times := 0
	for i := 0; i < len(tokens); i++ {
		if !budget.check() {
			return "", false, false
		}
		token := tokens[i]
		keyword := asciiLowerWithBudget(cssUnescapeWithBudget(token.raw, budget), budget)
		switch token.kind {
		case css.DimensionToken:
			unit := "s"
			if strings.HasSuffix(keyword, "ms") {
				unit = "ms"
			}
			if !strings.HasSuffix(keyword, unit) || times == 2 {
				return "", false, false
			}
			n, valid := numberWithBudget(strings.TrimSuffix(keyword, unit), budget)
			if !valid || (times == 0 && n < 0) {
				return "", false, false
			}
			times++
			continue
		case css.NumberToken:
			n, valid := numberWithBudget(token.raw, budget)
			if !valid || n < 0 || iteration {
				return "", false, false
			}
			iteration = true
			continue
		case css.FunctionToken:
			if timing {
				return "", false, false
			}
			end, valid := animationTimingFunction(tokens, i, budget)
			if !valid {
				return "", false, false
			}
			i, timing = end, true
			continue
		case css.IdentToken:
			var slot *bool
			switch keyword {
			case "ease", "linear", "ease-in", "ease-out", "ease-in-out", "step-start", "step-end":
				slot = &timing
			case "infinite":
				slot = &iteration
			case "normal", "reverse", "alternate", "alternate-reverse":
				slot = &direction
			case "none", "forwards", "backwards", "both":
				slot = &fill
			case "running", "paused":
				slot = &play
			}
			if slot != nil && !*slot {
				*slot = true
				continue
			}
		}
		if nameSet {
			return "", false, false
		}
		nameSet = true
		if token.kind == css.IdentToken && keyword == "none" {
			continue
		}
		name, named = animationName(token.kind, token.raw, budget)
		if !named {
			return "", false, false
		}
	}
	return name, named, true
}

// Recognise the established easing functions. Newer or complex unsupported
// syntax remains uncertain rather than silently selecting no animation.
func animationTimingFunction(tokens []valueToken, start int, budget *cpuGuard) (int, bool) {
	end := start + 1
	for end < len(tokens) && tokens[end].kind != css.RightParenthesisToken {
		if !budget.check() {
			return 0, false
		}
		if tokens[end].kind == css.FunctionToken || tokens[end].kind == css.LeftParenthesisToken {
			return 0, false
		}
		end++
	}
	if end == len(tokens) {
		return 0, false
	}
	args := tokens[start+1 : end]
	switch asciiLowerWithBudget(cssUnescapeWithBudget(tokens[start].raw, budget), budget) {
	case "cubic-bezier(":
		if len(args) != 7 {
			return 0, false
		}
		for i, token := range args {
			if i%2 == 1 {
				if token.kind != css.CommaToken {
					return 0, false
				}
				continue
			}
			n, ok := numberWithBudget(token.raw, budget)
			if token.kind != css.NumberToken || !ok || (i%4 == 0 && (n < 0 || n > 1)) {
				return 0, false
			}
		}
	case "steps(":
		if len(args) != 1 && len(args) != 3 {
			return 0, false
		}
		n, ok := numberWithBudget(args[0].raw, budget)
		if args[0].kind != css.NumberToken || !ok || n < 1 || strings.ContainsAny(args[0].raw, ".eE") {
			return 0, false
		}
		if len(args) == 3 {
			if args[1].kind != css.CommaToken || args[2].kind != css.IdentToken {
				return 0, false
			}
			switch asciiLowerWithBudget(cssUnescapeWithBudget(args[2].raw, budget), budget) {
			case "jump-start", "jump-end", "jump-both", "start", "end":
			case "jump-none":
				if n < 2 {
					return 0, false
				}
			default:
				return 0, false
			}
		}
	default:
		return 0, false
	}
	return end, true
}

func (s *sheet) potentiallyActiveAnimation(c candidate, context evaluationContext, work *cpuGuard) bool {
	if !c.set || (s.keyframeNames.Len() == 0 && !s.unresolvedStylesheet) {
		return false
	}
	if c.uncertainOrigin || c.d.unsupported {
		return true
	}
	value := c.d.animation
	if value == nil {
		resolved := substitute(c.d, context.vars, context.budget)
		if resolved.status == valueInvalid {
			return false
		}
		if resolved.status != valueResolved || !context.budget.check() {
			return true
		}
		parsed := parseAnimationValue(resolved.text, c.d.animationShorthand, context.budget)
		value = &parsed
	}
	if value.unresolved {
		return true
	}
	for _, name := range value.names {
		if !work.check() {
			return true
		}
		if _, found := s.keyframeNames.View()[name]; found || s.unresolvedStylesheet {
			return true
		}
	}
	return false
}
