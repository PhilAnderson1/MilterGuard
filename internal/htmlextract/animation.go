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

func animationName(kind css.TokenType, raw string) (string, bool) {
	if kind == css.StringToken && len(raw) >= 2 && raw[0] == raw[len(raw)-1] {
		return cssUnescape(raw[1 : len(raw)-1]), true
	}
	if kind != css.IdentToken && kind != css.CustomPropertyNameToken {
		return "", false
	}
	name := cssUnescape(raw)
	switch asciiLower(name) {
	case "none", "initial", "inherit", "unset", "revert", "revert-layer", "default":
		return "", false
	}
	return name, true
}

func (s *sheet) recordKeyframeName(tokens []css.Token) {
	var name string
	found := false
	for _, token := range tokens {
		if token.TokenType == css.WhitespaceToken || token.TokenType == css.CommentToken {
			continue
		}
		if found {
			return // A keyframes prelude contains exactly one name.
		}
		var ok bool
		name, ok = animationName(token.TokenType, string(token.Data))
		if !ok {
			return
		}
		found = true
	}
	if found {
		// Source bytes and this prelude's planning work have already been
		// admitted by parseCSSResult. The registry shares those document bounds.
		if s.keyframeNames == nil {
			s.keyframeNames = make(map[string]struct{})
		}
		s.keyframeNames[name] = struct{}{}
	}
}

func parseAnimationValue(value string, shorthand bool) animationValue {
	tokens, status := lexValue(value)
	if status != valueResolved {
		return animationValue{unresolved: true}
	}
	tokens = significant(tokens)
	if len(tokens) == 0 {
		return animationValue{unresolved: true}
	}
	if len(tokens) == 1 && tokens[0].kind == css.IdentToken {
		switch asciiLower(cssUnescape(tokens[0].raw)) {
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
		name, named, ok := singleAnimationName(tokens[start:end], shorthand)
		if !ok {
			return animationValue{unresolved: true}
		}
		if named {
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

func singleAnimationName(tokens []valueToken, shorthand bool) (name string, named, ok bool) {
	if !shorthand {
		if len(tokens) != 1 {
			return "", false, false
		}
		if tokens[0].kind == css.IdentToken && asciiLower(cssUnescape(tokens[0].raw)) == "none" {
			return "", false, true
		}
		name, ok = animationName(tokens[0].kind, tokens[0].raw)
		return name, ok, ok
	}
	// Shorthand keywords fill their other longhand slots before animation-name.
	// A repeated keyword may then be a case-sensitive keyframe name (ease ease).
	var timing, iteration, direction, fill, play, nameSet bool
	times := 0
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		keyword := asciiLower(cssUnescape(token.raw))
		switch token.kind {
		case css.DimensionToken:
			unit := "s"
			if strings.HasSuffix(keyword, "ms") {
				unit = "ms"
			}
			if !strings.HasSuffix(keyword, unit) || times == 2 {
				return "", false, false
			}
			n, valid := number(strings.TrimSuffix(keyword, unit))
			if !valid || (times == 0 && n < 0) {
				return "", false, false
			}
			times++
			continue
		case css.NumberToken:
			n, valid := number(token.raw)
			if !valid || n < 0 || iteration {
				return "", false, false
			}
			iteration = true
			continue
		case css.FunctionToken:
			if timing {
				return "", false, false
			}
			end, valid := animationTimingFunction(tokens, i)
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
		name, named = animationName(token.kind, token.raw)
		if !named {
			return "", false, false
		}
	}
	return name, named, true
}

// Recognise the established easing functions. Newer or complex unsupported
// syntax remains uncertain rather than silently selecting no animation.
func animationTimingFunction(tokens []valueToken, start int) (int, bool) {
	end := start + 1
	for end < len(tokens) && tokens[end].kind != css.RightParenthesisToken {
		if tokens[end].kind == css.FunctionToken || tokens[end].kind == css.LeftParenthesisToken {
			return 0, false
		}
		end++
	}
	if end == len(tokens) {
		return 0, false
	}
	args := tokens[start+1 : end]
	switch asciiLower(cssUnescape(tokens[start].raw)) {
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
			n, ok := number(token.raw)
			if token.kind != css.NumberToken || !ok || (i%4 == 0 && (n < 0 || n > 1)) {
				return 0, false
			}
		}
	case "steps(":
		if len(args) != 1 && len(args) != 3 {
			return 0, false
		}
		n, ok := number(args[0].raw)
		if args[0].kind != css.NumberToken || !ok || n < 1 || strings.ContainsAny(args[0].raw, ".eE") {
			return 0, false
		}
		if len(args) == 3 {
			if args[1].kind != css.CommaToken || args[2].kind != css.IdentToken {
				return 0, false
			}
			switch asciiLower(cssUnescape(args[2].raw)) {
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

func (s *sheet) potentiallyActiveAnimation(c candidate, context evaluationContext, matches *matchBudget) bool {
	if !c.set || (len(s.keyframeNames) == 0 && !s.unresolvedStylesheet) {
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
		if resolved.status != valueResolved || !context.budget.charge(len(resolved.text)+1) {
			return true
		}
		parsed := parseAnimationValue(resolved.text, c.d.animationShorthand)
		value = &parsed
	}
	if value.unresolved {
		return true
	}
	for _, name := range value.names {
		if !matches.spend(1 + selectorByteWork(len(name))) {
			return true
		}
		if _, found := s.keyframeNames[name]; found || s.unresolvedStylesheet {
			return true
		}
	}
	return false
}
