package htmlextract

import (
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
)

type cssPreflightContext uint8

const (
	cssRuleList cssPreflightContext = iota
	cssDeclarationList
)

type cssPreflightPhase uint8

const (
	cssConstructStart cssPreflightPhase = iota
	cssPrelude
	cssProperty
	cssValue
)

// boundedCSSConstructs tokenizes without retaining tokens and rejects any
// construct that the full parser could otherwise accumulate without bound.
// It deliberately mirrors only CSS structural boundaries; the full parser
// remains authoritative for syntax and recovery.
func boundedCSSConstructs(source string, inline bool, byteLimit, tokenLimit int) bool {
	// Every CSS token consumes at least one source byte. If the whole input is
	// within both limits, no contained construct can exceed either one.
	if len(source) <= byteLimit && len(source) <= tokenLimit {
		return true
	}
	lexer := css.NewLexer(parse.NewInputString(source))
	initialContext := cssRuleList
	if inline {
		initialContext = cssDeclarationList
	}
	contexts := []cssPreflightContext{initialContext}
	phase := cssConstructStart
	componentDepth := 0
	constructBytes, constructTokens := 0, 0
	var atRule string
	customProperty := false

	reset := func() {
		constructBytes = 0
		constructTokens = 0
	}
	withinLimit := func(data []byte) bool {
		constructBytes += len(data)
		constructTokens++
		return constructBytes <= byteLimit && constructTokens <= tokenLimit
	}
	popContext := func() {
		if len(contexts) > 1 {
			contexts = contexts[:len(contexts)-1]
		}
		phase = cssConstructStart
		componentDepth = 0
		atRule = ""
		customProperty = false
		reset()
	}

	for {
		token, data := lexer.Next()
		if token == css.ErrorToken {
			// Malformed CSS remains the full parser's concern. EOF and lexer
			// errors are safe here because the source and the unfinished
			// construct have already been bounded.
			return true
		}
		// The full parser drops comments and collapses whitespace before it
		// appends tokens to a construct. Mirror that here so harmless padding
		// does not consume an accumulation limit.
		if token == css.CommentToken && !(phase == cssValue && customProperty) {
			continue
		}
		if phase == cssConstructStart && (token == css.WhitespaceToken || token == css.SemicolonToken) {
			reset()
			continue
		}
		accounted := data
		if token == css.WhitespaceToken && !(phase == cssValue && customProperty) {
			accounted = []byte{' '}
		}
		if !withinLimit(accounted) {
			return false
		}

		if componentDepth > 0 {
			switch token {
			case css.LeftParenthesisToken, css.LeftBracketToken, css.LeftBraceToken, css.FunctionToken:
				componentDepth++
			case css.RightParenthesisToken, css.RightBracketToken, css.RightBraceToken:
				componentDepth--
			}
			continue
		}

		context := contexts[len(contexts)-1]
		switch phase {
		case cssConstructStart:
			switch token {
			case css.WhitespaceToken, css.CommentToken, css.SemicolonToken:
				reset()
			case css.RightBraceToken:
				popContext()
			case css.AtKeywordToken:
				atRule = asciiLower(string(data))
				phase = cssPrelude
			default:
				if context == cssRuleList {
					phase = cssPrelude
				} else {
					phase = cssProperty
					customProperty = token == css.CustomPropertyNameToken
				}
			}

		case cssPrelude:
			switch token {
			case css.LeftParenthesisToken, css.LeftBracketToken, css.FunctionToken:
				componentDepth = 1
			case css.LeftBraceToken:
				contexts = append(contexts, atRuleContext(atRule))
				phase = cssConstructStart
				atRule = ""
				reset()
			case css.SemicolonToken:
				phase = cssConstructStart
				atRule = ""
				reset()
			case css.RightBraceToken:
				popContext()
			}

		case cssProperty:
			switch token {
			case css.ColonToken:
				phase = cssValue
				reset() // Only the value is retained by the full parser.
			case css.LeftParenthesisToken, css.LeftBracketToken, css.LeftBraceToken, css.FunctionToken:
				componentDepth = 1
			case css.SemicolonToken:
				phase = cssConstructStart
				customProperty = false
				reset()
			case css.RightBraceToken:
				popContext()
			}

		case cssValue:
			switch token {
			case css.LeftParenthesisToken, css.LeftBracketToken, css.LeftBraceToken, css.FunctionToken:
				componentDepth = 1
			case css.SemicolonToken:
				phase = cssConstructStart
				customProperty = false
				reset()
			case css.RightBraceToken:
				popContext()
			}
		}
	}
}

func atRuleContext(name string) cssPreflightContext {
	// tdewolff removes a leading vendor identifier before dispatching an
	// at-rule, so @-vendor-media and @media both contain a rule list. Mirror
	// that structural decision here; otherwise the preflight can mistake all
	// of the nested rules for one oversized declaration construct.
	if strings.HasPrefix(name, "@-") {
		if end := strings.IndexByte(name[2:], '-'); end >= 0 {
			name = "@" + name[end+3:]
		}
	}
	switch name {
	case "@media", "@supports", "@document", "@layer", "@keyframes":
		return cssRuleList
	default:
		return cssDeclarationList
	}
}
