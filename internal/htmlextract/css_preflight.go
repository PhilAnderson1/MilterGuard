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

type cssPreflightOutcome uint8

const (
	cssPreflightAccepted cssPreflightOutcome = iota
	cssPreflightLimitExceeded
	cssPreflightUnsafeDelimiter
)

// boundedCSSConstructs retains the compact boolean interface used by limit
// tests. Production callers use inspectCSSConstructs so malformed delimiters
// can be distinguished from ordinary size exhaustion.
func boundedCSSConstructs(source string, inline bool, byteLimit, tokenLimit int) bool {
	return inspectCSSConstructs(source, inline, byteLimit, tokenLimit) == cssPreflightAccepted
}

// inspectCSSConstructs tokenizes without retaining tokens and rejects any
// construct that the full parser could otherwise accumulate without bound. It
// also rejects unmatched ')' and ']' at construct level: tdewolff can otherwise pop
// parser state without reporting the corresponding at-rule boundary, causing
// our condition stack to diverge from its stream.
func inspectCSSConstructs(source string, inline bool, byteLimit, tokenLimit int) cssPreflightOutcome {
	// Every CSS token consumes at least one source byte. If the whole input is
	// within both limits, no contained construct can exceed either one.
	if len(source) <= byteLimit && len(source) <= tokenLimit {
		// Small inputs still require delimiter validation; malformed closers are
		// a parser-state issue rather than an accumulation issue.
	}
	lexer := css.NewLexer(parse.NewInputString(source))
	initialContext := cssRuleList
	if inline {
		initialContext = cssDeclarationList
	}
	contexts := []cssPreflightContext{initialContext}
	phase := cssConstructStart
	var componentClosers []css.TokenType
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
		componentClosers = componentClosers[:0]
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
			return cssPreflightAccepted
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
			return cssPreflightLimitExceeded
		}

		if len(componentClosers) > 0 {
			switch token {
			case css.LeftParenthesisToken, css.FunctionToken:
				componentClosers = append(componentClosers, css.RightParenthesisToken)
			case css.LeftBracketToken:
				componentClosers = append(componentClosers, css.RightBracketToken)
			case css.LeftBraceToken:
				componentClosers = append(componentClosers, css.RightBraceToken)
			case css.RightParenthesisToken, css.RightBracketToken, css.RightBraceToken:
				if componentClosers[len(componentClosers)-1] == token {
					componentClosers = componentClosers[:len(componentClosers)-1]
				}
				// A mismatched closer is an ordinary component-value token under
				// CSS recovery rules. It does not close the currently open block;
				// this is important for valid unused var() fallbacks such as [x)].
			}
			continue
		}
		if token == css.RightParenthesisToken || token == css.RightBracketToken {
			return cssPreflightUnsafeDelimiter
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
				// The first token belongs to the newly selected phase too. In
				// particular, an attribute selector commonly begins a rule with
				// '[', so retain its closer before reading the next token.
				switch token {
				case css.LeftParenthesisToken, css.FunctionToken:
					componentClosers = append(componentClosers, css.RightParenthesisToken)
				case css.LeftBracketToken:
					componentClosers = append(componentClosers, css.RightBracketToken)
				}
			}

		case cssPrelude:
			switch token {
			case css.LeftParenthesisToken, css.FunctionToken:
				componentClosers = append(componentClosers, css.RightParenthesisToken)
			case css.LeftBracketToken:
				componentClosers = append(componentClosers, css.RightBracketToken)
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
			case css.LeftParenthesisToken, css.FunctionToken:
				componentClosers = append(componentClosers, css.RightParenthesisToken)
			case css.LeftBracketToken:
				componentClosers = append(componentClosers, css.RightBracketToken)
			case css.LeftBraceToken:
				componentClosers = append(componentClosers, css.RightBraceToken)
			case css.SemicolonToken:
				phase = cssConstructStart
				customProperty = false
				reset()
			case css.RightBraceToken:
				popContext()
			}

		case cssValue:
			switch token {
			case css.LeftParenthesisToken, css.FunctionToken:
				componentClosers = append(componentClosers, css.RightParenthesisToken)
			case css.LeftBracketToken:
				componentClosers = append(componentClosers, css.RightBracketToken)
			case css.LeftBraceToken:
				componentClosers = append(componentClosers, css.RightBraceToken)
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
