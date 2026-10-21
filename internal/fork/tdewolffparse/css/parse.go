package css

import (
	"bytes"
	"errors"
	"io"
	"strconv"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

// ErrSyntax reports a recoverable CSS syntax error without retaining diagnostics.
var ErrSyntax = errors.New("css: syntax error")

var errInvalidComponent = errors.New("css: invalid component opener")

var wsBytes = []byte(" ")
var colonBytes = []byte(":")
var endBytes = []byte("}")
var emptyBytes = []byte("")

// GrammarType determines the type of grammar.
type GrammarType uint32

// GrammarType values.
const (
	ErrorGrammar GrammarType = iota // extra token when errors occur
	CommentGrammar
	AtRuleGrammar
	BeginAtRuleGrammar
	EndAtRuleGrammar
	QualifiedRuleGrammar
	BeginRulesetGrammar
	EndRulesetGrammar
	DeclarationGrammar
	TokenGrammar
	CustomPropertyGrammar
)

// String returns the string representation of a GrammarType.
func (tt GrammarType) String() string {
	switch tt {
	case ErrorGrammar:
		return "Error"
	case CommentGrammar:
		return "Comment"
	case AtRuleGrammar:
		return "AtRule"
	case BeginAtRuleGrammar:
		return "BeginAtRule"
	case EndAtRuleGrammar:
		return "EndAtRule"
	case QualifiedRuleGrammar:
		return "QualifiedRule"
	case BeginRulesetGrammar:
		return "BeginRuleset"
	case EndRulesetGrammar:
		return "EndRuleset"
	case DeclarationGrammar:
		return "Declaration"
	case TokenGrammar:
		return "Token"
	case CustomPropertyGrammar:
		return "CustomProperty"
	}
	return "Invalid(" + strconv.Itoa(int(tt)) + ")"
}

////////////////////////////////////////////////////////////////

// State is the state function the parser currently is in.
type State func(*Parser) GrammarType

// Token is a single TokenType and its associated data.
type Token struct {
	TokenType
	Data []byte
}

func (t Token) String() string {
	return t.TokenType.String() + "('" + string(t.Data) + "')"
}

// Parser is the state for the parser.
type Parser struct {
	l          *Lexer
	state      []State
	parseError bool

	buf              []Token
	level            int
	componentClosers [maxCSSParserStates / 32]uint64
	guard            *resourceGuard
	resourceErr      error

	data         []byte
	originalData []byte
	tt           TokenType
	keepWS       bool
	prevWS       bool
	prevEnd      bool
	prevComment  bool
	isStylesheet bool
}

// NewParser returns a new CSS parser from an io.Reader. isInline specifies whether this is an inline style attribute.
func NewParser(r *parse.Input, isInline bool) *Parser {
	return newParser(r, isInline, nil)
}

// NewParserWithLimits returns a parser with limits enforced at the operations
// that retain construct tokens, copy custom-property values, and grow stacks.
func NewParserWithLimits(r *parse.Input, isInline bool, limits ResourceLimits) *Parser {
	r.SetProgressCheck(limits.ShouldStop)
	return newParser(r, isInline, newResourceGuard(limits))
}

func newParser(r *parse.Input, isInline bool, guard *resourceGuard) *Parser {
	l := newLexer(r, guard)
	p := resourceguard.New(guard.memory(), Parser{l: l, guard: guard})

	p.state = resourceguard.MakeSlice[State](guard.memory(), 0, 4)

	if isInline {
		p.state = append(p.state, (*Parser).parseDeclarationList)
	} else {
		p.state = append(p.state, (*Parser).parseStylesheet)
		p.isStylesheet = true
	}
	return p
}

// HasParseError returns true if there is a parse error (and not a read error).
func (p *Parser) HasParseError() bool {
	return p.resourceErr == nil && p.parseError
}

// Err returns the error encountered during parsing, this is often io.EOF but also other errors can be returned.
func (p *Parser) Err() error {
	if p.resourceErr != nil {
		return p.resourceErr
	}
	if p.parseError {
		return ErrSyntax
	}
	return p.l.Err()
}

// Next returns the next Grammar. It returns ErrorGrammar when an error was encountered. Err reports ErrSyntax for recoverable syntax errors, or the terminal error.
func (p *Parser) Next() (gt GrammarType, tt TokenType, data []byte) {
	if p.resourceErr != nil {
		return ErrorGrammar, ErrorToken, nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			termination.Rethrow(recovered)
			if _, ok := recovered.(resourceAbort); ok {
				gt, tt, data = ErrorGrammar, ErrorToken, nil
				return
			}
			panic(recovered)
		}
	}()
	p.parseError = false
	p.originalData = nil

	if p.prevEnd {
		p.tt, p.data = RightBraceToken, endBytes
		p.prevEnd = false
	} else {
		p.tt, p.data = p.popToken(true)
	}
	gt = p.state[len(p.state)-1](p)
	return gt, p.tt, p.data
}

// Offset return offset for current Grammar
func (p *Parser) Offset() int {
	return p.l.r.Offset()
}

// Values returns a slice of Tokens for the last Grammar. Only AtRuleGrammar, BeginAtRuleGrammar, BeginRulesetGrammar and Declaration will return the at-rule components, ruleset selector and declaration values respectively.
func (p *Parser) Values() []Token {
	return p.buf
}

// OriginalData returns the source spelling of the name emitted for the last
// declaration. Unlike Next's data result it is not ASCII-lowercased. The
// returned bytes remain valid until the next call to Next.
func (p *Parser) OriginalData() []byte {
	return p.originalData
}

func (p *Parser) popToken(allowComment bool) (TokenType, []byte) {
	p.prevWS = false
	p.prevComment = false
	tt, data := p.rawToken()
	for !p.keepWS && tt == WhitespaceToken || tt == CommentToken {
		if tt == WhitespaceToken {
			p.prevWS = true
		} else {
			p.prevComment = true
			if allowComment && len(p.state) == 1 {
				break
			}
		}
		tt, data = p.rawToken()
	}
	return tt, data
}

func (p *Parser) initBuf() {
	p.buf = p.buf[:0]
}

func (p *Parser) pushBuf(tt TokenType, data []byte) {
	p.guard.step()

	p.buf = append(growParserSlice(p.buf, 1, p), Token{tt, data})
}

func (p *Parser) rawToken() (TokenType, []byte) {
	tt, data := p.l.Next()
	if err := p.l.Err(); err != nil && err != io.EOF {
		p.abort(err)
	}
	return tt, data
}

func (p *Parser) abort(err error) {
	p.resourceErr = err
	panic(resourceAbort{})
}

func (p *Parser) pushState(state State) {
	if len(p.state) >= maxCSSParserStates {
		p.abort(&ResourceLimitError{Resource: "parser nesting", Limit: maxCSSParserStates})
	}
	p.state = append(growParserSlice(p.state, 1, p), state)
}

const maxCSSParserStates = 256

func (p *Parser) openComponentToken(tt TokenType) {
	if p.level >= maxCSSParserStates {
		p.abort(&ResourceLimitError{Resource: "component nesting", Limit: maxCSSParserStates})
	}
	var closer uint64
	switch tt {
	case FunctionToken, LeftParenthesisToken:
		closer = 1
	case LeftBracketToken:
		closer = 2
	case LeftBraceToken:
		closer = 3
	default:
		p.abort(errInvalidComponent)
	}
	word, shift := p.level/32, uint(p.level%32*2)
	p.componentClosers[word] = p.componentClosers[word]&^(uint64(3)<<shift) | closer<<shift
	p.level++
}

func (p *Parser) closeComponent(tt TokenType) {
	if p.level == 0 {
		p.abort(ErrUnsafeDelimiter)
	}
	index := p.level - 1
	word, shift := index/32, uint(index%32*2)
	closer := p.componentClosers[word] >> shift & 3
	var want uint64
	switch tt {
	case RightParenthesisToken:
		want = 1
	case RightBracketToken:
		want = 2
	case RightBraceToken:
		want = 3
	}
	if closer == want {
		p.level--
	}
}

func (p *Parser) rejectUnsafeDelimiter(tt TokenType) {
	if tt == RightParenthesisToken || tt == RightBracketToken {
		p.abort(ErrUnsafeDelimiter)
	}
}

func (p *Parser) appendCustomValue(value, data []byte) []byte {
	p.guard.step()

	return append(growParserSlice(value, len(data), p), data...)
}

func (p *Parser) appendCustomCommentSpace(value, comment []byte) []byte {
	p.guard.step()

	value = growParserSlice(value, len(comment), p)
	nextCheck := 1024
	for i := range comment {
		if i >= nextCheck {
			nextCheck = i + 1024
			p.checkWork()
		}
		value = append(value, ' ')
	}
	return value
}

////////////////////////////////////////////////////////////////

func (p *Parser) parseStylesheet() GrammarType {
	if p.tt == CDOToken || p.tt == CDCToken {
		return TokenGrammar
	} else if p.tt == AtKeywordToken {
		return p.parseAtRule()
	} else if p.tt == CommentToken {
		return CommentGrammar
	} else if p.tt == CustomPropertyNameToken {
		return p.parseCustomProperty()
	} else if p.tt == ErrorToken {
		return ErrorGrammar
	}
	return p.parseQualifiedRule()
}

func (p *Parser) parseDeclarationList() GrammarType {
	if p.tt == CommentToken {
		p.tt, p.data = p.popToken(false)
	}
	for p.tt == SemicolonToken {
		p.tt, p.data = p.popToken(false)
	}

	// IE hack: *color:red;
	if p.tt == DelimToken && p.data[0] == '*' {
		tt, data := p.popToken(false)
		p.tt = tt
		p.data = append(growParserSlice(p.data, len(data), p), data...)
	}

	if p.tt == ErrorToken {
		return ErrorGrammar
	} else if p.tt == AtKeywordToken {
		return p.parseAtRule()
	} else if p.tt == IdentToken || p.tt == DelimToken {
		return p.parseDeclaration()
	} else if p.tt == CustomPropertyNameToken {
		return p.parseCustomProperty()
	}

	// parse error
	p.initBuf()
	p.parseError = true

	if p.tt == RightBraceToken {
		// right brace token will occur when we've had a decl error that ended in a right brace token
		// as these are not handled by decl error, we handle it here explicitly. Normally its used to end eg. the qual rule.
		p.pushBuf(p.tt, p.data)
		return ErrorGrammar
	}
	return p.parseDeclarationError(p.tt, p.data)
}

////////////////////////////////////////////////////////////////

func (p *Parser) parseAtRule() GrammarType {
	p.initBuf()

	// Bound the at-keyword before Copy allocates storage for it. The keyword
	// is part of the at-rule construct even though it is exposed separately
	// from Values.
	p.guard.step()

	p.data = p.lowerCopy(p.data)
	atRuleName := p.data
	if len(atRuleName) > 1 && atRuleName[1] == '-' {

		if i := bytes.IndexByte(atRuleName[2:], '-'); i != -1 {
			atRuleName = atRuleName[i+2:] // skip vendor specific prefix
		}

	}
	atRule := ToHash(atRuleName[1:])

	first := true
	skipWS := false
	for {
		tt, data := p.popToken(false)
		if tt == LeftBraceToken && p.level == 0 {
			if atRule == Font_Face || atRule == Page {
				p.pushState((*Parser).parseAtRuleDeclarationList)
			} else if atRule == Document || atRule == Keyframes || atRule == Layer || atRule == Media || atRule == Supports {
				p.pushState((*Parser).parseAtRuleRuleList)
			} else {
				p.pushState((*Parser).parseAtRuleUnknown)
			}

			return BeginAtRuleGrammar
		} else if (tt == SemicolonToken || tt == RightBraceToken) && p.level == 0 || tt == ErrorToken {
			p.prevEnd = tt == RightBraceToken
			return AtRuleGrammar
		} else if tt == LeftParenthesisToken || tt == LeftBraceToken || tt == LeftBracketToken || tt == FunctionToken {
			p.openComponentToken(tt)
		} else if tt == RightParenthesisToken || tt == RightBraceToken || tt == RightBracketToken {
			if p.level == 0 {
				p.rejectUnsafeDelimiter(tt)
				// TODO: buggy
				p.pushBuf(tt, data)
				if 1 < len(p.state) {
					p.state = p.state[:len(p.state)-1]
				}
				p.parseError = true
				return ErrorGrammar
			}
			p.closeComponent(tt)
		}

		if first {
			if tt == LeftParenthesisToken || tt == LeftBracketToken {
				p.prevWS = false
			}
			first = false
		}
		if len(data) == 1 && (data[0] == ',' || data[0] == ':') {
			skipWS = true
		} else if (p.prevWS || p.prevComment) && !skipWS && tt != RightParenthesisToken {
			p.pushBuf(WhitespaceToken, wsBytes)
		} else {
			skipWS = false
		}

		if tt == LeftParenthesisToken {
			skipWS = true
		}
		p.pushBuf(tt, data)
	}
}

func (p *Parser) parseAtRuleRuleList() GrammarType {
	if p.tt == RightBraceToken || p.tt == ErrorToken {
		p.state = p.state[:len(p.state)-1]
		return EndAtRuleGrammar
	} else if p.tt == AtKeywordToken {
		return p.parseAtRule()
	} else {
		return p.parseQualifiedRule()
	}
}

func (p *Parser) parseAtRuleDeclarationList() GrammarType {
	for p.tt == SemicolonToken {
		p.tt, p.data = p.popToken(false)
	}
	if p.tt == RightBraceToken || p.tt == ErrorToken {
		p.state = p.state[:len(p.state)-1]
		return EndAtRuleGrammar
	}
	return p.parseDeclarationList()
}

func (p *Parser) parseAtRuleUnknown() GrammarType {
	p.keepWS = true
	if p.tt == RightBraceToken && p.level == 0 || p.tt == ErrorToken {
		p.state = p.state[:len(p.state)-1]
		p.keepWS = false
		return EndAtRuleGrammar
	}
	if p.tt == LeftParenthesisToken || p.tt == LeftBraceToken || p.tt == LeftBracketToken || p.tt == FunctionToken {
		p.openComponentToken(p.tt)
	} else if p.tt == RightParenthesisToken || p.tt == RightBraceToken || p.tt == RightBracketToken {
		p.closeComponent(p.tt)
	}
	return TokenGrammar
}

func (p *Parser) parseQualifiedRule() GrammarType {
	p.initBuf()
	first := true
	inAttrSel := false
	skipWS := true
	var tt TokenType
	var data []byte
	for {
		if first {
			tt, data = p.tt, p.data
			p.tt = WhitespaceToken
			p.data = emptyBytes
			first = false
		} else {
			tt, data = p.popToken(false)
		}
		if tt == LeftBraceToken && p.level == 0 {
			p.pushState((*Parser).parseQualifiedRuleDeclarationList)
			return BeginRulesetGrammar
		} else if tt == ErrorToken {
			p.parseError = true
			return ErrorGrammar
		} else if tt == LeftParenthesisToken || tt == LeftBraceToken || tt == LeftBracketToken || tt == FunctionToken {
			p.openComponentToken(tt)
		} else if tt == RightParenthesisToken || tt == RightBraceToken || tt == RightBracketToken {
			if p.level == 0 {
				p.rejectUnsafeDelimiter(tt)
				// TODO: buggy
				p.pushBuf(tt, data)
				if 1 < len(p.state) {
					p.state = p.state[:len(p.state)-1]
				}
				p.parseError = true
				return ErrorGrammar
			}
			p.closeComponent(tt)
		}
		if len(data) == 1 && (data[0] == ',' || data[0] == '>' || data[0] == '+' || data[0] == '~') {
			skipWS = true
		} else if (p.prevWS || p.prevComment) && !skipWS && !inAttrSel {
			p.pushBuf(WhitespaceToken, wsBytes)
		} else {
			skipWS = false
		}
		if tt == LeftBracketToken {
			inAttrSel = true
		} else if tt == RightBracketToken {
			inAttrSel = false
		}
		p.pushBuf(tt, data)
	}
}

func (p *Parser) parseQualifiedRuleDeclarationList() GrammarType {
	for p.tt == SemicolonToken {
		p.tt, p.data = p.popToken(false)
	}
	if p.tt == RightBraceToken || p.tt == ErrorToken {
		p.state = p.state[:len(p.state)-1]
		return EndRulesetGrammar
	}
	return p.parseDeclarationList()
}

func (p *Parser) parseDeclaration() GrammarType {
	valueStarted := false
	p.initBuf()
	p.pushBuf(p.tt, p.data)
	for {
		tt, data := p.popToken(false)
		if (tt == SemicolonToken || tt == RightBraceToken) && p.level == 0 || tt == ErrorToken {
			// regular declaration
			i := 1
			nextCheck := 256
			for i < len(p.buf) && p.buf[i].TokenType == WhitespaceToken {
				if i >= nextCheck {
					nextCheck = i + 256
					p.checkWork()
				}
				i++
			}
			if len(p.buf) == i || p.buf[i].TokenType != ColonToken {
				p.parseError = true
				return p.parseDeclarationError(tt, data)
			}

			// remove superfluous whitespace
			// Keep the parser buffer anchored at the start of its backing array.
			// Slicing away the property and colon here makes each declaration
			// progressively lose capacity and forces repeated allocations in a
			// stylesheet with many declarations.
			valueTokens := copy(p.buf, p.buf[i+1:])
			p.buf = p.buf[:valueTokens]
			nextTrimCheck := len(p.buf) - 256
			for 0 < len(p.buf) && p.buf[0].TokenType == WhitespaceToken {
				if len(p.buf) <= nextTrimCheck {
					nextTrimCheck = len(p.buf) - 256
					p.checkWork()
				}
				p.buf = p.buf[1:]
			}
			var j int
			nextCheck = 256
			for i := 0; i < len(p.buf); {
				if i >= nextCheck {
					nextCheck = i + 256
					p.checkWork()
				}
				if p.buf[i].TokenType == WhitespaceToken {
					// remove whitespace preceded or followed by any of ,/:!=
					if 0 < j {

						if data := p.buf[j-1].Data; len(data) == 1 && (data[0] == ',' || data[0] == '/' || data[0] == ':' || data[0] == '!' || data[0] == '=') {
							i++
							continue
						}

					}
					if i+1 < len(p.buf) {

						if data := p.buf[i+1].Data; len(data) == 1 && (data[0] == ',' || data[0] == '/' || data[0] == ':' || data[0] == '!' || data[0] == '=') {
							i++
							continue
						}

						if j < i {
							p.buf[j] = p.buf[i]
						}
						j++
						i++
					}
				}
				if j < i {
					p.buf[j] = p.buf[i]
				}
				j++
				i++
			}
			p.buf = p.buf[:j]
			p.originalData = p.data
			p.data = p.lowerCopy(p.data)
			p.prevEnd = tt == RightBraceToken
			return DeclarationGrammar
		} else if tt == LeftBraceToken && p.level == 0 && p.isStylesheet {
			// nested ruleset
			p.tt = WhitespaceToken
			p.data = emptyBytes
			p.pushState((*Parser).parseQualifiedRuleDeclarationList)
			return BeginRulesetGrammar
		} else if tt == LeftParenthesisToken || tt == LeftBraceToken || tt == LeftBracketToken || tt == FunctionToken {
			p.openComponentToken(tt)
		} else if tt == RightParenthesisToken || tt == RightBraceToken || tt == RightBracketToken {
			if p.level == 0 {
				p.parseError = true
				return p.parseDeclarationError(tt, data)
			}
			p.closeComponent(tt)
		}

		if (p.prevWS || p.prevComment) && p.buf[len(p.buf)-1].TokenType != WhitespaceToken {
			p.pushBuf(WhitespaceToken, wsBytes)
		}
		p.pushBuf(tt, data)
		if !valueStarted && tt == ColonToken && p.level == 0 {
			// The property name is no longer retained as part of the value work.
			valueStarted = true
		}
	}
}

func (p *Parser) parseDeclarationError(tt TokenType, data []byte) GrammarType {
	// we're on the offending (tt,data), keep popping tokens till we reach ;, }, or EOF
	p.tt, p.data = tt, data
	for {
		if (tt == SemicolonToken || tt == RightBraceToken) && p.level == 0 || tt == ErrorToken {
			p.prevEnd = tt == RightBraceToken
			if tt == SemicolonToken {
				p.pushBuf(tt, data)
			}
			return ErrorGrammar
		} else if tt == LeftParenthesisToken || tt == LeftBraceToken || tt == LeftBracketToken || tt == FunctionToken {
			p.openComponentToken(tt)
		} else if tt == RightParenthesisToken || tt == RightBraceToken || tt == RightBracketToken {
			p.closeComponent(tt)
		}

		if p.prevWS || p.prevComment {
			p.pushBuf(WhitespaceToken, wsBytes)
		}
		p.pushBuf(tt, data)

		tt, data = p.popToken(false)
	}
}

func (p *Parser) parseCustomProperty() GrammarType {
	p.originalData = p.data
	p.initBuf()

	// The property name borrows input storage. The caller owns any retained
	// copy; this checkpoint is only for cooperative cancellation.
	p.guard.step()

	if tt, data := p.popToken(false); tt != ColonToken {
		p.l.r.Move(-len(data))
		p.parseError = true
		p.l.r.Move(len(data))
		return ErrorGrammar
	}

	val := []byte{}
	for {
		tt, data := p.rawToken()
		if (tt == SemicolonToken || tt == RightBraceToken) && p.level == 0 || tt == ErrorToken {
			p.prevEnd = tt == RightBraceToken
			p.buf = append(growParserSlice(p.buf, 1, p), Token{CustomPropertyValueToken, val})
			return CustomPropertyGrammar
		} else if tt == LeftParenthesisToken || tt == LeftBraceToken || tt == LeftBracketToken || tt == FunctionToken {
			p.openComponentToken(tt)
		} else if tt == RightParenthesisToken || tt == RightBraceToken || tt == RightBracketToken {
			if p.level == 0 {
				p.rejectUnsafeDelimiter(tt)
				// TODO: buggy
				p.pushBuf(tt, data)
				p.parseError = true
				return ErrorGrammar
			}
			p.closeComponent(tt)
		}

		if tt == CommentToken {
			// CSS comments separate adjacent tokens. Preserve their source width
			// so construct-byte accounting remains exact while exposing ordinary
			// whitespace to callers that re-tokenize custom-property values.
			val = p.appendCustomCommentSpace(val, data)
		} else {
			val = p.appendCustomValue(val, data)
		}
	}
}
