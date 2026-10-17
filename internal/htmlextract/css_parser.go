package htmlextract

import (
	"errors"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse"
	"github.com/PhilAnderson1/MilterGuard/internal/fork/tdewolffparse/css"
)

// cssParseSession owns state which is meaningful only while consuming one
// stylesheet or style attribute. Retained rules and cumulative limits remain
// on sheet.
type cssParseSession struct {
	parser     *css.Parser
	inline     bool
	finished   bool
	incomplete bool
	out        []declaration

	conditions       *conditionFrame
	atRules          []atRuleFrame
	rulesetDepth     int
	defaultNamespace bool
	current          int
	importsAllowed   bool
}

type atRuleFrame struct {
	enclosingRule int
	nested        bool
	rulesetDepth  int
}

func newCSSParseSession(s *sheet, text string, mode cssParseMode) cssParseSession {
	inline := mode == inlineCSS
	session := cssParseSession{
		inline:         inline,
		current:        -1,
		importsAllowed: !inline,
	}
	if !inline {
		s.invalidateMediaCache()
	}
	if !s.admitCSS(text) {
		session.finished = true
		return session
	}
	session.parser = css.NewParserWithLimits(parse.NewInputString(text), inline, css.ResourceLimits{
		ShouldStop: s.shouldStop,
		Memory:     s.memory,
	})
	return session
}

func (p *cssParseSession) result() cssParseResult {
	return cssParseResult{declarations: p.out, incomplete: p.incomplete}
}

func (p *cssParseSession) run(s *sheet) cssParseResult {
	if p.finished {
		return p.result()
	}
	for {
		if s.cascadeIncomplete || s.stopped {
			return p.result()
		}
		grammar, tokenType, data := p.parser.Next()
		values := p.parser.Values()
		var stop bool
		switch grammar {
		case css.ErrorGrammar:
			stop = p.handleError(s, tokenType, values)
		case css.BeginAtRuleGrammar:
			stop = p.beginAtRule(s, string(data), values)
		case css.EndAtRuleGrammar:
			p.endAtRule()
		case css.AtRuleGrammar:
			stop = p.atRule(s, string(data), values)
		case css.BeginRulesetGrammar:
			stop = p.beginRuleset(s, values)
		case css.EndRulesetGrammar:
			p.endRuleset()
		case css.DeclarationGrammar, css.CustomPropertyGrammar:
			stop = p.declaration(s, grammar, string(data), values)
		case css.QualifiedRuleGrammar, css.TokenGrammar:
		}
		if stop {
			return p.result()
		}
	}
}

func (p *cssParseSession) handleError(s *sheet, tokenType css.TokenType, values []css.Token) bool {
	if !p.parser.HasParseError() {
		err := p.parser.Err()
		if errors.Is(err, css.ErrResourceStopped) {
			s.stopped = true
			return true
		}
		var limitErr *css.ResourceLimitError
		if errors.As(err, &limitErr) || errors.Is(err, css.ErrUnsafeDelimiter) {
			if p.inline {
				p.incomplete = true
				return true
			}
			s.abandonCascade()
		}
		return true
	}
	insideNestedGroup := len(p.atRules) > 0 && p.atRules[len(p.atRules)-1].nested
	if !p.inline && p.rulesetDepth > 0 && (hasTopLevelCSSBlock(values) || (p.current < 0 && insideNestedGroup)) {
		s.noteUnsupportedNesting()
	}
	// Recovery inside an inline at-rule can consume its closing brace without
	// emitting EndAtRuleGrammar, making the following declaration scope unsafe.
	if p.inline && p.conditions != nil {
		p.incomplete = true
		return true
	}
	// A stray right brace can silently pop the parser's enclosing at-rule while
	// leaving our retained condition frame stale.
	if !p.inline && p.conditions != nil && hasCSSToken(values, css.RightBraceToken) {
		p.incomplete = true
		return true
	}
	// An unmatched ')' or ']' can leave the upstream recovery nesting level
	// negative and consume later declarations.
	if tokenType == css.RightParenthesisToken || tokenType == css.RightBracketToken {
		p.incomplete = true
		return true
	}
	return false
}

func (p *cssParseSession) beginAtRule(s *sheet, name string, values []css.Token) bool {
	p.importsAllowed = false
	if !p.inline && opaqueRuleBearingAtRule(name) {
		s.unresolvedStylesheet = true
	}
	// Descriptor blocks suspend an enclosing qualified rule. The matching end
	// event restores it.
	enclosingRule := p.current
	p.current = -1
	if !s.checkCPU() {
		return true
	}
	var condition mediaCondition
	switch asciiLower(name) {
	case "@media":
		condition = s.parseMediaCondition(tokenString(values))
	case "@font-face":
		condition = mediaCondition{{schemes: colourSchemeBoth, never: true}}
	case "@keyframes", "@-webkit-keyframes":
		if !p.inline {
			s.recordKeyframeName(values)
		}
		condition = mediaCondition{{schemes: colourSchemeBoth, never: true}}
	default:
		condition = mediaCondition{{schemes: colourSchemeBoth, unknown: true}}
	}
	p.conditions = newConditionFrame(condition, p.conditions, s.memory)
	if p.conditions == nil {
		s.abandonCascade()
		return true
	}
	parentNested := len(p.atRules) > 0 && p.atRules[len(p.atRules)-1].nested
	var ok bool
	p.atRules, ok = growSlice(p.atRules, 1, s.memory)
	if !ok {
		s.abandonCascade()
		return true
	}
	p.atRules = append(p.atRules, atRuleFrame{enclosingRule: enclosingRule, nested: cssNestingGroup(name) && (enclosingRule >= 0 || parentNested), rulesetDepth: p.rulesetDepth})
	return false
}

func (p *cssParseSession) endAtRule() {
	p.current = -1
	if p.conditions == nil {
		return
	}
	p.conditions = p.conditions.parent
	p.current = p.atRules[len(p.atRules)-1].enclosingRule
	p.atRules = p.atRules[:len(p.atRules)-1]
}

func (p *cssParseSession) atRule(s *sheet, name string, values []css.Token) bool {
	if !s.checkCPU() {
		return true
	}
	name = asciiLower(name)
	if name == "@import" {
		if p.importsAllowed && p.conditions == nil {
			s.parseImport(values)
		}
		return false
	}
	if name != "@charset" && name != "@layer" {
		p.importsAllowed = false
	}
	if !p.inline && p.conditions == nil && name == "@namespace" && defaultNamespaceRule(values) {
		p.defaultNamespace = true
	}
	return false
}

func (p *cssParseSession) beginRuleset(s *sheet, values []css.Token) bool {
	p.importsAllowed = false
	nestedQualifiedRule := p.rulesetDepth > 0 &&
		(len(p.atRules) == 0 || p.rulesetDepth > p.atRules[len(p.atRules)-1].rulesetDepth)
	if !p.inline && (nestedQualifiedRule || len(p.atRules) > 0 && p.atRules[len(p.atRules)-1].nested) {
		s.noteUnsupportedNesting()
	}
	p.rulesetDepth++
	p.current = -1
	if p.inline {
		return false
	}
	selector := tokenString(values)
	if !s.checkCPU() {
		return true
	}
	plans, branches, exceeded := planSelectorList(selector, &s.planCount, s.memory, maxSelectorBranches-s.selectorBranches)
	s.selectorBranches += branches
	if exceeded {
		s.abandonCascade()
		return true
	}
	if len(plans) == 0 {
		return false
	}
	if p.defaultNamespace {
		for i := range plans {
			plans[i].scopePrefix = ""
			plans[i].key = selectorKey{}
			plans[i].makeUncertain(s.memory)
		}
	}
	if !s.memory.Reserve(int64(len(plans)) * int64(unsafe.Sizeof(selectorPlan{}))) {
		s.abandonCascade()
		return true
	}
	var ok bool
	s.rules, ok = growSlice(s.rules, 1, s.memory)
	if !ok {
		s.abandonCascade()
		return true
	}
	s.rules = append(s.rules, rule{plans: plans, conditions: p.conditions})
	p.current = len(s.rules) - 1
	return false
}

func (p *cssParseSession) endRuleset() {
	p.current = -1
	if p.rulesetDepth > 0 {
		p.rulesetDepth--
	}
}

func (p *cssParseSession) declaration(s *sheet, grammar css.GrammarType, property string, values []css.Token) bool {
	if !s.checkCPU() {
		return true
	}
	if original := p.parser.OriginalData(); len(original) != 0 {
		property = string(original)
	}
	property = normalizeDeclarationProperty(property)
	insideNestedGroup := len(p.atRules) > 0 && p.atRules[len(p.atRules)-1].nested
	if !p.inline && p.rulesetDepth > 0 && grammar != css.CustomPropertyGrammar &&
		(hasTopLevelCSSBlock(values) || (p.current < 0 && insideNestedGroup)) {
		s.noteUnsupportedNesting()
		return false
	}
	applicable := p.inline && p.conditions == nil || !p.inline && p.current >= 0
	if !applicable || !relevantNormalizedDeclarationProperty(property) {
		return false
	}
	value := rawTokenString(values)
	var declarations []declaration
	if grammar == css.CustomPropertyGrammar {
		valueTokens, status := lexValue(value, s.cpu)
		declarations = s.declarationsFromTokens(property, valueTokens, status, value)
	} else if cssTokensNeedRetention(property, values) {
		valueTokens, status := ownedValueTokens(values, value, s.cpu)
		declarations = s.declarationsFromTokens(property, valueTokens, status, value)
	} else {
		declarations = s.declarationsFromParsed(property, parseUnretainedCSSTokens(values, value), false)
	}
	if len(declarations) > maxCSSDeclarations-s.declarationCount {
		s.abandonCascade()
		return true
	}
	// Account for the temporary declaration slice separately from the retained
	// inline/rule backing array grown below.
	if !s.memory.Reserve(int64(len(declarations)) * int64(unsafe.Sizeof(declaration{}))) {
		s.abandonCascade()
		return true
	}
	s.declarationCount += len(declarations)
	if p.inline {
		var ok bool
		p.out, ok = growSlice(p.out, len(declarations), s.memory)
		if !ok {
			s.abandonCascade()
			return true
		}
		p.out = append(p.out, declarations...)
	} else if p.current >= 0 {
		out, ok := growSlice(s.rules[p.current].decls, len(declarations), s.memory)
		if !ok {
			s.abandonCascade()
			return true
		}
		s.rules[p.current].decls = append(out, declarations...)
	}
	return false
}
