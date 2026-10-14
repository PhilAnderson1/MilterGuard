package htmlextract

import "fmt"

// allocationPreflight bounds parser-created elements and attribute slices
// before x/net/html allocates its tree. It deliberately overestimates recovery:
// orphaned formatting entries remain reconstructible until a known marker
// clears their scope. The fixed document/html/head/body overhead is checked by
// the subsequent tree walk rather than charged as input-dependent expansion.
type allocationPreflight struct {
	limits                      Limits
	usage                       *lexicalUsage
	formatting                  []*preflightFormatting
	scopes                      []*preflightFormattingScope
	orphans, orphanAttributes   int
	uncertain                   bool
	maximumFormattingAttributes int
}

type preflightFormatting struct {
	name           string
	attributes     int
	active, orphan bool
}

type preflightFormattingScope struct{ base int }

func (p *allocationPreflight) add(nodes, attributes int) error {
	if nodes > p.limits.Nodes-p.usage.projectedNodes {
		return fmt.Errorf("limit: projected tree allocations > %d nodes", p.limits.Nodes)
	}
	if attributes > p.limits.Attributes-p.usage.projectedAttributes {
		return fmt.Errorf("limit: projected tree allocations > %d attributes", p.limits.Attributes)
	}
	p.usage.projectedNodes += nodes
	p.usage.projectedAttributes += attributes
	return nil
}

func formattingTag(name string) bool {
	switch name {
	case "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong", "tt", "u":
		return true
	}
	return false
}

func (p *allocationPreflight) scopeBase() int {
	if len(p.scopes) == 0 {
		return 0
	}
	return p.scopes[len(p.scopes)-1].base
}

func (p *allocationPreflight) orphan(entry *preflightFormatting) {
	if entry != nil && entry.active && !entry.orphan {
		entry.orphan = true
		p.orphans++
		p.orphanAttributes += entry.attributes
	}
}

func (p *allocationPreflight) uncertainInsertionMode(name string) {
	if closesParagraph(name) {
		for _, entry := range p.formatting {
			p.orphan(entry)
		}
		return
	}
	switch name {
	case "table", "caption", "colgroup", "tbody", "thead", "tfoot", "tr", "td", "th", "select", "button":
		// These tokens can change the real insertion mode or implicitly pop
		// elements not popped by the lexical depth model (nested table starts
		// are one example). Existing entries may consequently be reconstructed.
		for _, entry := range p.formatting {
			p.orphan(entry)
		}
	}
}

func (p *allocationPreflight) notePop(stack []lexicalFrame, keep int, name string, explicit bool) {
	if !explicit {
		return
	}
	for _, frame := range stack[keep+1:] {
		if frame.foreign || frame.uncertain {
			p.uncertain = true
		}
		switch frame.name {
		case "caption", "td", "th":
			switch name {
			case "td", "th", "tr", "tbody", "thead", "tfoot", "table":
				continue
			}
			p.uncertain = true
		case "applet", "html", "table", "marquee", "object", "template", "select", "button":
			p.uncertain = true
		}
	}
}

func (p *allocationPreflight) remove(index int) {
	entry := p.formatting[index]
	entry.active = false
	if entry.orphan {
		p.orphans--
		p.orphanAttributes -= entry.attributes
	}
	copy(p.formatting[index:], p.formatting[index+1:])
	p.formatting[len(p.formatting)-1] = nil
	p.formatting = p.formatting[:len(p.formatting)-1]
}

func (p *allocationPreflight) pushScope() (*preflightFormattingScope, error) {
	// Once recovery makes marker identity uncertain, no later marker can
	// justify clearing entries. Retain the existing entries conservatively
	// without accumulating unusable scope records for every following cell.
	if p.uncertain {
		return nil, nil
	}
	if len(p.scopes) >= p.limits.Depth {
		return nil, fmt.Errorf("limit: formatting scope depth > %d", p.limits.Depth)
	}
	scope := &preflightFormattingScope{base: len(p.formatting)}
	p.scopes = append(p.scopes, scope)
	return scope, nil
}

func (p *allocationPreflight) popScope() {
	base := p.scopeBase()
	for len(p.formatting) > base {
		p.remove(len(p.formatting) - 1)
	}
	p.scopes = p.scopes[:len(p.scopes)-1]
}

// Lexical popping alone does not prove that the tree builder clears a marker:
// </div>, for example, can be ignored inside object scope. Only trust a known
// innermost marker at its own close or a table cell's structural close.
func (p *allocationPreflight) canClearScope(stack []lexicalFrame, keep int, name string, explicit bool) *preflightFormattingScope {
	if p.uncertain {
		return nil
	}
	marker := -1
	for i := keep; i < len(stack); i++ {
		if stack[i].foreign || stack[i].uncertain {
			return nil
		}
		if stack[i].formattingMarker != nil {
			if marker >= 0 {
				return nil
			}
			marker = i
		}
	}
	if marker < 0 || len(p.scopes) == 0 || stack[marker].formattingMarker != p.scopes[len(p.scopes)-1] {
		return nil
	}
	for _, frame := range stack[marker+1:] {
		switch frame.name {
		case "applet", "caption", "html", "table", "td", "th", "marquee", "object", "template", "select":
			return nil
		}
	}
	if explicit && name == stack[marker].name {
		return stack[marker].formattingMarker
	}
	switch stack[marker].name {
	case "td", "th", "caption":
		switch name {
		case "td", "th", "tr", "tbody", "thead", "tfoot", "table":
			return stack[marker].formattingMarker
		}
	}
	return nil
}

func (p *allocationPreflight) startFormatting(name string, attributes int) (*preflightFormatting, error) {
	p.maximumFormattingAttributes = max(p.maximumFormattingAttributes, attributes)
	// The parser's Noah's Ark rule keeps at most three identical entries in a
	// scope. With no attributes, equality is exact without retaining attacker
	// controlled strings. Attributed entries remain conservatively distinct.
	if attributes == 0 {
		identical := 0
		for i := len(p.formatting) - 1; i >= p.scopeBase(); i-- {
			entry := p.formatting[i]
			if entry.name == name && entry.attributes == 0 {
				identical++
				if identical >= 3 {
					p.remove(i)
				}
			}
		}
	}
	if len(p.formatting) >= p.limits.Depth {
		return nil, fmt.Errorf("limit: formatting recovery depth > %d", p.limits.Depth)
	}
	entry := &preflightFormatting{name: name, attributes: attributes, active: true}
	p.formatting = append(p.formatting, entry)
	return entry, nil
}

func (p *allocationPreflight) hasFormatting(name string) bool {
	// A conservatively retained marker may already have been cleared by real
	// recovery. Include outer entries when reserving adoption-agency clones.
	base := p.scopeBase()
	if p.uncertain {
		base = 0
	}
	for i := len(p.formatting) - 1; i >= base; i-- {
		if p.formatting[i].name == name {
			return true
		}
	}
	return false
}

func (p *allocationPreflight) endFormatting(name string, stack []lexicalFrame) error {
	if !p.hasFormatting(name) {
		return nil
	}
	last := len(p.formatting) - 1
	if len(stack) > 0 {
		top := stack[len(stack)-1]
		if top.name == name && !top.uncertain && top.formatting == p.formatting[last] && (!top.formatting.orphan || !p.uncertain) {
			p.remove(last)
			return nil
		}
	}
	p.uncertain = true
	// Adoption-agency recovery has at most eight outer iterations, each
	// cloning at most three inner formatting elements and the target element.
	// Reserve copied attributes too, including temporary clones not retained
	// in the final DOM. Repeat the additions to avoid integer multiplication.
	attributes := 0
	for _, entry := range p.formatting {
		attributes += entry.attributes
		p.orphan(entry)
	}
	for range 8 {
		if err := p.addClones(min(4, len(p.formatting)), attributes); err != nil {
			return err
		}
	}
	return nil
}

func (p *allocationPreflight) reconstruct() error {
	// Count every possible reconstruction. Keeping the orphan state after
	// charging avoids trusting a speculative replica of the parser's open
	// element stack, at the cost of conservative overcounting malformed HTML.
	return p.addClones(p.orphans, p.orphanAttributes)
}

func (p *allocationPreflight) addClones(nodes, attributes int) error {
	// Recovery can move formatting entries across the lexical scopes. Bound
	// each possible copy by the largest formatting attribute slice seen, even
	// when the lexical model associates it with a different formatting entry.
	if p.maximumFormattingAttributes != 0 {
		if nodes > (p.limits.Attributes-p.usage.projectedAttributes)/p.maximumFormattingAttributes {
			return fmt.Errorf("limit: projected tree allocations > %d attributes", p.limits.Attributes)
		}
		attributes = max(attributes, nodes*p.maximumFormattingAttributes)
	}
	return p.add(nodes, attributes)
}

func tableContext(stack []lexicalFrame) (table, row, body, colgroup bool) {
	for i := len(stack) - 1; i >= 0; i-- {
		frame := stack[i]
		if frame.foreign || frame.uncertain || frame.name == "template" || frame.name == "select" {
			return false, false, false, false
		}
		switch frame.name {
		case "table":
			return true, row, body, colgroup
		case "tr":
			row = true
		case "tbody", "thead", "tfoot":
			body = true
		case "colgroup":
			colgroup = true
		}
	}
	return false, false, false, false
}

func impliedTableNodes(name string, stack []lexicalFrame) int {
	// Charge the maximum wrapper expansion even when the lexical stack says
	// wrappers exist: ignored tags or recovery can change the allocating
	// parser's insertion mode. Ordinary documents stay far below this budget.
	switch name {
	case "td", "th":
		return 2 // tbody and tr
	case "tr", "col":
		return 1 // tbody or colgroup
	}
	return 0
}

func formattingScopeMarker(name string, stack []lexicalFrame) bool {
	switch name {
	case "applet", "marquee", "object", "template":
		return true
	case "caption", "td", "th":
		table, _, _, _ := tableContext(stack)
		return table
	}
	return false
}
