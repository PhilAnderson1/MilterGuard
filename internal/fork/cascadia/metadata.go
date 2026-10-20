package cascadia

import (
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// IndexKeyKind identifies a positive selector that can narrow candidate
// elements without changing selector semantics.
type IndexKeyKind uint8

const (
	IndexUniversal IndexKeyKind = iota
	IndexTag
	IndexID
	IndexClass
)

type IndexKey struct {
	Kind  IndexKeyKind
	Value string
}

// CompoundMetadata describes one element-matching part of a compiled selector.
// Matcher is the exact matcher already produced by the authoritative parse.
type CompoundMetadata struct {
	Matcher            Matcher
	PositiveMatcher    Matcher
	FullyPositive      bool
	Key                IndexKey
	OriginalTypeName   string
	AttributeSensitive bool
}

// SelectorMetadata exposes the structural information needed by bounded
// candidate indexing and ancestor-chain matching without parsing selector text
// a second time.
type SelectorMetadata struct {
	Compounds     []CompoundMetadata
	Combinators   []byte
	Inactive      bool
	Supported     bool
	PseudoElement string
}

// Metadata derives structural information from an already compiled selector.
func Metadata(selector Sel) SelectorMetadata {
	metadata, _ := MetadataWithMemory(selector, nil)
	return metadata
}

// MetadataWithMemory accounts for arrays owned by metadata before allocating.
func MetadataWithMemory(selector Sel, memory *resourceguard.Memory) (result SelectorMetadata, err error) {
	compoundCount := selectorCompoundCount(selector)
	metadata := SelectorMetadata{
		Compounds: selectorSlice[CompoundMetadata](memory, 0, compoundCount),
	}
	if compoundCount > 1 {
		metadata.Combinators = selectorSlice[byte](memory, 0, compoundCount-1)
	}
	appendSelectorMetadata(selector, &metadata, memory)
	metadata.Inactive = selectorNeverMatches(selector)
	metadata.PseudoElement = selector.PseudoElement()
	metadata.Supported = metadata.PseudoElement == "" && selectorSupportedForEmail(selector)
	return metadata, nil
}

func selectorCompoundCount(selector Sel) int {
	if combined, ok := selector.(combinedSelector); ok {
		return selectorCompoundCount(combined.first) + 1
	}
	return 1
}

func appendSelectorMetadata(selector Sel, metadata *SelectorMetadata, memory *resourceguard.Memory) {
	if combined, ok := selector.(combinedSelector); ok {
		appendSelectorMetadata(combined.first, metadata, memory)
		metadata.Combinators = append(metadata.Combinators, combined.combinator)
		metadata.Compounds = append(metadata.Compounds, describeCompound(combined.second, memory))
		return
	}
	metadata.Compounds = append(metadata.Compounds, describeCompound(selector, memory))
}

func describeCompound(selector Sel, memory *resourceguard.Memory) CompoundMetadata {
	metadata := CompoundMetadata{
		Matcher:            selector,
		AttributeSensitive: selectorUsesAttributes(selector),
	}
	state := compoundMetadataState{}
	if compound, ok := selector.(compoundSelector); ok {
		for _, simple := range compound.selectors {
			state.add(simple)
		}
	} else {
		state.add(selector)
	}
	metadata.FullyPositive = state.positiveCount == state.simpleCount && selector.PseudoElement() == ""
	if metadata.FullyPositive {
		metadata.PositiveMatcher = selector
	} else if state.positiveCount == 1 {
		metadata.PositiveMatcher = state.firstPositive
	} else if state.positiveCount > 1 {
		positive := selectorSlice[Sel](memory, 0, state.positiveCount)
		compound := selector.(compoundSelector)
		for _, simple := range compound.selectors {
			switch simple.(type) {
			case tagSelector, idSelector, classSelector:
				positive = append(positive, simple)
			}
		}
		metadata.PositiveMatcher = selectorObject(memory, compoundSelector{selectors: positive})
	}
	switch {
	case state.id != "":
		metadata.Key = IndexKey{Kind: IndexID, Value: state.id}
	case state.class != "":
		metadata.Key = IndexKey{Kind: IndexClass, Value: state.class}
	case state.tag != "":
		metadata.Key = IndexKey{Kind: IndexTag, Value: state.tag}
	}
	metadata.OriginalTypeName = state.originalTag
	return metadata
}

type compoundMetadataState struct {
	tag, originalTag, id, class string
	firstPositive               Sel
	positiveCount, simpleCount  int
}

func (s *compoundMetadataState) add(simple Sel) {
	s.simpleCount++
	switch value := simple.(type) {
	case tagSelector:
		s.tag = value.tag
		s.originalTag = value.original
		s.firstPositive = simple
		s.positiveCount++
	case idSelector:
		s.id = value.id
		if s.firstPositive == nil {
			s.firstPositive = simple
		}
		s.positiveCount++
	case classSelector:
		if s.class == "" {
			s.class = value.class
		}
		if s.firstPositive == nil {
			s.firstPositive = simple
		}
		s.positiveCount++
	}
}

func selectorSupportedForEmail(selector Sel) bool {
	switch value := selector.(type) {
	case tagSelector, classSelector, idSelector, attrSelector, rootPseudoClassSelector, neverMatchSelector:
		return true
	case compoundSelector:
		for _, simple := range value.selectors {
			if !selectorSupportedForEmail(simple) {
				return false
			}
		}
		return true
	case combinedSelector:
		return selectorSupportedForEmail(value.first) && selectorSupportedForEmail(value.second)
	case relativePseudoClassSelector:
		if value.name != "not" {
			return false
		}
		for _, nested := range value.match {
			if _, combined := nested.(combinedSelector); combined || !simpleNegationSelector(nested) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func simpleNegationSelector(selector Sel) bool {
	switch value := selector.(type) {
	case tagSelector, classSelector, idSelector, attrSelector:
		return true
	case compoundSelector:
		for _, simple := range value.selectors {
			if !simpleNegationSelector(simple) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func selectorUsesAttributes(selector Sel) bool {
	switch value := selector.(type) {
	case classSelector, idSelector, attrSelector:
		return true
	case compoundSelector:
		for _, simple := range value.selectors {
			if selectorUsesAttributes(simple) {
				return true
			}
		}
	case combinedSelector:
		return selectorUsesAttributes(value.first) || selectorUsesAttributes(value.second)
	case relativePseudoClassSelector:
		for _, nested := range value.match {
			if selectorUsesAttributes(nested) {
				return true
			}
		}
	}
	return false
}

func selectorNeverMatches(selector Sel) bool {
	switch value := selector.(type) {
	case neverMatchSelector:
		return true
	case compoundSelector:
		for _, simple := range value.selectors {
			if selectorNeverMatches(simple) {
				return true
			}
		}
	case combinedSelector:
		return selectorNeverMatches(value.first) || selectorNeverMatches(value.second)
	}
	return false
}
