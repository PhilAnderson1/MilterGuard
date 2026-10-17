package cascadia

import (
	"fmt"

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
	Source             string
	PositiveSource     string
	PositiveMatcher    Matcher
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
	var metadata SelectorMetadata
	appendSelectorMetadata(selector, &metadata)
	metadata.Inactive = selectorNeverMatches(selector)
	metadata.PseudoElement = selector.PseudoElement()
	metadata.Supported = metadata.PseudoElement == "" && selectorSupportedForEmail(selector)
	return metadata
}

// MetadataWithMemory derives selector metadata and charges newly retained
// serialized compound strings. Per-component object growth is independently
// bounded by the parser's component limit.
func MetadataWithMemory(selector Sel, memory *resourceguard.Memory) (SelectorMetadata, error) {
	metadata := Metadata(selector)
	var retained int64
	for _, compound := range metadata.Compounds {
		retained += int64(len(compound.Source) + len(compound.PositiveSource))
	}
	if memory != nil && !memory.Reserve(retained) {
		return SelectorMetadata{}, fmt.Errorf("cascadia: memory limit exceeded")
	}
	return metadata, nil
}

func appendSelectorMetadata(selector Sel, metadata *SelectorMetadata) {
	if combined, ok := selector.(combinedSelector); ok {
		appendSelectorMetadata(combined.first, metadata)
		metadata.Combinators = append(metadata.Combinators, combined.combinator)
		metadata.Compounds = append(metadata.Compounds, describeCompound(combined.second))
		return
	}
	metadata.Compounds = append(metadata.Compounds, describeCompound(selector))
}

func describeCompound(selector Sel) CompoundMetadata {
	metadata := CompoundMetadata{
		Matcher:            selector,
		Source:             selector.String(),
		AttributeSensitive: selectorUsesAttributes(selector),
	}
	var tag, originalTag, id, class string
	var positive []Sel
	visitDirectSimpleSelectors(selector, func(simple Sel) {
		switch value := simple.(type) {
		case tagSelector:
			tag = value.tag
			originalTag = value.original
			positive = append(positive, simple)
		case idSelector:
			id = value.id
			positive = append(positive, simple)
		case classSelector:
			if class == "" {
				class = value.class
			}
			positive = append(positive, simple)
		}
	})
	if len(positive) != 0 {
		var matcher Sel
		if len(positive) == 1 {
			matcher = positive[0]
		} else {
			matcher = compoundSelector{selectors: positive}
		}
		metadata.PositiveMatcher = matcher
		metadata.PositiveSource = matcher.String()
	}
	switch {
	case id != "":
		metadata.Key = IndexKey{Kind: IndexID, Value: id}
	case class != "":
		metadata.Key = IndexKey{Kind: IndexClass, Value: class}
	case tag != "":
		metadata.Key = IndexKey{Kind: IndexTag, Value: tag}
	}
	metadata.OriginalTypeName = originalTag
	return metadata
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

func visitDirectSimpleSelectors(selector Sel, visit func(Sel)) {
	if compound, ok := selector.(compoundSelector); ok {
		for _, simple := range compound.selectors {
			visit(simple)
		}
		return
	}
	visit(selector)
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
