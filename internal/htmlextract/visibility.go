package htmlextract

type visibilityLabel uint8

const (
	labelVisible visibilityLabel = 1 << iota
	labelConcealed
	labelUnknown
)

// ConcealmentReason is a compact set of reasons for a concealed result.
// Primary returns the reason with the same priority used by output annotations.
type ConcealmentReason uint8

type concealmentReason = ConcealmentReason

func (r ConcealmentReason) Primary() ConcealmentReason { return r & -r }

func concealedVisibilityReason(value Value) concealmentReason {
	if !value.Known {
		return 0
	}
	switch value.Text {
	case "hidden":
		return reasonVisibilityHidden
	case "collapse":
		return reasonVisibilityCollapse
	default:
		return 0
	}
}

const (
	reasonDisplayNone concealmentReason = 1 << iota
	reasonVisibilityHidden
	reasonVisibilityCollapse
	reasonOpacity
	reasonFontSize
	reasonColour
	reasonEmptyClip
	reasonContentVisibility
)

// Exported reasons let consumers format annotations without allocating or
// reparsing an intermediate list of names.
const (
	ReasonDisplayNone        = reasonDisplayNone
	ReasonVisibilityHidden   = reasonVisibilityHidden
	ReasonVisibilityCollapse = reasonVisibilityCollapse
	ReasonOpacity            = reasonOpacity
	ReasonFontSize           = reasonFontSize
	ReasonColour             = reasonColour
	ReasonEmptyClip          = reasonEmptyClip
	ReasonContentVisibility  = reasonContentVisibility
)

type visibilityDecision struct {
	label   visibilityLabel
	reasons concealmentReason
}

type presentationState struct {
	none, displayKnown           bool
	stableDisplayNone            bool
	alpha                        float64
	alphaKnown                   bool
	clipped, clipKnown           bool
	contentHidden, contentKnown  bool
	msoHidden, msoKnown          bool
	layoutUncertain              bool
	clipsDescendantsX            bool
	clipsDescendantsY            bool
	animationUncertain           bool
	fontScaleUncertain           bool
	textLayout                   [3]bool
	clientDependentReasons       concealmentReason
	alternateColourSchemeReasons concealmentReason
}

func initialPresentationState() presentationState {
	return presentationState{alpha: 1, alphaKnown: true, displayKnown: true, contentKnown: true, msoKnown: true, clipKnown: true}
}

func elementPaintKnown(style *Style) bool {
	for _, property := range [...]int{filter, blend, maskImage, transform} {
		if !style[property].Known {
			return false
		}
	}
	return true
}

func decideVisibility(style *Style, state presentationState, colour *colourResult) visibilityDecision {
	var mask concealmentReason
	visibilityReason := concealedVisibilityReason(style[visibility])
	if state.none {
		mask |= reasonDisplayNone
	}
	if visibilityReason != 0 {
		mask |= visibilityReason
	}
	if state.alphaKnown && state.alpha <= .01+1e-14 {
		mask |= reasonOpacity
	}
	if state.clipped {
		mask |= reasonEmptyClip
	}
	if state.contentHidden {
		mask |= reasonContentVisibility
	}

	known := state.displayKnown && style[visibility].Known && state.alphaKnown && state.clipKnown && state.contentKnown && state.msoKnown && !state.layoutUncertain && !state.textLayout[0] && !state.textLayout[1] && !state.textLayout[2]
	if colour != nil {
		if (!state.fontScaleUncertain || style[fontSize].Number == 0) && style[fontSize].Known && style[fontSize].Number <= 2 {
			mask |= reasonFontSize
		}
		if colour.known && colourConcealed(colour.distance) {
			mask |= reasonColour
		}
		known = known && style[fontSize].Known && colour.known && !state.fontScaleUncertain
	}

	decision := visibilityDecision{label: labelVisible, reasons: mask}
	if mask != 0 {
		decision.label = labelConcealed
	} else if !known {
		decision.label = labelUnknown
	} else if state.msoHidden {
		// mso-hide is honored only by Word-based Outlook clients. This is
		// client-dependent, but not viewport-dependent, so use the generic
		// uncertainty annotation rather than the viewport-specific one.
		decision.label = labelUnknown
	}
	// Light mode is the canonical colour scheme. Visible content remains
	// visible even if dark-mode CSS could alter its presentation. Conversely,
	// do not confidently call content invisible when a scheme-dependent rule
	// can change the property responsible for that conclusion.
	// Some concealment mechanisms are ignored by prominent email clients, and
	// colour-scheme rules can independently reveal content. A confident result
	// requires at least one reason unaffected by either source of divergence.
	uncertainReasons := state.clientDependentReasons | state.alternateColourSchemeReasons
	if decision.label == labelConcealed && decision.reasons&^uncertainReasons == 0 {
		decision.label = labelUnknown
	}
	if state.animationUncertain {
		decision.label = labelUnknown
	}
	if state.stableDisplayNone {
		decision.label = labelConcealed
	}
	return decision
}

func aggregateLabel(bits visibilityLabel) string {
	if bits&labelUnknown != 0 {
		return "unknown"
	}
	if bits&(labelVisible|labelConcealed) == labelVisible|labelConcealed {
		return "client-dependent"
	}
	if bits&labelConcealed != 0 {
		return "concealed"
	}
	return "visible"
}
