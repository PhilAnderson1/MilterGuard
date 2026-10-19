package htmlextract

const (
	display = iota
	visibility
	contentVisibility
	msoHide
	opacity
	fontSize
	color
	background
	backgroundImage
	filter
	blend
	backdropFilter
	backgroundBlend
	maskImage
	backgroundClip
	textShadow
	textFill
	transform
	position
	textStroke
	clip
	clipPath
	lineHeight
	properties
)

const (
	overflowX = properties + iota
	overflowY
	width
	height
	maxWidth
	maxHeight
	left
	top
	right
	bottom
	textIndent
	letterSpacing
	wordSpacing
	marginTop
	marginRight
	marginBottom
	marginLeft
	zoom
	inlineSize
	blockSize
	maxInlineSize
	maxBlockSize
	insetInlineStart
	insetInlineEnd
	insetBlockStart
	insetBlockEnd
	marginInlineStart
	marginInlineEnd
	marginBlockStart
	marginBlockEnd
	declarationProperties
	layoutProperties = declarationProperties - properties
	// allShorthandProperty is an internal sentinel. Keep one declaration for
	// the source shorthand and broadcast it across the tracked properties only
	// while applying the cascade; eagerly materialising every property permits
	// severe memory amplification from a small stylesheet.
	allShorthandProperty = declarationProperties
	// animationProperty is a cascade-only sentinel. Animation is not rendered;
	// its winning declaration is retained solely to prevent a time-varying
	// subtree from receiving a static visibility conclusion.
	animationProperty = allShorthandProperty + 1
)

var names = [declarationProperties]string{"display", "visibility", "content-visibility", "mso-hide", "opacity", "font-size", "color", "background-color", "background-image", "filter", "mix-blend-mode", "backdrop-filter", "background-blend-mode", "mask-image", "background-clip", "text-shadow", "-webkit-text-fill-color", "transform", "position", "-webkit-text-stroke", "clip", "clip-path", "line-height", "overflow-x", "overflow-y", "width", "height", "max-width", "max-height", "left", "top", "right", "bottom", "text-indent", "letter-spacing", "word-spacing", "margin-top", "margin-right", "margin-bottom", "margin-left", "zoom", "inline-size", "block-size", "max-inline-size", "max-block-size", "inset-inline-start", "inset-inline-end", "inset-block-start", "inset-block-end", "margin-inline-start", "margin-inline-end", "margin-block-start", "margin-block-end"}
