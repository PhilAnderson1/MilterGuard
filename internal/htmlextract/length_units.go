package htmlextract

import "strings"

type lengthUnitKind uint8

const (
	lengthUnitContextual lengthUnitKind = iota
	lengthUnitAbsolute
	lengthUnitParentFont
	lengthUnitRootFont
	lengthUnitPercentage
)

type lengthUnit struct {
	suffix string
	kind   lengthUnitKind
	scale  float64
}

// CSS length suffixes are ordered longest first where one is a suffix of
// another (for example rem before em and rlh before lh). All length parsers use
// this table so recognition and ordering cannot drift between code paths.
var lengthUnits = [...]lengthUnit{
	{suffix: "rem", kind: lengthUnitRootFont},
	{suffix: "px", kind: lengthUnitAbsolute, scale: 1},
	{suffix: "pt", kind: lengthUnitAbsolute, scale: 96.0 / 72},
	{suffix: "em", kind: lengthUnitParentFont},
	{suffix: "%", kind: lengthUnitPercentage},
	{suffix: "vmin", kind: lengthUnitContextual},
	{suffix: "vmax", kind: lengthUnitContextual},
	{suffix: "svw", kind: lengthUnitContextual},
	{suffix: "svh", kind: lengthUnitContextual},
	{suffix: "lvw", kind: lengthUnitContextual},
	{suffix: "lvh", kind: lengthUnitContextual},
	{suffix: "dvw", kind: lengthUnitContextual},
	{suffix: "dvh", kind: lengthUnitContextual},
	{suffix: "rcap", kind: lengthUnitContextual},
	{suffix: "rlh", kind: lengthUnitContextual},
	{suffix: "ric", kind: lengthUnitContextual},
	{suffix: "rex", kind: lengthUnitContextual},
	{suffix: "rch", kind: lengthUnitContextual},
	{suffix: "pc", kind: lengthUnitAbsolute, scale: 16},
	{suffix: "cm", kind: lengthUnitAbsolute, scale: 96.0 / 2.54},
	{suffix: "mm", kind: lengthUnitAbsolute, scale: 96.0 / 25.4},
	{suffix: "in", kind: lengthUnitAbsolute, scale: 96},
	{suffix: "ex", kind: lengthUnitContextual},
	{suffix: "ch", kind: lengthUnitContextual},
	{suffix: "lh", kind: lengthUnitContextual},
	{suffix: "cap", kind: lengthUnitContextual},
	{suffix: "ic", kind: lengthUnitContextual},
	{suffix: "vw", kind: lengthUnitContextual},
	{suffix: "vh", kind: lengthUnitContextual},
	{suffix: "vi", kind: lengthUnitContextual},
	{suffix: "vb", kind: lengthUnitContextual},
	{suffix: "q", kind: lengthUnitAbsolute, scale: 96.0 / 101.6},
}

func splitLength(value string) (numberText string, unit lengthUnit, found bool) {
	for _, candidate := range lengthUnits {
		if strings.HasSuffix(value, candidate.suffix) {
			return value[:len(value)-len(candidate.suffix)], candidate, true
		}
	}
	return value, lengthUnit{}, false
}
