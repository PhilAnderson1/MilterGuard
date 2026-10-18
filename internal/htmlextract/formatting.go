package htmlextract

import "strconv"

// Shortest float64 formatting uses at most 24 bytes. The fixed buffers cover
// one number with its unit, or four colour channels with their punctuation.
// Only the final string escapes; no fmt interface boxes or temporary strings
// are needed. Charge before copying, rounding up to a 16-byte size class (the
// buffers and their outputs stay below 128 bytes).
func formattedString(data []byte, budget *cpuGuard) string {
	if budget.stopNow(false) || !budget.reserve(int64((len(data)+15)/16*16)) {
		return ""
	}
	return string(data)
}

func numberStringWithBudget(value float64, unit string, budget *cpuGuard) string {
	var storage [32]byte
	out := strconv.AppendFloat(storage[:0], value, 'g', -1, 64)
	out = append(out, unit...)
	return formattedString(out, budget)
}

func colourStringWithBudget(c RGBA, budget *cpuGuard) string {
	var storage [128]byte
	out := append(storage[:0], "rgba("...)
	for i, channel := range [...]float64{c.R * 255, c.G * 255, c.B * 255, c.A} {
		if i != 0 {
			out = append(out, ',')
		}
		out = strconv.AppendFloat(out, channel, 'g', -1, 64)
	}
	out = append(out, ')')
	return formattedString(out, budget)
}
