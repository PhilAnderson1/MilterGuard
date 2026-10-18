package htmlextract

import (
	"math"
	"strconv"
	"unsafe"
)

// scanCSSNumber validates decimal CSS syntax and computes the base-10 order
// of the first significant digit. Exponents are saturated beyond anything the
// mantissa can cancel. Long scans sample cancellation without allocating.
func scanCSSNumber(s string, budget *cpuGuard) (order int64, zero, negative, valid bool) {
	i, digits, integerDigits, first := 0, 0, 0, -1
	nextCheck := stringWorkChunk
	step := func() bool {
		if i < nextCheck {
			return true
		}
		nextCheck = i + stringWorkChunk
		return !budget.stopNow(true)
	}
	if budget.stopNow(false) {
		return
	}
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		negative = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		if !step() {
			return
		}
		if first < 0 && s[i] != '0' {
			first = digits
		}
		digits++
		i++
	}
	integerDigits = digits
	hasInteger := i > start
	if i < len(s) && s[i] == '.' {
		i++
		start = i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			if !step() {
				return
			}
			if first < 0 && s[i] != '0' {
				first = digits
			}
			digits++
			i++
		}
		if i == start {
			return
		}
	} else if !hasInteger {
		return
	}
	var exponent int64
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		minus := false
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			minus = s[i] == '-'
			i++
		}
		start = i
		// More than len(s)+1024 cannot be cancelled by this mantissa.
		capExponent := int64(len(s)) + 1024
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			if !step() {
				return
			}
			digit := int64(s[i] - '0')
			if exponent > (capExponent-digit)/10 {
				exponent = capExponent
			} else {
				exponent = exponent*10 + digit
			}
			i++
		}
		if i == start {
			return
		}
		if minus {
			exponent = -exponent
		}
	}
	if i != len(s) {
		return
	}
	return int64(integerDigits) - int64(first) - 1 + exponent, first < 0, negative, true
}

// parseCSSNumber preserves overflow as infinity for colour clamping. Other
// numeric grammars use numberWithBudget, which accepts finite values only.
func parseCSSNumber(s string, budget *cpuGuard) (float64, bool) {
	order, zero, negative, valid := scanCSSNumber(s, budget)
	if !valid {
		return 0, false
	}
	sign := 1.0
	if negative {
		sign = -1
	}
	if zero {
		return math.Copysign(0, sign), true
	}
	if order >= 309 {
		return math.Copysign(math.Inf(1), sign), true
	}
	// ParseFloat's range error clones its input and owns a NumError. Admit that
	// possibility before conversion, including conservative size-class/page
	// rounding. The monotonic charge remains even when no error is allocated.
	bytes := int64(len(s))
	if !budget.reserve(bytes + bytes/4 + 64 + int64(unsafe.Sizeof(strconv.NumError{})) + 16) {
		return 0, false
	}
	value, _ := strconv.ParseFloat(s, 64)
	return value, !math.IsNaN(value)
}

func numberWithBudget(s string, budget *cpuGuard) (float64, bool) {
	value, valid := parseCSSNumber(s, budget)
	return value, valid && !math.IsInf(value, 0)
}
