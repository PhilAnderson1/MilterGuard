// Package termination implements immediate termination of a controlled
// extraction stage. Ordinary parser errors do not use this mechanism.
package termination

// Code identifies why a stage ended.
type Code uint8

const (
	None Code = iota
	CPUExceeded
	MemoryExceeded
	Cancelled
)

// Failure contains bounded diagnostic data. It never retains input text.
type Failure struct {
	Code Code
	// Limit is the memory allowance in bytes for MemoryExceeded, otherwise zero.
	// CPU enforcement retains only a deadline; its allowance belongs to the caller.
	Limit int64
}

// signal is private so only Fail can create a valid stage termination.
type signal struct{ failure Failure }

// Fail ends the current stage. Callers must establish a stage boundary with
// Recover before using it. Deferred cleanup must not raise another failure.
func Fail(f Failure) {
	switch f.Code {
	case CPUExceeded, MemoryExceeded, Cancelled:
		panic(signal{failure: f})
	default:
		panic("termination: invalid failure code")
	}
}

// Recover must be deferred directly at the stage boundary:
//
//	defer termination.Recover(&failure)
//
// It catches only a stage termination and rethrows unrelated panics. Do not
// install it in intermediate parser or text helpers.
func Recover(dst *Failure) {
	if value := recover(); value != nil {
		if stop, ok := value.(signal); ok {
			*dst = stop.failure
			return
		}
		panic(value)
	}
}

// Rethrow lets a legacy catch-all preserve stage termination before applying
// its ordinary error handling. It returns for all other values.
func Rethrow(value any) {
	if _, ok := value.(signal); ok {
		panic(value)
	}
}
