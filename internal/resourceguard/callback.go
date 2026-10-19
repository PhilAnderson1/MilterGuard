package resourceguard

import "unsafe"

// ErrorCheck owns the escaping progress callback. Its conservative environment
// allowance includes the function pointer, error interface, and allocator rounding.
func ErrorCheck(m *Memory, stop func() bool, err error) (func() error, bool) {
	if stop == nil {
		return nil, !m.Exhausted()
	}
	if m.Exhausted() || !m.Reserve(48) {
		return nil, false
	}
	return func() error {
		if stop() {
			return err
		}
		return nil
	}, true
}

// BindStop owns a callback environment without requiring an already escaping
// method value at the call site. fn should be a noncapturing function.
func BindStop[T any](m *Memory, target T, fn func(T) bool) (func() bool, bool) {
	if m.Exhausted() || !m.Reserve((int64(unsafe.Sizeof(target))+31)&^15) {
		return nil, false
	}
	return func() bool { return fn(target) }, true
}
