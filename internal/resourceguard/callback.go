package resourceguard

import "unsafe"

// BindCheckpoint admits one escaping checkpoint environment. The callback
// returns normally or raises a shared termination signal.
func BindCheckpoint[T any](m *Memory, target T, fn func(T)) func() {
	m.Reserve((int64(unsafe.Sizeof(target)) + 31) &^ 15)
	return func() { fn(target) }
}
