package resourceguard

import (
	"bytes"
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
	"strings"
	"unsafe"
)

// WorkChunk bounds scans and copies between cooperative cancellation checks.
const WorkChunk = 4096

// Stop is a checkpoint: return normally to continue or unwind to terminate.
// A nil callback disables CPU/cancellation checking.
type Stop func()

func (m *Memory) reject() {
	if m != nil {
		m.exhausted = true
	}
	termination.Fail(termination.Failure{Code: termination.MemoryExceeded, Limit: m.Limit()})
	return
}

// storageBytes validates arithmetic even for unguarded callers. It accounts for
// requested typed storage, not hidden allocator size classes or GC metadata.
func storageBytes(count int, size uintptr) (int64, bool) {
	if count < 0 || size != 0 && uint64(count) > uint64(^uint(0)>>1)/uint64(size) {
		return 0, false
	}
	return int64(count) * int64(size), true
}

// New admits and owns a fixed object. Referenced storage has its own owner.
func New[T any](m *Memory, value T) *T {
	m.Reserve((int64(unsafe.Sizeof(value)) + 15) &^ 15)

	owned := new(T)
	*owned = value
	return owned
}

// MakeSlice owns the initial backing array. The returned slice transfers that
// ownership to its caller; reslicing within capacity does not spend budget.
func MakeSlice[T any](m *Memory, length, capacity int) []T {
	var value T
	size, ok := storageBytes(capacity, unsafe.Sizeof(value))
	if !ok || length < 0 || length > capacity {
		m.reject()
		return nil
	}

	m.Reserve(size)

	return make([]T, length, capacity)
}

// GrowSlice owns replacement storage and leaves s unchanged on failure. Copies
// are cancellable; every full replacement remains charged, including discarded
// replacements. The caller must retire borrowed views before mutating storage.
func GrowSlice[T any](m *Memory, s []T, additional int, stop Stop) []T {
	return GrowSliceFrom(m, s, additional, 1, stop)
}

// GrowSliceFrom sets the modest initial capacity for a collection's workload.
func GrowSliceFrom[T any](m *Memory, s []T, additional, initial int, stop Stop) []T {
	if additional < 0 || additional > int(^uint(0)>>1)-len(s) {
		m.reject()
		return s
	}

	m.unavailable()

	needed := len(s) + additional
	if needed <= cap(s) {
		return s
	}
	capacity := needed
	if cap(s) <= int(^uint(0)>>1)/2 {
		capacity = max(capacity, max(initial, 2*cap(s)))
	}
	var value T

	if len(s) > WorkChunk/max(1, int(unsafe.Sizeof(value))) {
		if stop != nil {
			stop()
		}
	}

	grown := MakeSlice[T](m, len(s), capacity)

	chunk := max(1, WorkChunk/max(1, int(unsafe.Sizeof(value))))
	for start := 0; start < len(s); start += chunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		copy(grown[start:min(start+chunk, len(s))], s[start:])
	}
	return grown
}

// Append combines admission and insertion; no caller-side reservation is needed.
func Append[T any](m *Memory, s []T, stop Stop, values ...T) []T {
	grown := GrowSlice(m, s, len(values), stop)

	old := len(grown)
	grown = grown[:old+len(values)]
	var value T
	chunk := max(1, WorkChunk/max(1, int(unsafe.Sizeof(value))))
	for start := 0; start < len(values); start += chunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		copy(grown[old+start:old+min(start+chunk, len(values))], values[start:])
	}
	return grown
}

// MakeBytes reconciles capacity exposed by bytes.Buffer before publishing it.
// Failed reconciliation may already have allocated the rounding excess; it
// terminates the operation and discards the storage. It is not a hard process-memory cap.
func MakeBytes(m *Memory, size int) []byte {
	if size < 0 {
		m.reject()
		return nil
	}

	m.Reserve(int64(size))

	var b bytes.Buffer
	b.Grow(size)

	m.Reserve(int64(b.Cap() - size))

	return b.Bytes()[:size]
}

// GrowText owns complete builder replacements. String views remain immutable:
// never reuse their backing storage as mutable scratch. Reset drops ownership.
// A termination during replacement may leave b empty or containing only a
// copied prefix. Callers must therefore keep guarded builders inside the
// extraction stage that owns them and discard them if that stage unwinds.
func GrowText(m *Memory, b *strings.Builder, additional int, stop Stop) {
	if additional < 0 || additional > int(^uint(0)>>1)-b.Len() {
		m.reject()
		return
	}

	m.unavailable()

	if additional > WorkChunk || b.Len() > WorkChunk {
		if stop != nil {
			stop()
		}
	}

	if additional <= b.Cap()-b.Len() {
		return
	}
	capacity := b.Len() + additional
	if b.Cap() <= (int(^uint(0)>>1)-additional)/2 {
		capacity = 2*b.Cap() + additional
	}

	m.Reserve(int64(capacity))

	previous := b.String()
	b.Reset()
	b.Grow(capacity)

	m.Reserve(int64(b.Cap() - capacity))

	for start := 0; start < len(previous); start += WorkChunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		b.WriteString(previous[start:min(start+WorkChunk, len(previous))])
	}
	return
}

// WriteString appends guarded text. A termination while copying may leave b
// with only a prefix appended, so the caller must discard b with its stage.
func WriteString(m *Memory, b *strings.Builder, text string, stop Stop) {
	GrowText(m, b, len(text), stop)

	for start := 0; start < len(text); start += WorkChunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		b.WriteString(text[start:min(start+WorkChunk, len(text))])
	}
	return
}

// WriteBytes appends guarded bytes. A termination while copying may leave b
// with only a prefix appended, so the caller must discard b with its stage.
func WriteBytes(m *Memory, b *strings.Builder, data []byte, stop Stop) {
	GrowText(m, b, len(data), stop)

	for start := 0; start < len(data); start += WorkChunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		b.Write(data[start:min(start+WorkChunk, len(data))])
	}
	return
}

func CopyString(m *Memory, data []byte, stop Stop) string {
	if len(data) <= 1 {
		m.unavailable()
		m.Reserve(int64(len(data)))

		return string(data)
	}
	var b strings.Builder

	WriteBytes(m, &b, data, stop)

	return b.String()
}

func Concat(m *Memory, left, right string, stop Stop) string {
	if len(right) == 0 {
		m.unavailable()
		return left
	}
	if len(left) == 0 {
		m.unavailable()
		return right
	}
	var b strings.Builder
	if len(right) > int(^uint(0)>>1)-len(left) {
		m.reject()
		return ""
	}

	GrowText(m, &b, len(left)+len(right), stop)
	WriteString(m, &b, left, stop)
	WriteString(m, &b, right, stop)

	return b.String()
}

// CloneBytes owns a byte copy and reconciles the capacity exposed by Clone.
func CloneBytes(m *Memory, data []byte, stop Stop) []byte {
	if len(data) > WorkChunk {
		if stop != nil {
			stop()
		}

		out := MakeBytes(m, len(data))

		for start := 0; start < len(data); start += WorkChunk {
			if start > 0 {
				if stop != nil {
					stop()
				}
			}

			copy(out[start:min(start+WorkChunk, len(data))], data[start:])
		}
		return out
	}

	m.Reserve(int64(len(data)))

	out := bytes.Clone(data)

	m.Reserve(int64(cap(out) - len(data)))

	return out
}

// StringBytes creates mutable owned bytes, optionally with a trailing NUL.
func StringBytes(m *Memory, s string, nul bool, stop Stop) []byte {
	size := len(s)
	if nul {
		if size == int(^uint(0)>>1) {
			m.reject()
			return nil
		}
		size++
	}

	if len(s) > WorkChunk {
		if stop != nil {
			stop()
		}
	}

	out := MakeSlice[byte](m, size, size)

	for start := 0; start < len(s); start += WorkChunk {
		if start > 0 {
			if stop != nil {
				stop()
			}
		}

		copy(out[start:min(start+WorkChunk, len(s))], s[start:])
	}
	return out
}

// Box owns a value stored in an interface. It preserves the concrete value type
// (unlike New), which matters to selector type switches. Pointer-bearing fields
// still refer to separately owned storage. Small/static values may be overcharged.
func Box[T any](m *Memory, value T) any {
	m.Reserve((int64(unsafe.Sizeof(value)) + 15) &^ 15)

	return value
}

func LowerASCII(m *Memory, s string, stop Stop) string {
	changed := false
	for i := 0; i < len(s); i++ {
		if i > 0 && i%WorkChunk == 0 {
			if stop != nil {
				stop()
			}
		}

		if s[i] >= 'A' && s[i] <= 'Z' {
			changed = true
			break
		}
	}
	if !changed {
		m.unavailable()
		return s
	}
	var b strings.Builder

	GrowText(m, &b, len(s), stop)

	for i := 0; i < len(s); i++ {
		if i > 0 && i%WorkChunk == 0 {
			if stop != nil {
				stop()
			}
		}

		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// TryMakeSlice is optional-cache admission: rejection does not poison required
// work. Like all storage entry points, it terminates when reusing an exhausted
// ledger. Invalid dimensions are rejected first, without inspecting or changing
// the budget.
func TryMakeSlice[T any](m *Memory, length, capacity int) ([]T, bool) {
	var value T
	size, ok := storageBytes(capacity, unsafe.Sizeof(value))
	if !ok || length < 0 || length > capacity || !m.TryReserve(size) {
		return nil, false
	}
	return make([]T, length, capacity), true
}
