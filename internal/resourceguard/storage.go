package resourceguard

import (
	"bytes"
	"strings"
	"unsafe"
)

// WorkChunk bounds scans and copies between cooperative cancellation checks.
const WorkChunk = 4096

// Stop returns true when work must stop. A nil callback permits the operation.
type Stop func() bool

func stopped(stop Stop) bool { return stop != nil && stop() }

func (m *Memory) reject() bool {
	if m != nil {
		m.exhausted = true
	}
	return false
}

// storageBytes validates arithmetic even for unguarded callers. It accounts for
// requested typed storage, not hidden allocator size classes or GC metadata.
func storageBytes(count int, size uintptr) (int64, bool) {
	if count < 0 || (size != 0 && uint64(count) > uint64(^uint(0)>>1)/uint64(size)) {
		return 0, false
	}
	return int64(count) * int64(size), true
}

// New admits and owns a fixed object. Referenced storage has its own owner.
func New[T any](m *Memory, value T) (*T, bool) {
	if m.Exhausted() || !m.Reserve((int64(unsafe.Sizeof(value))+15)&^15) {
		return nil, false
	}
	owned := new(T)
	*owned = value
	return owned, true
}

// MakeSlice owns the initial backing array. The returned slice transfers that
// ownership to its caller; reslicing within capacity does not spend budget.
func MakeSlice[T any](m *Memory, length, capacity int) ([]T, bool) {
	var value T
	size, ok := storageBytes(capacity, unsafe.Sizeof(value))
	if !ok || length < 0 || length > capacity {
		return nil, m.reject()
	}
	if m.Exhausted() || !m.Reserve(size) {
		return nil, false
	}
	return make([]T, length, capacity), true
}

// GrowSlice owns replacement storage and leaves s unchanged on failure. Copies
// are cancellable; every full replacement remains charged, including discarded
// replacements. The caller must retire borrowed views before mutating storage.
func GrowSlice[T any](m *Memory, s []T, additional int, stop Stop) ([]T, bool) {
	return GrowSliceFrom(m, s, additional, 1, stop)
}

// GrowSliceFrom sets the modest initial capacity for a collection's workload.
func GrowSliceFrom[T any](m *Memory, s []T, additional, initial int, stop Stop) ([]T, bool) {
	if additional < 0 || additional > int(^uint(0)>>1)-len(s) {
		return s, m.reject()
	}
	if m.Exhausted() {
		return s, false
	}
	needed := len(s) + additional
	if needed <= cap(s) {
		return s, true
	}
	capacity := needed
	if cap(s) <= int(^uint(0)>>1)/2 {
		capacity = max(capacity, max(initial, 2*cap(s)))
	}
	var value T
	if len(s) > WorkChunk/max(1, int(unsafe.Sizeof(value))) && stopped(stop) {
		return s, false
	}
	grown, ok := MakeSlice[T](m, len(s), capacity)
	if !ok {
		return s, false
	}
	chunk := max(1, WorkChunk/max(1, int(unsafe.Sizeof(value))))
	for start := 0; start < len(s); start += chunk {
		if start > 0 && stopped(stop) {
			return s, false
		}
		copy(grown[start:min(start+chunk, len(s))], s[start:])
	}
	return grown, true
}

// Append combines admission and insertion; no caller-side reservation is needed.
func Append[T any](m *Memory, s []T, stop Stop, values ...T) ([]T, bool) {
	grown, ok := GrowSlice(m, s, len(values), stop)
	if !ok {
		return s, false
	}
	old := len(grown)
	grown = grown[:old+len(values)]
	var value T
	chunk := max(1, WorkChunk/max(1, int(unsafe.Sizeof(value))))
	for start := 0; start < len(values); start += chunk {
		if start > 0 && stopped(stop) {
			clear(grown[old:])
			return grown[:old], false
		}
		copy(grown[old+start:old+min(start+chunk, len(values))], values[start:])
	}
	return grown, true
}

// MakeBytes reconciles capacity exposed by bytes.Buffer before publishing it.
// Failed reconciliation may already have allocated the rounding excess; it
// latches failure and discards the storage. It is not a hard process-memory cap.
func MakeBytes(m *Memory, size int) ([]byte, bool) {
	if size < 0 {
		return nil, m.reject()
	}
	if m.Exhausted() || !m.Reserve(int64(size)) {
		return nil, false
	}
	var b bytes.Buffer
	b.Grow(size)
	if !m.Reserve(int64(b.Cap() - size)) {
		return nil, false
	}
	return b.Bytes()[:size], true
}

// GrowText owns complete builder replacements. String views remain immutable:
// never reuse their backing storage as mutable scratch. Reset drops ownership.
func GrowText(m *Memory, b *strings.Builder, additional int, stop Stop) bool {
	if additional < 0 || additional > int(^uint(0)>>1)-b.Len() {
		return m.reject()
	}
	if m.Exhausted() || (additional > WorkChunk || b.Len() > WorkChunk) && stopped(stop) {
		return false
	}
	if additional <= b.Cap()-b.Len() {
		return true
	}
	capacity := b.Len() + additional
	if b.Cap() <= (int(^uint(0)>>1)-additional)/2 {
		capacity = 2*b.Cap() + additional
	}
	if !m.Reserve(int64(capacity)) {
		return false
	}
	previous := b.String()
	b.Reset()
	b.Grow(capacity)
	if !m.Reserve(int64(b.Cap() - capacity)) {
		b.Reset()
		return false
	}
	for start := 0; start < len(previous); start += WorkChunk {
		if start > 0 && stopped(stop) {
			b.Reset()
			return false
		}
		b.WriteString(previous[start:min(start+WorkChunk, len(previous))])
	}
	return true
}

func WriteString(m *Memory, b *strings.Builder, text string, stop Stop) bool {
	if !GrowText(m, b, len(text), stop) {
		return false
	}
	for start := 0; start < len(text); start += WorkChunk {
		if start > 0 && stopped(stop) {
			b.Reset()
			return false
		}
		b.WriteString(text[start:min(start+WorkChunk, len(text))])
	}
	return true
}

func WriteBytes(m *Memory, b *strings.Builder, data []byte, stop Stop) bool {
	if !GrowText(m, b, len(data), stop) {
		return false
	}
	for start := 0; start < len(data); start += WorkChunk {
		if start > 0 && stopped(stop) {
			b.Reset()
			return false
		}
		b.Write(data[start:min(start+WorkChunk, len(data))])
	}
	return true
}

func CopyString(m *Memory, data []byte, stop Stop) (string, bool) {
	if len(data) <= 1 {
		if m.Exhausted() || !m.Reserve(int64(len(data))) {
			return "", false
		}
		return string(data), true
	}
	var b strings.Builder
	if !WriteBytes(m, &b, data, stop) {
		return "", false
	}
	return b.String(), true
}

func Concat(m *Memory, left, right string, stop Stop) (string, bool) {
	if len(right) == 0 {
		return left, !m.Exhausted()
	}
	if len(left) == 0 {
		return right, !m.Exhausted()
	}
	var b strings.Builder
	if len(right) > int(^uint(0)>>1)-len(left) {
		return "", m.reject()
	}
	if !GrowText(m, &b, len(left)+len(right), stop) || !WriteString(m, &b, left, stop) || !WriteString(m, &b, right, stop) {
		return "", false
	}
	return b.String(), true
}

// CloneBytes owns a byte copy and reconciles the capacity exposed by Clone.
func CloneBytes(m *Memory, data []byte, stop Stop) ([]byte, bool) {
	if len(data) > WorkChunk {
		if stopped(stop) {
			return nil, false
		}
		out, ok := MakeBytes(m, len(data))
		if !ok {
			return nil, false
		}
		for start := 0; start < len(data); start += WorkChunk {
			if start > 0 && stopped(stop) {
				return nil, false
			}
			copy(out[start:min(start+WorkChunk, len(data))], data[start:])
		}
		return out, true
	}
	if m.Exhausted() || !m.Reserve(int64(len(data))) {
		return nil, false
	}
	out := bytes.Clone(data)
	if !m.Reserve(int64(cap(out) - len(data))) {
		return nil, false
	}
	return out, true
}

// StringBytes creates mutable owned bytes, optionally with a trailing NUL.
func StringBytes(m *Memory, s string, nul bool, stop Stop) ([]byte, bool) {
	size := len(s)
	if nul {
		if size == int(^uint(0)>>1) {
			return nil, m.reject()
		}
		size++
	}
	if len(s) > WorkChunk && stopped(stop) {
		return nil, false
	}
	out, ok := MakeSlice[byte](m, size, size)
	if !ok {
		return nil, false
	}
	for start := 0; start < len(s); start += WorkChunk {
		if start > 0 && stopped(stop) {
			return nil, false
		}
		copy(out[start:min(start+WorkChunk, len(s))], s[start:])
	}
	return out, true
}

// Box owns a value stored in an interface. It preserves the concrete value type
// (unlike New), which matters to selector type switches. Pointer-bearing fields
// still refer to separately owned storage. Small/static values may be overcharged.
func Box[T any](m *Memory, value T) (any, bool) {
	if m.Exhausted() || !m.Reserve((int64(unsafe.Sizeof(value))+15)&^15) {
		return nil, false
	}
	return value, true
}

func LowerASCII(m *Memory, s string, stop Stop) (string, bool) {
	changed := false
	for i := 0; i < len(s); i++ {
		if i > 0 && i%WorkChunk == 0 && stopped(stop) {
			return "", false
		}
		if s[i] >= 'A' && s[i] <= 'Z' {
			changed = true
			break
		}
	}
	if !changed {
		return s, !m.Exhausted()
	}
	var b strings.Builder
	if !GrowText(m, &b, len(s), stop) {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if i > 0 && i%WorkChunk == 0 && stopped(stop) {
			return "", false
		}
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

// TryMakeSlice is optional-cache admission: rejection does not poison required
// work. Invalid dimensions fail without allocating or changing the budget.
func TryMakeSlice[T any](m *Memory, length, capacity int) ([]T, bool) {
	var value T
	size, ok := storageBytes(capacity, unsafe.Sizeof(value))
	if !ok || length < 0 || length > capacity || !m.TryReserve(size) {
		return nil, false
	}
	return make([]T, length, capacity), true
}
