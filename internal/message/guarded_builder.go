package message

import (
	"unicode/utf8"
	"unsafe"

	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
)

// guardedBuilder grows only after charging the complete new backing array to
// the operation's monotonic allocation budget. Charging the complete array is
// intentional: the superseded array can remain live until a later GC.
type guardedBuilder struct {
	buf    []byte
	memory *resourceguard.Memory
	failed bool
}

func newGuardedBuilder(memory *resourceguard.Memory) guardedBuilder {
	return guardedBuilder{memory: memory}
}

func growGuardedSlice[T any](values []T, required int, memory *resourceguard.Memory) ([]T, bool) {
	if required <= cap(values) {
		return values, true
	}
	newCapacity := cap(values) * 2
	if newCapacity < required {
		newCapacity = required
	}
	elementBytes := uint64(unsafe.Sizeof(*new(T)))
	if newCapacity <= 0 || elementBytes > 0 && uint64(newCapacity) > uint64(^uint64(0))/elementBytes {
		return values, false
	}
	allocationBytes := uint64(newCapacity) * elementBytes
	if allocationBytes > uint64(^uint64(0)>>1) || !memory.Reserve(int64(allocationBytes)) {
		return values, false
	}
	grown := make([]T, len(values), newCapacity)
	copy(grown, values)
	return grown, true
}

func (b *guardedBuilder) Grow(additional int) bool {
	if additional <= 0 {
		return !b.failed
	}
	return b.ensure(additional)
}

func (b *guardedBuilder) ensure(additional int) bool {
	if b.failed {
		return false
	}
	if additional < 0 || len(b.buf) > int(^uint(0)>>1)-additional {
		b.failed = true
		return false
	}
	required := len(b.buf) + additional
	if required <= cap(b.buf) {
		return true
	}
	newCapacity := cap(b.buf) * 2
	if newCapacity < required {
		newCapacity = required
	}
	if newCapacity <= 0 || !b.memory.Reserve(int64(newCapacity)) {
		b.failed = true
		return false
	}
	grown := make([]byte, len(b.buf), newCapacity)
	copy(grown, b.buf)
	b.buf = grown
	return true
}

func (b *guardedBuilder) Write(value []byte) (int, error) {
	if !b.ensure(len(value)) {
		return 0, errOutputMemoryLimit
	}
	b.buf = append(b.buf, value...)
	return len(value), nil
}

func (b *guardedBuilder) WriteString(value string) bool {
	if !b.ensure(len(value)) {
		return false
	}
	b.buf = append(b.buf, value...)
	return true
}

func (b *guardedBuilder) appendByte(value byte) bool {
	if !b.ensure(1) {
		return false
	}
	b.buf = append(b.buf, value)
	return true
}

func (b *guardedBuilder) appendRune(value rune) bool {
	width := utf8.RuneLen(value)
	if width < 0 {
		value = utf8.RuneError
		width = utf8.RuneLen(value)
	}
	if !b.ensure(width) {
		return false
	}
	b.buf = utf8.AppendRune(b.buf, value)
	return true
}

func (b *guardedBuilder) Len() int      { return len(b.buf) }
func (b *guardedBuilder) Bytes() []byte { return b.buf }
func (b *guardedBuilder) Failed() bool  { return b.failed }
func (b *guardedBuilder) Reset()        { b.buf = b.buf[:0] }

// String transfers a read-only view of the completed buffer without creating
// another full-size allocation. Callers must not write to the builder after
// retaining the returned string.
func (b *guardedBuilder) String() string {
	if len(b.buf) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b.buf), len(b.buf))
}

type outputMemoryLimitError struct{}

func (outputMemoryLimitError) Error() string { return "message output memory limit exceeded" }

var errOutputMemoryLimit error = outputMemoryLimitError{}
