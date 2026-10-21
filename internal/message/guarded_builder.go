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
}

func newGuardedBuilder(memory *resourceguard.Memory) guardedBuilder {
	return guardedBuilder{memory: memory}
}

func growGuardedSlice[T any](values []T, required int, memory *resourceguard.Memory) []T {
	return resourceguard.GrowSlice(memory, values, required-len(values), nil)
}

func (b *guardedBuilder) Grow(additional int) {
	if additional <= 0 {
		return
	}
	b.ensure(additional)
	return
}

func (b *guardedBuilder) ensure(additional int) {
	grown := resourceguard.GrowSlice(b.memory, b.buf, additional, nil)

	b.buf = grown
	return
}

func (b *guardedBuilder) Write(value []byte) (int, error) {
	b.ensure(len(value))

	b.buf = append(b.buf, value...)
	return len(value), nil
}

// writeWithStop bounds both backing-array replacement and copying for text
// passes which already divide their work into checkpoint-sized chunks.
func (b *guardedBuilder) writeWithStop(value []byte, stop resourceguard.Stop) {
	if len(value) == 0 {
		return
	}
	b.buf = resourceguard.Append(b.memory, b.buf, stop, value...)
}

func (b *guardedBuilder) WriteString(value string) {
	b.ensure(len(value))

	b.buf = append(b.buf, value...)
	return
}

func (b *guardedBuilder) appendByte(value byte) {
	b.ensure(1)

	b.buf = append(b.buf, value)
	return
}

func (b *guardedBuilder) appendRune(value rune) {
	width := utf8.RuneLen(value)
	if width < 0 {
		value = utf8.RuneError
		width = utf8.RuneLen(value)
	}

	b.ensure(width)

	b.buf = utf8.AppendRune(b.buf, value)
	return
}

func (b *guardedBuilder) Len() int      { return len(b.buf) }
func (b *guardedBuilder) Bytes() []byte { return b.buf }
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
