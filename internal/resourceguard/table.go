package resourceguard

import "unsafe"

// Table owns a native map and its conservative, version-sensitive allowance.
// Reads may borrow View; all insertion and reset must go through the owner.
// Values and referenced key bytes are owned separately. A Table may be moved with its containing slice, but must not have two mutable owners.
// Native Go maps do not expose capacity; this is an estimate, not a heap cap.
type Table[K comparable, V any] struct {
	data      map[K]V
	highWater int
}

// The first native group has eight slots even for one entry. Per-entry
// allowance then covers subsequent growth and transient replacement groups.
func tableBaseBytes[K comparable, V any]() int64 {
	var k K
	var v V
	return 128 + 8*int64(unsafe.Sizeof(k)+unsafe.Sizeof(v))
}

func tableEntryBytes[K comparable, V any]() int64 {
	var k K
	var v V
	return 4*int64(unsafe.Sizeof(k)+unsafe.Sizeof(v)) + 64
}

func (t *Table[K, V]) View() map[K]V     { return t.data }
func (t *Table[K, V]) Len() int          { return len(t.data) }
func (t *Table[K, V]) Get(k K) (V, bool) { v, ok := t.data[k]; return v, ok }

func (t *Table[K, V]) Set(m *Memory, k K, v V)         { t.set(m, k, v, false) }
func (t *Table[K, V]) TrySet(m *Memory, k K, v V) bool { return t.set(m, k, v, true) }
func (t *Table[K, V]) set(m *Memory, k K, v V, optional bool) bool {
	m.unavailable()

	if _, exists := t.data[k]; exists {
		t.data[k] = v
		return true
	}

	cost := int64(0)
	if t.data == nil {
		cost = tableBaseBytes[K, V]()
	}
	if len(t.data) >= t.highWater {
		cost += tableEntryBytes[K, V]()
	}
	if optional {
		if !m.TryReserve(cost) {
			return false
		}
	} else {
		m.Reserve(cost)
	}
	if t.data == nil {
		t.data = make(map[K]V)
	}
	t.data[k] = v
	t.highWater = max(t.highWater, len(t.data))
	return true
}

// Reset retains backing storage and its admitted high-water allowance. This
// policy is restricted to clear/refill (no deletes) and the tested Go runtime;
// the entry allowance includes growth/rounding, not an exact capacity promise.
func (t *Table[K, V]) Reset()   { clear(t.data) }
func (t *Table[K, V]) Release() { t.data = nil; t.highWater = 0 }

// Init admits a known entry count once; subsequent Set operations up to that
// count consume the existing allowance. Replacing a table charges it anew.
func (t *Table[K, V]) Init(m *Memory, count int) {
	size, ok := storageBytes(count, uintptr(tableEntryBytes[K, V]()))
	if !ok || size > int64(^uint64(0)>>1)-tableBaseBytes[K, V]() {
		m.reject()
		return
	}

	m.Reserve(size + tableBaseBytes[K, V]())

	t.data = make(map[K]V, count)
	t.highWater = count
	return
}

// MakeMap transfers a preadmitted native map to a caller that can prove a bound
// on distinct keys. Inserting more than count keys requires Table instead.
// The allowance includes runtime growth/rounding; key/value referents are separate.
func MakeMap[K comparable, V any](m *Memory, count int) map[K]V {
	var t Table[K, V]

	t.Init(m, count)

	return t.data
}

// TryCacheEntry admits the initial index and first map entry atomically. A
// declined optional cache allocates nothing and consumes no required budget.
func TryCacheEntry[K comparable, V any](m *Memory, tables *[]Table[K, V], count, index int, key K, value V) bool {
	if index < 0 || index >= count {
		return false
	}
	if *tables != nil {
		return (*tables)[index].TrySet(m, key, value)
	}
	size, ok := storageBytes(count, unsafe.Sizeof(Table[K, V]{}))
	first := tableBaseBytes[K, V]() + tableEntryBytes[K, V]()
	if !ok || size > int64(^uint64(0)>>1)-first || !m.TryReserve(size+first) {
		return false
	}
	owned := MakeSlice[Table[K, V]](nil, count, count)
	owned[index].Set(nil, key, value)
	*tables = owned
	return true
}
