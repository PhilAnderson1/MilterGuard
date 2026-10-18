package resourceguard

// Memory is a monotonic per-operation allocation budget. It deliberately does
// not release charges: unreachable Go objects remain allocated until a later
// garbage collection, and repeated temporary allocation is itself hostile
// memory pressure.
type Memory struct {
	limit     int64
	used      int64
	exhausted bool
}

func NewMemory(limit int64) *Memory {
	return &Memory{limit: limit}
}

func (m *Memory) Reserve(bytes int64) bool {
	if m == nil || bytes <= 0 {
		return true
	}
	if m.exhausted {
		return false
	}
	if m.limit <= 0 || m.used > m.limit || bytes > m.limit-m.used {
		m.exhausted = true
		return false
	}
	m.used += bytes
	return true
}

func (m *Memory) Exhausted() bool { return m != nil && m.exhausted }

func (m *Memory) Used() int64 {
	if m == nil {
		return 0
	}
	if m.exhausted {
		return m.limit
	}
	return m.used
}

func (m *Memory) Limit() int64 {
	if m == nil {
		return 0
	}
	return m.limit
}

// TryReserve admits optional memoization without poisoning required work when
// it does not fit. Like Reserve, it is owned by one operation, not concurrent.
func (m *Memory) TryReserve(bytes int64) bool {
	if m == nil {
		return true
	}
	if m.exhausted {
		return false
	}
	if bytes <= 0 {
		return true
	}
	if m.limit <= 0 || m.used > m.limit || bytes > m.limit-m.used {
		return false
	}
	return m.Reserve(bytes)
}
