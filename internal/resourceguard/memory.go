package resourceguard

import (
	"github.com/PhilAnderson1/MilterGuard/internal/termination"
)

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

// unavailable protects storage entry points against reuse of an exhausted
// ledger. Exhausted remains a side-effect-free query for boundary reporting.
func (m *Memory) unavailable() {
	if !m.Exhausted() {
		return
	}

	termination.Fail(termination.Failure{Code: termination.MemoryExceeded, Limit: m.limit})

	return
}

func (m *Memory) Reserve(bytes int64) {
	if m == nil {
		return
	}

	m.unavailable()

	if bytes <= 0 {
		return
	}
	if m.limit <= 0 || m.used > m.limit || bytes > m.limit-m.used {
		m.reject()
		return
	}
	m.used += bytes
	return
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
// a request does not fit. It is not recovery: reuse of an already-exhausted
// ledger terminates the operation. Like Reserve, it is owned by one operation,
// not concurrent.
func (m *Memory) TryReserve(bytes int64) bool {
	if m == nil {
		return true
	}

	m.unavailable()

	if bytes <= 0 {
		return true
	}
	if m.limit <= 0 || m.used > m.limit || bytes > m.limit-m.used {
		return false
	}
	m.Reserve(bytes)
	return true
}

// RecordUsage transfers charges already admitted by a child ledger. It is not
// allocation admission: the child must be limited to the parent's remaining
// allowance, with no intervening parent charges. It never raises during deferred
// cleanup. An overrun exhausts the parent, so subsequent admissions fail closed.
func (m *Memory) RecordUsage(bytes int64) {
	if m == nil || m.exhausted || bytes <= 0 {
		return
	}
	if m.limit <= 0 || m.used > m.limit || bytes > m.limit-m.used {
		m.exhausted = true
		return
	}
	m.used += bytes
}
