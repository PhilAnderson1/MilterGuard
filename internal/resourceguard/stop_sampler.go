package resourceguard

// StopSampler controls checkpoint frequency only. It belongs to one operation
// and is not concurrent. A nil callback (including the zero value) does nothing.
type StopSampler struct {
	remaining uint32
	reload    uint32
	check     func()
}

// NewStopSampler checks on calls 1, 1+every, 1+2*every, ... . A zero frequency
// is a configuration error, not a way to disable resource enforcement.
func NewStopSampler(every uint32, check func()) StopSampler {
	if every == 0 {
		panic("resourceguard: zero sampling frequency")
	}
	return StopSampler{reload: every - 1, check: check}
}

// Check invokes a checkpoint on calls 1, 1+every, 1+2*every, ... .
// The checkpoint is supplied once during initialization.
func (s *StopSampler) Check() {
	if s.remaining != 0 {
		s.remaining--
		return
	}
	s.remaining = s.reload
	if s.check != nil {
		s.check()
	}
}
