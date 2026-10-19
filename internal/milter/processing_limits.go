package milter

import "time"

// CPU durations are the most recent cooperative samples for each stage. There
// is no combined duration or completion-time budget check.
type htmlProcessingUsage struct {
	primaryCPUTime      time.Duration
	fallbackCPUTime     time.Duration
	primaryCPUExceeded  bool
	fallbackCPUExceeded bool
	memoryExceeded      bool
	measured            bool
}

func (u htmlProcessingUsage) cpuExceeded() bool { return u.primaryCPUExceeded || u.fallbackCPUExceeded }

// cpuAllowance belongs to one stage of one message. Once fallback starts its
// allowance is reused across all remaining parts; the primary stage is retired.
type cpuAllowance struct {
	started   time.Duration
	elapsed   time.Duration
	available bool
	exceeded  bool
}

func (a *cpuAllowance) check(current time.Duration, ok bool, maximum time.Duration) bool {
	if a.exceeded {
		return true
	}
	if a.available && ok && current >= a.started {
		a.elapsed = current - a.started
		a.exceeded = a.elapsed > maximum
	}
	return a.exceeded
}
