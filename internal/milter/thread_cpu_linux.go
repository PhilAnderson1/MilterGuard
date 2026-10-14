//go:build linux

package milter

import (
	"time"

	"golang.org/x/sys/unix"
)

func currentThreadCPUTime() (time.Duration, bool) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &value); err != nil {
		return 0, false
	}
	return time.Duration(value.Sec)*time.Second + time.Duration(value.Nsec), true
}
