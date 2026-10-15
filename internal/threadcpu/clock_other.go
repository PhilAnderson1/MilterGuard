//go:build !linux

package threadcpu

import "time"

// Now reports that per-thread CPU time is unavailable on this platform.
func Now() (time.Duration, bool) {
	return 0, false
}
