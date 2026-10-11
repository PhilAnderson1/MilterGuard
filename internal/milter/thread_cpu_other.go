//go:build !linux

package milter

import "time"

func currentThreadCPUTime() (time.Duration, bool) {
	return 0, false
}
