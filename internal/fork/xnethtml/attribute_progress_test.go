package html

import "github.com/PhilAnderson1/MilterGuard/internal/termination"

import (
	"fmt"
	"github.com/PhilAnderson1/MilterGuard/internal/resourceguard"
	"strings"
	"testing"
)

func TestAttributeProcessingCancellation(t *testing.T) {
	for _, materialize := range []bool{false, true} {
		for _, longValue := range []bool{false, true} {
			t.Run(fmt.Sprintf("token=%v/long=%v", materialize, longValue), func(t *testing.T) {
				count, width := 1024, 1000
				if longValue {
					count, width = 1, 8192
				}
				var source strings.Builder
				source.WriteString("<div")
				for i := 0; i < count; i++ {
					fmt.Fprintf(&source, " a%d='%s'", i, strings.Repeat("x", width))
				}
				source.WriteString(">")
				armed, calls := false, 0
				z := NewTokenizerWithStop(strings.NewReader(source.String()), func() {
					if armed {
						calls++
						if true {
							termination.Fail(termination.Failure{Code: termination.CPUExceeded})
						}

						return
					}
					return
				})
				if z.Next() != StartTagToken {
					t.Fatal(z.Err())
				}
				// Exercise periodic sampling, not the first-operation check.
				z.guard.sampler = resourceguard.NewStopSampler(256, z.guard.limits.ShouldStop)
				z.guard.sampler.Check()
				armed = true
				expectTermination(t, termination.CPUExceeded, func() {
					if materialize {
						z.Token()
					} else {
						for {
							_, _, more := z.TagAttr()
							if !more {
								break
							}
						}
					}
				})
				if calls != 1 {
					t.Fatalf("calls=%d", calls)
				}

				if !longValue && z.nAttrReturned >= 256 {
					t.Fatalf("processed %d attributes before stopping", z.nAttrReturned)
				}
			})
		}
	}
}
